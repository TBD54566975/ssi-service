package schema

import (
	"context"
	"fmt"
	"time"

	"github.com/TBD54566975/ssi-sdk/credential/schema"
	schemalib "github.com/TBD54566975/ssi-sdk/schema"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	didresolver "github.com/tbd54566975/ssi-service/pkg/service/did/resolution"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/internal/did"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"

	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type Service struct {
	storage *Storage
	config  config.SchemaServiceConfig

	// external dependencies
	keyStore *keystore.Service
	resolver didresolver.Resolver
}

func (s Service) Type() framework.Type {
	return framework.Schema
}

func (s Service) Status() framework.Status {
	ae := sdkutil.NewAppendError()
	if s.storage == nil {
		ae.AppendString("no storage configured")
	}
	if s.keyStore == nil {
		ae.AppendString("no key store service configured")
	}
	if s.resolver == nil {
		ae.AppendString("no did resolver configured")
	}
	if !ae.IsEmpty() {
		return framework.Status{
			Status:  framework.StatusNotReady,
			Message: fmt.Sprintf("schema service is not ready: %s", ae.Error().Error()),
		}
	}
	return framework.Status{Status: framework.StatusReady}
}

func (s Service) Config() config.SchemaServiceConfig {
	return s.config
}

func NewSchemaService(config config.SchemaServiceConfig, s storage.ServiceStorage, keyStore *keystore.Service, resolver didresolver.Resolver) (*Service, error) {
	schemaStorage, err := NewSchemaStorage(s)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not instantiate storage for the schema service")
	}
	service := Service{
		storage:  schemaStorage,
		config:   config,
		keyStore: keyStore,
		resolver: resolver,
	}
	if !service.Status().IsReady() {
		return nil, errors.New(service.Status().Message)
	}
	return &service, nil
}

// CreateSchema houses the main service logic for schema creation. It validates the input, and
// produces a schema value that conforms with the VC JSON JSONSchema specification.
// TODO(gabe) support data integrity proof generation on schemas, versioning, and more
func (s Service) CreateSchema(ctx context.Context, request CreateSchemaRequest) (*CreateSchemaResponse, error) {

	logrus.Debugf("creating schema: %+v", request)

	if !request.IsValid() {
		return nil, util.LoggingNewErrorf("invalid create schema request: %+v", request)
	}

	schemaBytes, err := json.Marshal(request.Schema)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not marshal schema in request")
	}
	if err = schemalib.IsValidJSONSchema(string(schemaBytes)); err != nil {
		return nil, util.LoggingErrorMsg(err, "provided value is not a valid JSON schema")
	}

	// create schema
	schemaID := uuid.NewString()
	schemaValue := schema.VCJSONSchema{
		Type:     schema.VCJSONSchemaType,
		Version:  Version1,
		ID:       schemaID,
		Name:     request.Name,
		Author:   request.Author,
		Authored: time.Now().Format(time.RFC3339),
		Schema:   prepareJSONSchema(schemaID, request.Name, request.Schema),
	}

	storedSchema := StoredSchema{ID: schemaID, Schema: schemaValue}

	// sign the schema
	if request.Sign {
		signedSchema, err := s.signSchemaJWT(ctx, request.Author, schemaValue)
		if err != nil {
			return nil, util.LoggingError(err)
		}
		storedSchema.SchemaJWT = signedSchema
	}

	if err = s.storage.StoreSchema(ctx, storedSchema); err != nil {
		return nil, util.LoggingErrorMsg(err, "could not store schema")
	}

	return &CreateSchemaResponse{ID: schemaID, Schema: schemaValue, SchemaJWT: storedSchema.SchemaJWT}, nil
}

// make sure the schema is well-formed before proceeding
func prepareJSONSchema(id, name string, s schema.JSONSchema) schema.JSONSchema {
	if _, ok := s["$id"]; !ok {
		s["$id"] = id
	}
	if _, ok := s["$schema"]; !ok {
		s["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	}
	if _, ok := s["description"]; !ok {
		s["description"] = "schema for " + name
	}
	return s
}

// signSchemaJWT signs a schema after the key associated with the provided author for the schema as a JWT
func (s Service) signSchemaJWT(ctx context.Context, author string, schema schema.VCJSONSchema) (*keyaccess.JWT, error) {
	gotKey, err := s.keyStore.GetKey(ctx, keystore.GetKeyRequest{ID: author})
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get key for signing schema for author<%s>", author)
	}
	keyAccess, err := keyaccess.NewJWKKeyAccess(gotKey.ID, gotKey.Key)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not create key access for signing schema for author<%s>", author)
	}
	schemaJSONBytes, err := sdkutil.ToJSONMap(schema)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not marshal schema for signing for author<%s>", author)
	}
	schemaToken, err := keyAccess.SignWithDefaults(schemaJSONBytes)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not sign schema for author<%s>", author)
	}
	if _, err = s.verifySchemaJWT(ctx, keyaccess.JWT(schemaToken)); err != nil {
		return nil, util.LoggingErrorMsg(err, "could not verify signed schema")
	}
	return keyaccess.JWTPtr(string(schemaToken)), nil
}

// VerifySchema verifies a schema's signature and makes sure the schema is compliant with the specification
func (s Service) VerifySchema(ctx context.Context, request VerifySchemaRequest) (*VerifySchemaResponse, error) {
	credSchema, err := s.verifySchemaJWT(ctx, request.SchemaJWT)
	if err != nil {
		return &VerifySchemaResponse{Verified: false, Reason: "could not verify schema's signature: " + err.Error()}, nil
	}

	// check the schema is valid against its specification
	schemaBytes, err := json.Marshal(credSchema)
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal schema into json")
	}
	if err := schema.IsValidCredentialSchema(string(schemaBytes)); err != nil {
		return &VerifySchemaResponse{Verified: false, Reason: "schema is not a valid credential schema: " + err.Error()}, nil
	}
	return &VerifySchemaResponse{Verified: true}, nil
}

func (s Service) verifySchemaJWT(ctx context.Context, token keyaccess.JWT) (*schema.VCJSONSchema, error) {
	parsed, err := jwt.Parse([]byte(token))
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not parse JWT")
	}
	claims := parsed.PrivateClaims()
	claimsJSONBytes, err := json.Marshal(claims)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not marshal claims")
	}
	var parsedSchema schema.VCJSONSchema
	if err = json.Unmarshal(claimsJSONBytes, &parsedSchema); err != nil {
		return nil, util.LoggingErrorMsg(err, "could not unmarshal claims into schema")
	}
	resolved, err := s.resolver.Resolve(ctx, parsedSchema.Author)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to resolution schema author's did: %s", parsedSchema.Author)
	}
	kid, pubKey, err := did.GetVerificationInformation(resolved.Document, "")
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not get verification information from schema")
	}
	verifier, err := keyaccess.NewJWKKeyAccessVerifier(kid, pubKey)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not create schema verifier")
	}
	if err = verifier.Verify(token); err != nil {
		return nil, util.LoggingErrorMsg(err, "could not verify the schema's signature")
	}
	return &parsedSchema, nil
}

func (s Service) GetSchemas(ctx context.Context) (*GetSchemasResponse, error) {

	logrus.Debug("getting all schema")

	storedSchemas, err := s.storage.GetSchemas(ctx)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "error getting schemas")
	}
	schemas := make([]GetSchemaResponse, 0, len(storedSchemas))
	for _, stored := range storedSchemas {
		schemas = append(schemas, GetSchemaResponse{
			ID:        stored.Schema.ID,
			Schema:    stored.Schema,
			SchemaJWT: stored.SchemaJWT,
		})
	}

	return &GetSchemasResponse{Schemas: schemas}, nil
}

func (s Service) GetSchema(ctx context.Context, request GetSchemaRequest) (*GetSchemaResponse, error) {

	logrus.Debugf("getting schema: %s", request.ID)

	// TODO(gabe) support external schema resolution https://github.com/TBD54566975/ssi-service/issues/125
	gotSchema, err := s.storage.GetSchema(ctx, request.ID)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "error getting schema: %s", request.ID)
	}
	if gotSchema == nil {
		return nil, util.LoggingNewErrorf("schema with id<%s> could not be found", request.ID)
	}
	return &GetSchemaResponse{Schema: gotSchema.Schema, SchemaJWT: gotSchema.SchemaJWT}, nil
}

func (s Service) Resolve(ctx context.Context, id string) (*schema.VCJSONSchema, error) {
	schemaResponse, err := s.GetSchema(ctx, GetSchemaRequest{ID: id})
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get schema for id<%s>", id)
	}
	return &schemaResponse.Schema, nil
}

func (s Service) DeleteSchema(ctx context.Context, request DeleteSchemaRequest) error {

	logrus.Debugf("deleting schema: %s", request.ID)

	if err := s.storage.DeleteSchema(ctx, request.ID); err != nil {
		return util.LoggingErrorMsgf(err, "could not delete schema with id: %s", request.ID)
	}

	return nil
}
