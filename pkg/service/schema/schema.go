package schema

import (
	"fmt"
	"time"

	"github.com/TBD54566975/ssi-sdk/credential/schema"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	schemalib "github.com/TBD54566975/ssi-sdk/schema"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	schemastorage "github.com/tbd54566975/ssi-service/pkg/service/schema/storage"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type Service struct {
	storage schemastorage.Storage
	config  config.SchemaServiceConfig

	// external dependencies
	keyStore *keystore.Service
	resolver *didsdk.Resolver
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

func NewSchemaService(config config.SchemaServiceConfig, s storage.ServiceStorage, keyStore *keystore.Service, resolver *didsdk.Resolver) (*Service, error) {
	schemaStorage, err := schemastorage.NewSchemaStorage(s)
	if err != nil {
		errMsg := "could not instantiate storage for the schema service"
		return nil, util.LoggingErrorMsg(err, errMsg)
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
func (s Service) CreateSchema(request CreateSchemaRequest) (*CreateSchemaResponse, error) {

	logrus.Debugf("creating schema: %+v", request)

	if !request.IsValid() {
		errMsg := fmt.Sprintf("invalid create schema request: %+v", request)
		return nil, util.LoggingNewError(errMsg)
	}

	schemaBytes, err := json.Marshal(request.Schema)
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal schema in request")
	}
	if err := schemalib.IsValidJSONSchema(string(schemaBytes)); err != nil {
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

	storedSchema := schemastorage.StoredSchema{ID: schemaID, Schema: schemaValue}

	// sign the schema
	if request.Sign {
		signedSchema, err := s.signSchemaJWT(request.Author, schemaValue)
		if err != nil {
			return nil, util.LoggingError(err)
		}
		storedSchema.SchemaJWT = signedSchema
	}

	if err := s.storage.StoreSchema(storedSchema); err != nil {
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
		s["$schema"] = "http://json-schema.org/draft-07/schema#"
	}
	if _, ok := s["description"]; !ok {
		s["description"] = "schema for " + name
	}
	if _, ok := s["required"]; !ok {
		s["required"] = []string{}
	}
	return s
}

// signSchemaJWT signs a schema after the key associated with the provided author for the schema as a JWT
func (s Service) signSchemaJWT(author string, schema schema.VCJSONSchema) (*string, error) {
	gotKey, err := s.keyStore.GetKey(keystore.GetKeyRequest{ID: author})
	if err != nil {
		errMsg := fmt.Sprintf("could not get key for signing schema for author<%s>", author)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	keyAccess, err := keyaccess.NewJWKKeyAccess(gotKey.ID, gotKey.Key)
	if err != nil {
		errMsg := fmt.Sprintf("could not create key access for signing schema for author<%s>", author)
		return nil, errors.Wrap(err, errMsg)
	}
	schemaJSONBytes, err := sdkutil.ToJSONMap(schema)
	if err != nil {
		errMsg := fmt.Sprintf("could not marshal schema for signing for author<%s>", author)
		return nil, errors.Wrap(err, errMsg)
	}
	schemaToken, err := keyAccess.SignJWT(schemaJSONBytes)
	if err != nil {
		errMsg := fmt.Sprintf("could not sign schema for author<%s>", author)
		return nil, errors.Wrap(err, errMsg)
	}
	if err = s.verifySchemaJWT(string(schemaToken)); err != nil {
		return nil, errors.Wrap(err, "could not verify signed schema")
	}
	return sdkutil.StringPtr(string(schemaToken)), nil
}

type VerifySchemaRequest struct {
	SchemaJWT string `json:"credentialJwt"`
}

type VerifySchemaResponse struct {
	Verified bool   `json:"verified" json:"verified"`
	Reason   string `json:"reason,omitempty" json:"reason,omitempty"`
}

func (s Service) VerifySchema(request VerifySchemaRequest) (*VerifySchemaResponse, error) {
	if err := s.verifySchemaJWT(request.SchemaJWT); err != nil {
		return &VerifySchemaResponse{Verified: false, Reason: "could not verify schema: " + err.Error()}, nil
	}
	return &VerifySchemaResponse{Verified: true}, nil
}

func (s Service) verifySchemaJWT(token string) error {
	parsed, err := jwt.Parse([]byte(token))
	if err != nil {
		errMsg := "could not parse JWT"
		logrus.WithError(err).Error(errMsg)
		return util.LoggingErrorMsg(err, errMsg)
	}
	claims := parsed.PrivateClaims()
	claimsJSONBytes, err := json.Marshal(claims)
	if err != nil {
		errMsg := "could not marshal claims"
		logrus.WithError(err).Error(errMsg)
		return util.LoggingErrorMsg(err, errMsg)
	}
	var parsedSchema schema.VCJSONSchema
	if err := json.Unmarshal(claimsJSONBytes, &parsedSchema); err != nil {
		errMsg := "could not unmarshal claims into schema"
		logrus.WithError(err).Error(errMsg)
		return util.LoggingErrorMsg(err, errMsg)
	}
	resolved, err := s.resolver.Resolve(parsedSchema.Author)
	if err != nil {
		return errors.Wrapf(err, "failed to resolve schema author's did: %s", parsedSchema.Author)
	}
	kid, pubKey, err := keyaccess.GetVerificationInformation(resolved.DIDDocument, "")
	if err != nil {
		return util.LoggingErrorMsg(err, "could not get verification information from schema")
	}
	verifier, err := keyaccess.NewJWKKeyAccessVerifier(kid, pubKey)
	if err != nil {
		return util.LoggingErrorMsg(err, "could not create verifier")
	}
	if err := verifier.Verify(keyaccess.JWKToken{Token: token}); err != nil {
		return util.LoggingErrorMsg(err, "could not verify the schema's signature")
	}
	return nil
}

func (s Service) GetSchemas() (*GetSchemasResponse, error) {

	logrus.Debug("getting all schema")

	storedSchemas, err := s.storage.GetSchemas()
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "error getting schemas")
	}
	var schemas []GetSchemaResponse
	for _, stored := range storedSchemas {
		schemas = append(schemas, GetSchemaResponse{
			ID:        stored.Schema.ID,
			Schema:    stored.Schema,
			SchemaJWT: stored.SchemaJWT,
		})
	}
	return &GetSchemasResponse{
		Schemas: schemas,
	}, nil
}

func (s Service) GetSchema(request GetSchemaRequest) (*GetSchemaResponse, error) {

	logrus.Debugf("getting schema: %s", request.ID)

	// TODO(gabe) support external schema resolution https://github.com/TBD54566975/ssi-service/issues/125
	gotSchema, err := s.storage.GetSchema(request.ID)
	if err != nil {
		err := errors.Wrapf(err, "error getting schema: %s", request.ID)
		return nil, util.LoggingError(err)
	}
	if gotSchema == nil {
		err := fmt.Errorf("schema with id<%s> could not be found", request.ID)
		return nil, util.LoggingError(err)
	}
	return &GetSchemaResponse{Schema: gotSchema.Schema, SchemaJWT: gotSchema.SchemaJWT}, nil
}

func (s Service) Resolve(id string) (*schema.VCJSONSchema, error) {
	schemaResponse, err := s.GetSchema(GetSchemaRequest{ID: id})
	if err != nil {
		return nil, err
	}
	return &schemaResponse.Schema, nil
}

func (s Service) DeleteSchema(request DeleteSchemaRequest) error {

	logrus.Debugf("deleting schema: %s", request.ID)

	if err := s.storage.DeleteSchema(request.ID); err != nil {
		errMsg := fmt.Sprintf("could not delete schema with id: %s", request.ID)
		return util.LoggingErrorMsg(err, errMsg)
	}

	return nil
}
