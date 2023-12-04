package schema

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/parsing"
	"github.com/TBD54566975/ssi-sdk/credential/schema"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/resolution"
	schemalib "github.com/TBD54566975/ssi-sdk/schema"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"

	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type Service struct {
	storage *Storage

	// external dependencies
	keyStore *keystore.Service
	resolver resolution.Resolver
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

func NewSchemaService(s storage.ServiceStorage, keyStore *keystore.Service,
	resolver resolution.Resolver) (*Service, error) {
	schemaStorage, err := NewSchemaStorage(s)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not instantiate storage for the schema service")
	}
	service := Service{
		storage:  schemaStorage,
		keyStore: keyStore,
		resolver: resolver,
	}
	if !service.Status().IsReady() {
		return nil, errors.New(service.Status().Message)
	}
	return &service, nil
}

// CreateSchema houses the main service logic for schema creation. It validates the input, and
// produces a schema value that conforms with the VC JSON Schema specification.
func (s Service) CreateSchema(ctx context.Context, request CreateSchemaRequest) (*CreateSchemaResponse, error) {
	logrus.Debugf("creating schema: %+v", request)

	if err := request.IsValid(); err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "validating schema request: %+v", request)
	}

	// validate the schema
	jsonSchema := request.Schema
	schemaBytes, err := json.Marshal(jsonSchema)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not marshal schema in request")
	}
	if err = schemalib.IsValidJSONSchema(string(schemaBytes)); err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "provided value is not a valid JSON schema")
	}
	if !schema.IsSupportedJSONSchemaVersion(jsonSchema.Schema()) {
		return nil, sdkutil.LoggingNewErrorf("unsupported schema version: %s", jsonSchema.Schema())
	}
	if jsonSchema.ID() != "" {
		logrus.Infof("schema has id: %s, which is being overwritten", jsonSchema.ID())
	}

	// set name, and description on the schema
	if jsonSchema[schema.JSONSchemaNameProperty] != "" && request.Name != "" {
		logrus.Infof("schema has name: %s, which is being overwritten", jsonSchema[schema.JSONSchemaNameProperty])
	}
	jsonSchema[schema.JSONSchemaNameProperty] = request.Name
	if request.Description != "" {
		if jsonSchema[schema.JSONSchemaDescriptionProperty] != "" {
			logrus.Infof("schema has description: %s, which is being overwritten", jsonSchema[schema.JSONSchemaDescriptionProperty])
		}
		jsonSchema[schema.JSONSchemaDescriptionProperty] = request.Description
	}

	// if the schema is a credential schema, the credential's id is a fully qualified URI
	// if the schema is a JSON schema, the schema's id is a fully qualified URI
	schemaID := uuid.NewString()
	schemaURI := strings.Join([]string{config.GetServicePath(framework.Schema), schemaID}, "/")

	// create schema for storage
	storedSchema := StoredSchema{ID: schemaID}
	if request.IsCredentialSchemaRequest() {
		jsonSchema[schema.JSONSchemaIDProperty] = schemaURI
		credSchema, err := s.createCredentialSchema(ctx, jsonSchema, schemaURI, request.Issuer, request.FullyQualifiedVerificationMethodID, schemaID)
		if err != nil {
			return nil, sdkutil.LoggingErrorMsg(err, "could not create credential schema")
		}
		storedSchema.Type = schema.JSONSchemaCredentialType
		storedSchema.CredentialSchema = credSchema
	} else {
		jsonSchema[schema.JSONSchemaIDProperty] = schemaURI
		storedSchema.Type = schema.JSONSchemaType
		storedSchema.Schema = &jsonSchema
	}
	// store schema
	if err = s.storage.StoreSchema(ctx, storedSchema); err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not store schema")
	}

	return &CreateSchemaResponse{
		ID:               schemaID,
		Type:             storedSchema.Type,
		Schema:           storedSchema.Schema,
		CredentialSchema: storedSchema.CredentialSchema,
	}, nil
}

// createCredentialSchema creates a credential schema, and signs it with the issuer's key and kid
func (s Service) createCredentialSchema(ctx context.Context, jsonSchema schema.JSONSchema, schemaURI, issuer, fullyQualifiedVerificationMethodID, schemaID string) (*keyaccess.JWT, error) {
	builder := credential.NewVerifiableCredentialBuilder()
	if err := builder.SetID(schemaURI); err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "building credential when setting id: %s", schemaURI)
	}
	if err := builder.SetIssuer(issuer); err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "building credential when setting issuer: %s", issuer)
	}
	if err := builder.SetCredentialSchema(credential.CredentialSchema{
		ID:        "https://www.w3.org/2022/credentials/v2/json-schema-credential-schema.json",
		Type:      "JsonSchema",
		DigestSRI: "sha384-S57yQDg1MTzF56Oi9DbSQ14u7jBy0RDdx0YbeV7shwhCS88G8SCXeFq82PafhCrW",
	}); err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "building credential when setting credential schema")
	}
	// set subject's jsonSchema value as the schema
	subject := make(credential.CredentialSubject)
	subject[credential.VerifiableCredentialJSONSchemaProperty] = jsonSchema
	subject[credential.VerifiableCredentialIDProperty] = "urn:uuid:" + schemaID
	subject[schema.TypeProperty] = schema.JSONSchemaType
	if err := builder.SetCredentialSubject(subject); err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "could not set subject: %+v", subject)
	}
	if err := builder.SetIssuanceDate(time.Now().Format(time.RFC3339)); err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not set credential schema issuance date")
	}
	cred, err := builder.Build()
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not build credential schema")
	}
	return s.signCredentialSchema(ctx, *cred, issuer, fullyQualifiedVerificationMethodID)
}

// signCredentialSchema signs a credential schema with the issuer's key and kid as a  VC JWT
func (s Service) signCredentialSchema(ctx context.Context, cred credential.VerifiableCredential, issuer, fullyQualifiedVerificationMethodID string) (*keyaccess.JWT, error) {
	keyStoreID := did.FullyQualifiedVerificationMethodID(cred.IssuerID(), fullyQualifiedVerificationMethodID)
	gotKey, err := s.keyStore.GetKey(ctx, keystore.GetKeyRequest{ID: keyStoreID})
	if err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "getting key for signing credential schema<%s>", fullyQualifiedVerificationMethodID)
	}
	if gotKey.Controller != issuer {
		return nil, sdkutil.LoggingNewErrorf("key controller<%s> does not match credential issuer<%s> for key<%s>", gotKey.Controller, issuer, fullyQualifiedVerificationMethodID)
	}
	if gotKey.Revoked {
		return nil, sdkutil.LoggingNewErrorf("cannot use revoked key<%s>", gotKey.ID)
	}
	keyAccess, err := keyaccess.NewJWKKeyAccess(fullyQualifiedVerificationMethodID, gotKey.ID, gotKey.Key)
	if err != nil {
		return nil, errors.Wrapf(err, "creating key access for signing credential schema with key<%s>", gotKey.ID)
	}
	credToken, err := keyAccess.SignVerifiableCredential(cred)
	if err != nil {
		return nil, errors.Wrapf(err, "could not sign credential schema with key<%s>", gotKey.ID)
	}
	return credToken, nil
}

func (s Service) ListSchemas(ctx context.Context, request ListSchemasRequest) (*ListSchemasResponse, error) {
	logrus.Debug("listing all schemas")

	storedSchemas, err := s.storage.ListSchemas(ctx, *request.PageRequest.ToServicePage())
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "error getting schemas")
	}
	schemas := make([]GetSchemaResponse, 0, len(storedSchemas.Schemas))
	for _, stored := range storedSchemas.Schemas {
		schemas = append(schemas, GetSchemaResponse{
			ID:               stored.ID,
			Type:             stored.Type,
			Schema:           stored.Schema,
			CredentialSchema: stored.CredentialSchema,
		})
	}

	return &ListSchemasResponse{Schemas: schemas, NextPageToken: storedSchemas.NextPageToken}, nil
}

func (s Service) GetSchema(ctx context.Context, request GetSchemaRequest) (*GetSchemaResponse, error) {
	logrus.Debugf("getting schema: %s", request.ID)

	// TODO(gabe) support external schema resolution https://github.com/TBD54566975/ssi-service/issues/125
	gotSchema, err := s.storage.GetSchema(ctx, request.ID)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "error getting schema: %s", request.ID)
	}
	if gotSchema == nil {
		return nil, sdkutil.LoggingNewErrorf("schema with id<%s> could not be found", request.ID)
	}
	return &GetSchemaResponse{
		ID:               gotSchema.ID,
		Type:             gotSchema.Type,
		Schema:           gotSchema.Schema,
		CredentialSchema: gotSchema.CredentialSchema,
	}, nil
}

func (s Service) DeleteSchema(ctx context.Context, request DeleteSchemaRequest) error {
	logrus.Debugf("deleting schema: %s", request.ID)

	if err := s.storage.DeleteSchema(ctx, request.ID); err != nil {
		return sdkutil.LoggingErrorMsgf(err, "deleting schema with id: %s", request.ID)
	}

	return nil
}

// Resolve wraps our get schema method for exposing schema access to other services
func (s Service) Resolve(ctx context.Context, id string) (*schema.JSONSchema, *schema.VCJSONSchema, schema.VCJSONSchemaType, error) {
	gotSchemaResponse, err := s.GetSchema(ctx, GetSchemaRequest{ID: id})
	if err != nil {
		return nil, nil, "", sdkutil.LoggingErrorMsg(err, "resolving schema")
	}
	switch gotSchemaResponse.Type {
	case schema.JSONSchemaType:
		return gotSchemaResponse.Schema, nil, schema.JSONSchemaType, nil
	case schema.JSONSchemaCredentialType:
		_, _, cred, err := parsing.ToCredential(gotSchemaResponse.CredentialSchema.String())
		if err != nil {
			return nil, nil, "", sdkutil.LoggingErrorMsg(err, "converting credential schema from jwt to credential map")
		}
		jsonSchema, ok := cred.CredentialSubject[credential.VerifiableCredentialJSONSchemaProperty]
		if !ok {
			return nil, nil, "", sdkutil.LoggingNewErrorf("credential schema does not contain %s property", credential.VerifiableCredentialJSONSchemaProperty)
		}
		credSubjectJSONSchemaBytes, err := json.Marshal(jsonSchema)
		if err != nil {
			return nil, nil, "", errors.Wrap(err, "marshalling credential subject")
		}
		var s schema.JSONSchema
		if err = json.Unmarshal(credSubjectJSONSchemaBytes, &s); err != nil {
			return nil, nil, "", errors.Wrap(err, "unmarshalling credential subject")
		}

		data, err := json.Marshal(cred)
		if err != nil {
			return nil, nil, "", sdkutil.LoggingErrorMsg(err, "marshalling credential")
		}

		var vcJSONSchema schema.VCJSONSchema
		if err := json.Unmarshal(data, &vcJSONSchema); err != nil {
			return nil, nil, "", sdkutil.LoggingErrorMsg(err, "umarshalling credential")
		}
		return &s, &vcJSONSchema, schema.JSONSchemaCredentialType, nil
	default:
		return nil, nil, "", sdkutil.LoggingNewErrorf("unknown schema type: %s", gotSchemaResponse.Type)
	}
}
