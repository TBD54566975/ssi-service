package schema

import (
	"context"
	"fmt"
	"strings"

	"github.com/TBD54566975/ssi-sdk/credential/schema"
	"github.com/TBD54566975/ssi-sdk/did/resolution"
	schemalib "github.com/TBD54566975/ssi-sdk/schema"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"

	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type Service struct {
	storage *Storage
	config  config.SchemaServiceConfig

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

func (s Service) Config() config.SchemaServiceConfig {
	return s.config
}

func NewSchemaService(config config.SchemaServiceConfig, s storage.ServiceStorage, keyStore *keystore.Service,
	resolver resolution.Resolver) (*Service, error) {
	schemaStorage, err := NewSchemaStorage(s)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not instantiate storage for the schema service")
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
// produces a schema value that conforms with the VC JSON SchemaID specification.
// TODO(gabe) support data integrity proofs for credential schemas
func (s Service) CreateSchema(ctx context.Context, request CreateSchemaRequest) (*CreateSchemaResponse, error) {
	logrus.Debugf("creating schema: %+v", request)

	if !request.IsValid() {
		return nil, sdkutil.LoggingNewErrorf("invalid create schema request: %+v", request)
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

	// set id, name, and description on the schema
	schemaID := uuid.NewString()
	jsonSchema[schema.JSONSchemaIDProperty] = strings.Join([]string{s.Config().ServiceEndpoint, schemaID}, "/")
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

	// TODO(gabe) support signing credential schemas
	// create schema
	storedSchema := StoredSchema{ID: schemaID, Schema: jsonSchema}
	if err = s.storage.StoreSchema(ctx, storedSchema); err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not store schema")
	}

	return &CreateSchemaResponse{ID: schemaID, Schema: jsonSchema}, nil
}

func (s Service) ListSchemas(ctx context.Context) (*ListSchemasResponse, error) {
	logrus.Debug("listing all schemas")

	storedSchemas, err := s.storage.ListSchemas(ctx)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "error getting schemas")
	}
	schemas := make([]GetSchemaResponse, 0, len(storedSchemas))
	for _, stored := range storedSchemas {
		schemas = append(schemas, GetSchemaResponse{
			ID:     stored.ID,
			Schema: stored.Schema,
		})
	}

	return &ListSchemasResponse{Schemas: schemas}, nil
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
	return &GetSchemaResponse{Schema: gotSchema.Schema}, nil
}

func (s Service) DeleteSchema(ctx context.Context, request DeleteSchemaRequest) error {
	logrus.Debugf("deleting schema: %s", request.ID)

	if err := s.storage.DeleteSchema(ctx, request.ID); err != nil {
		return sdkutil.LoggingErrorMsgf(err, "could not delete schema with id: %s", request.ID)
	}

	return nil
}

// Resolve wraps our get schema method for exposing schema access to other services
func (s Service) Resolve(ctx context.Context, id string) (*schema.JSONSchema, error) {
	gotSchemaResponse, err := s.GetSchema(ctx, GetSchemaRequest{ID: id})
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "resolving schema")
	}
	return &gotSchemaResponse.Schema, nil
}
