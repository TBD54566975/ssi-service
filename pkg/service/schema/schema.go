package schema

import (
	"fmt"
	"time"

	"github.com/TBD54566975/ssi-sdk/credential/schema"
	schemalib "github.com/TBD54566975/ssi-sdk/schema"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/google/uuid"
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
}

func (s Service) Type() framework.Type {
	return framework.Schema
}

func (s Service) Status() framework.Status {
	if s.storage == nil {
		return framework.Status{
			Status:  framework.StatusNotReady,
			Message: "storage not loaded",
		}
	}
	return framework.Status{Status: framework.StatusReady}
}

func (s Service) Config() config.SchemaServiceConfig {
	return s.config
}

func NewSchemaService(config config.SchemaServiceConfig, s storage.ServiceStorage, keyStore *keystore.Service) (*Service, error) {
	schemaStorage, err := schemastorage.NewSchemaStorage(s)
	if err != nil {
		errMsg := "could not instantiate storage for the schema service"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	return &Service{
		storage:  schemaStorage,
		config:   config,
		keyStore: keyStore,
	}, nil
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
		Schema:   request.Schema,
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
	return sdkutil.StringPtr(string(schemaToken)), nil
}

func (s Service) verifySchemaJWT(token string) error {
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

func (s Service) DeleteSchema(request DeleteSchemaRequest) error {

	logrus.Debugf("deleting schema: %s", request.ID)

	if err := s.storage.DeleteSchema(request.ID); err != nil {
		errMsg := fmt.Sprintf("could not delete schema with id: %s", request.ID)
		return util.LoggingErrorMsg(err, errMsg)
	}

	return nil
}
