package schema

import (
	"fmt"
	"github.com/TBD54566975/ssi-sdk/credential/schema"
	schemalib "github.com/TBD54566975/ssi-sdk/schema"
	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	schemastorage "github.com/tbd54566975/ssi-service/pkg/service/schema/storage"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"time"
)

type Service struct {
	storage schemastorage.Storage
	config  config.SchemaServiceConfig
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

func NewSchemaService(config config.SchemaServiceConfig, s storage.ServiceStorage) (*Service, error) {
	schemaStorage, err := schemastorage.NewSchemaStorage(s)
	if err != nil {
		return nil, errors.Wrap(err, "could not instantiate Schema storage for the Schema service")
	}
	return &Service{
		storage: schemaStorage,
		config:  config,
	}, nil
}

// CreateSchema houses the main service logic for schema creation. It validates the input, and
// produces a schema value that conforms with the VC JSON Schema specification.
// TODO(gabe) support proof generation on schemas, versioning, and more
func (s Service) CreateSchema(request CreateSchemaRequest) (*CreateSchemaResponse, error) {
	schemaBytes, err := json.Marshal(request.Schema)
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal schema in request")
	}
	if err := schemalib.IsValidJSONSchema(string(schemaBytes)); err != nil {
		err := errors.Wrap(err, "provided value is not a valid JSON schema")
		logrus.WithError(err).Error()
		return nil, err
	}

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

	storedSchema := schemastorage.StoredSchema{Schema: schemaValue}
	if err := s.storage.StoreSchema(storedSchema); err != nil {
		err := errors.Wrap(err, "could not store schema")
		logrus.WithError(err).Error()
		return nil, err
	}

	return &CreateSchemaResponse{ID: schemaID, Schema: schemaValue}, nil
}

func (s Service) GetSchemas() (*GetSchemasResponse, error) {
	storedSchemas, err := s.storage.GetSchemas()
	if err != nil {
		return nil, errors.Wrap(err, "error getting schemas")
	}
	var schemas []schema.VCJSONSchema
	for _, stored := range storedSchemas {
		schemas = append(schemas, stored.Schema)
	}
	return &GetSchemasResponse{
		Schemas: schemas,
	}, nil
}

func (s Service) GetSchemaByID(request GetSchemaByIDRequest) (*GetSchemaByIDResponse, error) {
	gotSchema, err := s.storage.GetSchema(request.ID)
	if err != nil {
		err := errors.Wrapf(err, "error getting schema: %s", request.ID)
		logrus.WithError(err).Error()
		return nil, err
	}
	if gotSchema == nil {
		err := fmt.Errorf("schema with id<%s> could not be found", request.ID)
		logrus.WithError(err).Error()
		return nil, err
	}
	return &GetSchemaByIDResponse{Schema: gotSchema.Schema}, nil
}
