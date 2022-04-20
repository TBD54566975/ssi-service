package schema

import (
	"encoding/json"
	"fmt"
	"github.com/TBD54566975/ssi-sdk/credential/schema"
	schemalib "github.com/TBD54566975/ssi-sdk/schema"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	schemastorage "github.com/tbd54566975/ssi-service/pkg/service/schema/storage"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"log"
	"time"
)

type Service struct {
	storage schemastorage.Storage
	log     *log.Logger
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

func NewSchemaService(logger *log.Logger, s storage.ServiceStorage) (*Service, error) {
	schemaStorage, err := schemastorage.NewSchemaStorage(s)
	if err != nil {
		return nil, errors.Wrap(err, "could not instantiate Schema storage for the Schema service")
	}
	return &Service{
		storage: schemaStorage,
		log:     logger,
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
		return nil, errors.Wrap(err, "provided value is not a valid JSON schema")
	}

	schemaID := uuid.NewString()
	schema := schema.VCJSONSchema{
		Type:     schema.VCJSONSchemaType,
		Version:  Version1,
		ID:       schemaID,
		Name:     request.Name,
		Author:   request.Author,
		Authored: time.Now().Format(time.RFC3339),
		Schema:   request.Schema,
	}

	storedSchema := schemastorage.StoredSchema{Schema: schema}
	if err := s.storage.StoreSchema(storedSchema); err != nil {
		return nil, errors.Wrap(err, "could not store schema")
	}

	return &CreateSchemaResponse{ID: schemaID, Schema: schema}, nil
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
		return nil, fmt.Errorf("error getting schema: %s", request.ID)
	}
	if gotSchema == nil {
		return nil, fmt.Errorf("schema with id<%s> could not be found", request.ID)
	}
	return &GetSchemaByIDResponse{Schema: gotSchema.Schema}, nil
}
