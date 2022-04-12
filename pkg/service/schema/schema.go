package schema

import (
	"github.com/TBD54566975/ssi-sdk/credential/schema"
	"github.com/pkg/errors"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	schemastorage "github.com/tbd54566975/ssi-service/pkg/service/schema/storage"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"log"
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

func (s Service) CreateSchema() (*CreateSchemaResponse, error) {

	return nil, nil
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
	return nil, nil
}
