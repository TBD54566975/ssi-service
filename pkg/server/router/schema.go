package router

import (
	"context"
	"fmt"
	schemalib "github.com/TBD54566975/ssi-sdk/credential/schema"
	"github.com/pkg/errors"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
	"log"
	"net/http"
)

type SchemaRouter struct {
	service *schema.Service
	logger  *log.Logger
}

func NewSchemaRouter(s svcframework.Service, l *log.Logger) (*SchemaRouter, error) {
	if s == nil {
		return nil, errors.New("service cannot be nil")
	}
	schemaService, ok := s.(*schema.Service)
	if !ok {
		return nil, fmt.Errorf("could not create schema router with service type: %s", s.Type())
	}
	return &SchemaRouter{
		service: schemaService,
		logger:  l,
	}, nil
}

type CreateSchemaRequest struct {
	DID    string                 `json:"did,omitempty"`
	Schema schemalib.VCJSONSchema `json:"schema" validate:"required"`
}

func (sr SchemaRouter) CreateSchema(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	return nil
}

type GetSchemasResponse struct {
	Schemas []schemalib.VCJSONSchema `json:"schemas,omitempty"`
}

func (sr SchemaRouter) GetSchemas(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (sr SchemaRouter) GetSchemaByID(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	return nil
}
