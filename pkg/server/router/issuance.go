package router

import (
	"context"
	"net/http"

	"github.com/pkg/errors"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/issuing"
)

type IssuanceRouter struct {
	service issuing.Service
}

func NewIssuanceRouter(svc framework.Service) (*IssuanceRouter, error) {
	service, ok := svc.(*issuing.Service)
	if !ok {
		return nil, errors.New("could not cast to issuing service type")
	}
	return &IssuanceRouter{service: *service}, nil
}

// GetIssuanceTemplate godoc
// @Summary      Get issuance template
// @Description  Get an issuance template by its id
// @Tags         IssuingAPI
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "ID"
// @Success      200  {object}  issuing.GetIssuanceTemplateResponse
// @Failure      400  {string}  string  "Bad request"
// @Router       /v1/issuancetemplates/{id} [get]
func (ir IssuanceRouter) GetIssuanceTemplate(ctx context.Context, w http.ResponseWriter, req *http.Request) error {
	return nil
}

// CreateIssuanceTemplate godoc
// @Summary      Create issuance template
// @Description  Create issuance template
// @Tags         IssuingAPI
// @Accept       json
// @Produce      json
// @Param        request  body      issuing.CreateIssuanceTemplateRequest  true  "request body"
// @Success      201      {object}  issuing.IssuanceTemplate
// @Failure      400      {string}  string  "Bad request"
// @Failure      500      {string}  string  "Internal server error"
// @Router       /v1/issuancetemplates [put]
func (ir IssuanceRouter) CreateIssuanceTemplate(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	return nil
}

// DeleteIssuanceTemplate godoc
// @Summary      Delete issuance template
// @Description  Delete issuance template by ID
// @Tags         IssuanceAPI
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "ID"
// @Success      200  {string}  string  "OK"
// @Failure      400  {string}  string  "Bad request"
// @Failure      500  {string}  string  "Internal server error"
// @Router       /v1/issuancetemplates/{id} [delete]
func (ir IssuanceRouter) DeleteIssuanceTemplate(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	return nil
}

type ListIssuanceTemplatesResponse struct {
	IssuanceTemplates []issuing.IssuanceTemplate `json:"issuanceTemplates"`
}

// ListIssuanceTemplates godoc
// @Summary      Lists issuance templates
// @Description  Lists all issuangce templates stored in this service.
// @Tags         IssuanceAPI
// @Accept       json
// @Produce      json
// @Success      200      {object}  ListIssuanceTemplatesResponse
// @Failure      400      {string}  string  "Bad request"
// @Failure      500      {string}  string  "Internal server error"
// @Router       /v1/manifests [get]
func (ir IssuanceRouter) ListIssuanceTemplates(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	return nil
}
