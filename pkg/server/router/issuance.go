package router

import (
	"net/http"

	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"

	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/issuing"
)

type IssuanceRouter struct {
	service issuing.Service
}

func NewIssuanceRouter(svc svcframework.Service) (*IssuanceRouter, error) {
	service, ok := svc.(*issuing.Service)
	if !ok {
		return nil, errors.New("could not cast to issuing service type")
	}
	return &IssuanceRouter{service: *service}, nil
}

// GetIssuanceTemplate godoc
//
// @Summary     Get issuance template
// @Description Get an issuance template by its id
// @Tags        IssuingAPI
// @Accept      json
// @Produce     json
// @Param       id  path     string true "ID"
// @Success     200 {object} issuing.IssuanceTemplate
// @Failure     400 {string} string "Bad request"
// @Router      /v1/issuancetemplates/{id} [get]
func (ir IssuanceRouter) GetIssuanceTemplate(ctx *gin.Context) error {
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		return framework.NewRequestError(
			sdkutil.LoggingNewError("cannot get issuance template without an ID"), http.StatusBadRequest)
	}

	issuanceTemplate, err := ir.service.GetIssuanceTemplate(ctx, &issuing.GetIssuanceTemplateRequest{ID: *id})
	if err != nil {
		return framework.NewRequestError(
			sdkutil.LoggingErrorMsg(err, "getting issuance template"), http.StatusInternalServerError)
	}
	return framework.Respond(ctx, issuanceTemplate.IssuanceTemplate, http.StatusOK)
}

type CreateIssuanceTemplateRequest struct {
	issuing.IssuanceTemplate
}

func (r CreateIssuanceTemplateRequest) ToServiceRequest() *issuing.CreateIssuanceTemplateRequest {
	return &issuing.CreateIssuanceTemplateRequest{
		IssuanceTemplate: r.IssuanceTemplate,
	}
}

// CreateIssuanceTemplate godoc
//
// @Summary     Create issuance template
// @Description Create issuance template
// @Tags        IssuingAPI
// @Accept      json
// @Produce     json
// @Param       request body     CreateIssuanceTemplateRequest true "request body"
// @Success     201     {object} issuing.IssuanceTemplate
// @Failure     400     {string} string "Bad request"
// @Failure     500     {string} string "Internal server error"
// @Router      /v1/issuancetemplates [put]
func (ir IssuanceRouter) CreateIssuanceTemplate(ctx *gin.Context) error {
	var request CreateIssuanceTemplateRequest
	errMsg := "Invalid Issuance Template Request"
	if err := framework.Decode(ctx.Request, &request); err != nil {
		return framework.NewRequestError(
			sdkutil.LoggingErrorMsg(err, errMsg), http.StatusBadRequest)
	}

	template, err := ir.service.CreateIssuanceTemplate(ctx, request.ToServiceRequest())
	if err != nil {
		return framework.NewRequestError(
			sdkutil.LoggingErrorMsg(err, "creating issuance template"), http.StatusInternalServerError)
	}

	return framework.Respond(ctx, template, http.StatusCreated)
}

// DeleteIssuanceTemplate godoc
//
// @Summary     Delete issuance template
// @Description Delete issuance template by ID
// @Tags        IssuingAPI
// @Accept      json
// @Produce     json
// @Param       id  path     string true "ID"
// @Success     204 {string} string "No Content"
// @Failure     400 {string} string "Bad request"
// @Failure     500 {string} string "Internal server error"
// @Router      /v1/issuancetemplates/{id} [delete]
func (ir IssuanceRouter) DeleteIssuanceTemplate(ctx *gin.Context) error {
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		return framework.NewRequestError(
			sdkutil.LoggingNewError("cannot delete an issuance template without an ID parameter"), http.StatusBadRequest)
	}

	if err := ir.service.DeleteIssuanceTemplate(ctx, &issuing.DeleteIssuanceTemplateRequest{ID: *id}); err != nil {
		return framework.NewRequestError(
			sdkutil.LoggingErrorMsgf(err, "could not delete issuance template with id: %s", *id), http.StatusInternalServerError)
	}

	return framework.Respond(ctx, nil, http.StatusNoContent)
}

type ListIssuanceTemplatesResponse struct {
	IssuanceTemplates []issuing.IssuanceTemplate `json:"issuanceTemplates"`
}

// ListIssuanceTemplates godoc
//
// @Summary     Lists issuance templates
// @Description Lists all issuance templates stored in this service.
// @Tags        IssuingAPI
// @Accept      json
// @Produce     json
// @Success     200 {object} ListIssuanceTemplatesResponse
// @Failure     400 {string} string "Bad request"
// @Failure     500 {string} string "Internal server error"
// @Router      /v1/manifests [get]
func (ir IssuanceRouter) ListIssuanceTemplates(ctx *gin.Context) error {
	gotManifests, err := ir.service.ListIssuanceTemplates(ctx, &issuing.ListIssuanceTemplatesRequest{})

	if err != nil {
		return framework.NewRequestError(
			sdkutil.LoggingErrorMsg(err, "could not get templates"), http.StatusBadRequest)
	}

	resp := ListIssuanceTemplatesResponse{IssuanceTemplates: gotManifests.IssuanceTemplates}
	return framework.Respond(ctx, resp, http.StatusOK)
}
