package router

import (
	"fmt"
	"net/http"

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
//	@Summary		Get issuance template
//	@Description	Get an issuance template by its id
//	@Tags			IssuingAPI
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"ID"
//	@Success		200	{object}	issuing.Template
//	@Failure		400	{string}	string	"Bad request"
//	@Router			/v1/issuancetemplates/{id} [get]
func (ir IssuanceRouter) GetIssuanceTemplate(c *gin.Context) {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "cannot get issuance template without an ID"
		framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
		return
	}

	issuanceTemplate, err := ir.service.GetIssuanceTemplate(c, &issuing.GetIssuanceTemplateRequest{ID: *id})
	if err != nil {
		errMsg := "getting issuance template"
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}
	framework.Respond(c, issuanceTemplate.IssuanceTemplate, http.StatusOK)
}

type CreateIssuanceTemplateRequest struct {
	issuing.Template
}

func (r CreateIssuanceTemplateRequest) toServiceRequest() *issuing.CreateIssuanceTemplateRequest {
	return &issuing.CreateIssuanceTemplateRequest{IssuanceTemplate: r.Template}
}

// CreateIssuanceTemplate godoc
//
//	@Summary		Create issuance template
//	@Description	Create issuance template
//	@Tags			IssuingAPI
//	@Accept			json
//	@Produce		json
//	@Param			request	body		CreateIssuanceTemplateRequest	true	"request body"
//	@Success		201		{object}	issuing.Template
//	@Failure		400		{string}	string	"Bad request"
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/v1/issuancetemplates [put]
func (ir IssuanceRouter) CreateIssuanceTemplate(c *gin.Context) {
	errMsg := "Invalid Issuance Template Request"
	var request CreateIssuanceTemplateRequest
	if err := framework.Decode(c.Request, &request); err != nil {
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
		return
	}

	template, err := ir.service.CreateIssuanceTemplate(c, request.toServiceRequest())
	if err != nil {
		errMsg = "creating issuing template"
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}

	framework.Respond(c, template, http.StatusCreated)
}

// DeleteIssuanceTemplate godoc
//
//	@Summary		Delete issuance template
//	@Description	Delete issuance template by ID
//	@Tags			IssuingAPI
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"ID"
//	@Success		204	{string}	string	"No Content"
//	@Failure		400	{string}	string	"Bad request"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/v1/issuancetemplates/{id} [delete]
func (ir IssuanceRouter) DeleteIssuanceTemplate(c *gin.Context) {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "cannot delete an issuing template without an ID parameter"
		framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
		return
	}

	if err := ir.service.DeleteIssuanceTemplate(c, &issuing.DeleteIssuanceTemplateRequest{ID: *id}); err != nil {
		errMsg := fmt.Sprintf("could not delete issuance template with id: %s", *id)
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}

	framework.Respond(c, nil, http.StatusNoContent)
}

type ListIssuanceTemplatesResponse struct {
	IssuanceTemplates []issuing.Template `json:"issuanceTemplates,omitempty"`
}

// ListIssuanceTemplates godoc
//
//	@Summary		Lists issuance templates
//	@Description	Lists all issuance templates stored in this service.
//	@Tags			IssuingAPI
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	ListIssuanceTemplatesResponse
//	@Failure		400	{string}	string	"Bad request"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/v1/manifests [get]
func (ir IssuanceRouter) ListIssuanceTemplates(c *gin.Context) {
	gotManifests, err := ir.service.ListIssuanceTemplates(c, &issuing.ListIssuanceTemplatesRequest{})
	if err != nil {
		errMsg := "could not get templates"
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
		return
	}

	resp := ListIssuanceTemplatesResponse{IssuanceTemplates: gotManifests.IssuanceTemplates}
	framework.Respond(c, resp, http.StatusOK)
}
