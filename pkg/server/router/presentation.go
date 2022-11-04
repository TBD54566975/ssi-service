package router

import (
	"context"
	"fmt"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/presentation"
	"net/http"
)

type PresentationDefinitionRouter struct {
	service *presentation.Service
}

func NewPresentationDefinitionRouter(s svcframework.Service) (*PresentationDefinitionRouter, error) {
	if s == nil {
		return nil, errors.New("service cannot be nil")
	}
	service, ok := s.(*presentation.Service)
	if !ok {
		return nil, fmt.Errorf("could not create presentation router with service type: %s", s.Type())
	}
	return &PresentationDefinitionRouter{service: service}, nil
}

type CreatePresentationDefinitionRequest struct {
	PresentationDefinition exchange.PresentationDefinition `json:"presentation_definition" validate:"required"`
}

type CreatePresentationDefinitionResponse struct {
	PresentationDefinition exchange.PresentationDefinition `json:"presentation_definition"`
}

// CreatePresentationDefinition godoc
// @Summary      Create PresentationDefinition
// @Description  Create presentation definition
// @Tags         PresentationDefinitionAPI
// @Accept       json
// @Produce      json
// @Param        request  body      CreatePresentationDefinitionRequest  true  "request body"
// @Success      201      {object}  CreatePresentationDefinitionResponse
// @Failure      400      {string}  string  "Bad request"
// @Failure      500      {string}  string  "Internal server error"
// @Router       /v1/presentation/definition [put]
func (sr PresentationDefinitionRouter) CreatePresentationDefinition(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	var request CreatePresentationDefinitionRequest
	invalidCreatePresentationDefinitionRequest := "invalid create presentation request"
	if err := framework.Decode(r, &request); err != nil {
		errMsg := invalidCreatePresentationDefinitionRequest
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	if err := framework.ValidateRequest(request); err != nil {
		errMsg := invalidCreatePresentationDefinitionRequest
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	req := presentation.CreatePresentationDefinitionRequest{}
	def, err := sr.service.CreatePresentationDefinition(req)
	if err != nil {
		errMsg := fmt.Sprintf("could not create presentation definition")
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	resp := CreatePresentationDefinitionResponse{def.PresentationDefinition}
	return framework.Respond(ctx, w, resp, http.StatusCreated)
}

type GetPresentationDefinitionResponse struct {
	ID                     string                          `json:"id"`
	PresentationDefinition exchange.PresentationDefinition `json:"presentation_definition"`
}

// GetPresentationDefinition godoc
// @Summary      Get PresentationDefinition
// @Description  Get a presentation definition by its ID
// @Tags         PresentationDefinitionAPI
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "ID"
// @Success      200  {object}  GetPresentationDefinitionResponse
// @Failure      400  {string}  string  "Bad request"
// @Router       /v1/presentation/definition/{id} [get]
func (sr PresentationDefinitionRouter) GetPresentationDefinition(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		errMsg := "cannot get presentation without ID parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	def, err := sr.service.GetPresentationDefinition(presentation.GetPresentationDefinitionRequest{ID: *id})
	if err != nil {
		errMsg := fmt.Sprintf("could not get presentation with id: %s", *id)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	resp := GetPresentationDefinitionResponse{
		ID:                     def.ID,
		PresentationDefinition: def.PresentationDefinition,
	}
	return framework.Respond(ctx, w, resp, http.StatusOK)
}

// DeletePresentationDefinition godoc
// @Summary      Delete PresentationDefinition
// @Description  Delete a presentation definition by its ID
// @Tags         PresentationDefinitionAPI
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "ID"
// @Success      200  {string}  string  "OK"
// @Failure      400  {string}  string  "Bad request"
// @Failure      500  {string}  string  "Internal server error"
// @Router       /v1/presentation/definition/{id} [delete]
func (sr PresentationDefinitionRouter) DeletePresentationDefinition(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		errMsg := "cannot delete a presentation without an ID parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	if err := sr.service.DeletePresentationDefinition(presentation.DeletePresentationDefinitionRequest{ID: *id}); err != nil {
		errMsg := fmt.Sprintf("could not delete presentation with id: %s", *id)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	return framework.Respond(ctx, w, nil, http.StatusOK)
}
