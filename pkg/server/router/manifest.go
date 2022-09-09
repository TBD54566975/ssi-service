package router

import (
	"context"
	"fmt"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	manifestsdk "github.com/TBD54566975/ssi-sdk/credential/manifest"
	"github.com/tbd54566975/ssi-service/pkg/service/manifest"
	"net/http"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
)

type ManifestRouter struct {
	service *manifest.Service
}

func NewManifestRouter(s svcframework.Service) (*ManifestRouter, error) {
	if s == nil {
		return nil, errors.New("service cannot be nil")
	}
	credService, ok := s.(*manifest.Service)
	if !ok {
		return nil, fmt.Errorf("could not create manifest router with service type: %s", s.Type())
	}
	return &ManifestRouter{
		service: credService,
	}, nil
}

type CreateManifestRequest struct {
	Issuer string `json:"issuer" validate:"required"`
	// A context is optional. If not present, we'll apply default, required context values.
	Context                string                          `json:"@context"`
	OutputDescriptors      []manifestsdk.OutputDescriptor  `json:"outputDescriptors" validate:"required"`
	PresentationDefinition exchange.PresentationDefinition `json:"presentationDefinition" validate:"required"`
}

func (c CreateManifestRequest) ToServiceRequest() manifest.CreateManifestRequest {
	return manifest.CreateManifestRequest{
		Issuer:                 c.Issuer,
		Context:                c.Context,
		OutputDescriptors:      c.OutputDescriptors,
		PresentationDefinition: c.PresentationDefinition,
	}
}

type CreateManifestResponse struct {
	Manifest manifestsdk.CredentialManifest `json:"manifest"`
}

// CreateManifest godoc
// @Summary      Create manifest
// @Description  Create manifest
// @Tags         ManifestAPI
// @Accept       json
// @Produce      json
// @Param        request  body      CreateManifestRequest  true  "request body"
// @Success      201      {object}  CreateManifestResponse
// @Failure      400      {string}  string  "Bad request"
// @Failure      500      {string}  string  "Internal server error"
// @Router       /v1/manifests [put]
func (mr ManifestRouter) CreateManifest(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	var request CreateManifestRequest
	if err := framework.Decode(r, &request); err != nil {
		errMsg := "invalid create manifest request"
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	req := request.ToServiceRequest()
	createManifestResponse, err := mr.service.CreateManifest(req)
	if err != nil {
		errMsg := "could not create manifest"
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	resp := CreateManifestResponse{Manifest: createManifestResponse.Manifest}

	return framework.Respond(ctx, w, resp, http.StatusCreated)
}

type GetManifestResponse struct {
	ID       string                         `json:"id"`
	Manifest manifestsdk.CredentialManifest `json:"manifest"`
}

// GetManifest godoc
// @Summary      Get manifest
// @Description  Get manifest by id
// @Tags         ManifestAPI
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "ID"
// @Success      200  {object}  GetManifestResponse
// @Failure      400  {string}  string  "Bad request"
// @Router       /v1/manifests/{id} [get]
func (mr ManifestRouter) GetManifest(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		errMsg := "cannot get manifest without ID parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	gotManifest, err := mr.service.GetManifest(manifest.GetManifestRequest{ID: *id})
	if err != nil {
		errMsg := fmt.Sprintf("could not get manifest with id: %s", *id)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	resp := GetManifestResponse{
		ID:       gotManifest.Manifest.ID,
		Manifest: gotManifest.Manifest,
	}
	return framework.Respond(ctx, w, resp, http.StatusOK)
}

type GetManifestsResponse struct {
	Manifests []manifestsdk.CredentialManifest `json:"manifests"`
}

// GetManifests godoc
// @Summary      Get manifests
// @Description  Checks for the presence of a query parameter and calls the associated filtered get method
// @Tags         ManifestAPI
// @Accept       json
// @Produce      json
// @Param        issuer   query     string  false  "string issuer"
// @Param        schema   query     string  false  "string schema"
// @Param        subject  query     string  false  "string subject"
// @Success      200      {object}  GetManifestsResponse
// @Failure      400      {string}  string  "Bad request"
// @Failure      500      {string}  string  "Internal server error"
// @Router       /v1/manifests [get]
func (mr ManifestRouter) GetManifests(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	gotManifests, err := mr.service.GetManifests()

	if err != nil {
		errMsg := fmt.Sprintf("could not get manifests")
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	resp := GetManifestsResponse{
		Manifests: gotManifests.Manifests,
	}

	return framework.Respond(ctx, w, resp, http.StatusOK)
}

// DeleteManifest godoc
// @Summary      Delete manifests
// @Description  Delete manifest by ID
// @Tags         ManifestAPI
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "ID"
// @Success      200  {string}  string  "OK"
// @Failure      400  {string}  string  "Bad request"
// @Failure      500  {string}  string  "Internal server error"
// @Router       /v1/manifests/{id} [delete]
func (mr ManifestRouter) DeleteManifest(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		errMsg := "cannot delete manifest without ID parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	if err := mr.service.DeleteManifest(manifest.DeleteManifestRequest{ID: *id}); err != nil {
		errMsg := fmt.Sprintf("could not delete manifest with id: %s", *id)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	return framework.Respond(ctx, w, nil, http.StatusOK)
}
