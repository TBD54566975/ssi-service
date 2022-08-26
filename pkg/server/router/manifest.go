package router

import (
	"context"
	"fmt"
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
	Context string                 `json:"@context"`
	Data    map[string]interface{} `json:"data" validate:"required"`
}

func (c CreateManifestRequest) ToServiceRequest() manifest.CreateManifestRequest {
	return manifest.CreateManifestRequest{
		Issuer:            c.Issuer,
		Context:           c.Context,
		OutputDescriptors: c.Data,
	}
}

type CreateManifestResponse struct {
	manifest manifestsdk.CredentialManifest `json:"manifest"`
}

// CreateManifest godoc
// @Summary      Create manifest
// @Description  Create manifest
// @Tags         manifestAPI
// @Accept       json
// @Produce      json
// @Param        request  body      CreatemanifestRequest  true  "request body"
// @Success      201      {object}  CreatemanifestResponse
// @Failure      400      {string}  string  "Bad request"
// @Failure      500      {string}  string  "Internal server error"
// @Router       /v1/manifests [put]
func (cr ManifestRouter) CreateManifest(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	var request CreateManifestRequest
	if err := framework.Decode(r, &request); err != nil {
		errMsg := "invalid create manifest request"
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	req := request.ToServiceRequest()
	createManifestResponse, err := cr.service.CreateManifest(req)
	if err != nil {
		errMsg := "could not create manifest"
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	resp := CreateManifestResponse{manifest: createManifestResponse.Manifest}
	return framework.Respond(ctx, w, resp, http.StatusCreated)
}

type GetManifestResponse struct {
	ID       string                         `json:"id"`
	manifest manifestsdk.CredentialManifest `json:"manifest"`
}

// GetManifest godoc
// @Summary      Get manifest
// @Description  Get manifest by id
// @Tags         manifestAPI
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "ID"
// @Success      200  {object}  GetmanifestResponse
// @Failure      400  {string}  string  "Bad request"
// @Router       /v1/manifests/{id} [get]
func (cr ManifestRouter) GetManifest(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		errMsg := "cannot get manifest without ID parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	gotManifest, err := cr.service.GetManifest(manifest.GetManifestRequest{ID: *id})
	if err != nil {
		errMsg := fmt.Sprintf("could not get manifest with id: %s", *id)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	resp := GetManifestResponse{
		ID:       gotManifest.Manifest.ID,
		manifest: gotManifest.Manifest,
	}
	return framework.Respond(ctx, w, resp, http.StatusOK)
}

type GetmanifestsResponse struct {
	manifests []manifestsdk.CredentialManifest `json:"manifests"`
}

// GetManifests godoc
// @Summary      Get manifests
// @Description  Checks for the presence of a query parameter and calls the associated filtered get method
// @Tags         manifestAPI
// @Accept       json
// @Produce      json
// @Param        issuer   query     string  false  "string issuer"
// @Param        schema   query     string  false  "string schema"
// @Param        subject  query     string  false  "string subject"
// @Success      200      {object}  GetmanifestsResponse
// @Failure      400      {string}  string  "Bad request"
// @Failure      500      {string}  string  "Internal server error"
// @Router       /v1/manifests [get]
func (cr ManifestRouter) GetManifests(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	//issuer := framework.GetQueryValue(r, IssuerParam)
	//
	//err := framework.NewRequestErrorMsg("must use one of the following query parameters: issuer, subject, schema", http.StatusBadRequest)

	return cr.GetManifests(ctx, w, r)
	//if issuer != nil {
	//	return cr.get(*issuer, ctx, w, r)
	//} else {
	//	return cr.GetManifests(ctx, w, r)
	//}
	//return err
}

//func (cr ManifestRouter) getManifestsByIssuer(issuer string, ctx context.Context, w http.ResponseWriter, r *http.Request) error {
//	gotManifests, err := cr.service.GetManifestsByIssuer(manifest.GetManifestByIssuerRequest{Issuer: issuer})
//	if err != nil {
//		errMsg := fmt.Sprintf("could not get manifests for issuer: %s", util.SanitizeLog(issuer))
//		logrus.WithError(err).Error(errMsg)
//		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
//	}
//
//	resp := GetmanifestsResponse{manifests: gotmanifests.manifests}
//	return framework.Respond(ctx, w, resp, http.StatusOK)
//}

// Deletemanifest godoc
// @Summary      Delete manifests
// @Description  Delete manifest by ID
// @Tags         manifestAPI
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "ID"
// @Success      200  {string}  string  "OK"
// @Failure      400  {string}  string  "Bad request"
// @Failure      500  {string}  string  "Internal server error"
// @Router       /v1/manifests/{id} [delete]
func (cr ManifestRouter) DeleteManifest(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		errMsg := "cannot delete manifest without ID parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	if err := cr.service.DeleteManifest(manifest.DeleteManifestRequest{ID: *id}); err != nil {
		errMsg := fmt.Sprintf("could not delete manifest with id: %s", *id)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	return framework.Respond(ctx, w, nil, http.StatusOK)
}
