package router

import (
	"context"
	"fmt"
	"github.com/TBD54566975/ssi-sdk/credential/manifest"
	"github.com/tbd54566975/ssi-service/pkg/service/dwn"
	"net/http"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
)

type DWNRouter struct {
	service *dwn.Service
}

func NewDWNRouter(s svcframework.Service) (*DWNRouter, error) {
	if s == nil {
		return nil, errors.New("service cannot be nil")
	}
	dwnService, ok := s.(*dwn.Service)
	if !ok {
		return nil, fmt.Errorf("could not create dwn router with service type: %s", s.Type())
	}

	return &DWNRouter{
		service: dwnService,
	}, nil
}

type DWNPostRequest struct {
	Manifest manifest.CredentialManifest `json:"manifest" validate:"required"`
}

type PublishManifestRequest struct {
	ManifestID string `json:"manifestId" validate:"required"`
}

func (req PublishManifestRequest) ToServiceRequest() dwn.DWNPublishManifestRequest {
	return dwn.DWNPublishManifestRequest{
		ManifestID: req.ManifestID,
	}
}

type PublishManifestResponse struct {
	Manifest     manifest.CredentialManifest `json:"manifest" validate:"required"`
	Published    bool                        `json:"published" validate:"required"`
	ErrorMessage string                      `json:"errorMessage" validate:"required"`
}

// PublishManifest godoc
// @Summary      Public Manifest to DWN
// @Description  Public Manifest to DWN
// @Tags         DWNAPI
// @Accept       json
// @Produce      json
// @Param        request  body      PublishManifestRequest  true  "request body"
// @Success      201      {object}  PublishManifestResponse
// @Failure      400      {string}  string  "Bad request"
// @Failure      500      {string}  string  "Internal server error"
// @Router       /v1/dwn/manifest [put]
func (dwnr DWNRouter) PublishManifest(ctx context.Context, w http.ResponseWriter, r *http.Request) error {

	if dwnr.service.Config().DWNEndpoint == "" {
		errMsg := "could not publish manifest to dwn because dwn endpoint is not configured"
		logrus.Error(errMsg)
		return framework.NewRequestError(errors.New(errMsg), http.StatusInternalServerError)
	}

	var request PublishManifestRequest
	if err := framework.Decode(r, &request); err != nil {
		errMsg := "invalid publish manifest message request"
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	req := request.ToServiceRequest()
	publishManifestResponse, err := dwnr.service.PublishManifest(req)

	if err != nil {
		errMsg := "could not publish manifest to dwn"
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	dwnReq := DWNPostRequest{Manifest: publishManifestResponse.Manifest}
	dwnResp, err := framework.Post(dwnr.service.Config().DWNEndpoint, dwnReq)

	if err != nil || dwnResp == nil {
		errMsg := "problem with publishing manifest to downstream dwn"
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	status := dwnResp.StatusCode >= 200 && dwnResp.StatusCode < 300
	resp := PublishManifestResponse{Manifest: publishManifestResponse.Manifest, Published: status}

	return framework.Respond(ctx, w, resp, http.StatusAccepted)
}
