package router

import (
	"context"
	"fmt"
	"net/http"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	manifestsdk "github.com/TBD54566975/ssi-sdk/credential/manifest"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"

	"github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/pkg/service/manifest"

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
	manifestService, ok := s.(*manifest.Service)
	if !ok {
		return nil, fmt.Errorf("could not create manifest router with service type: %s", s.Type())
	}
	return &ManifestRouter{
		service: manifestService,
	}, nil
}

// CreateManifestRequest is the request body for creating a manifest, which populates all remaining fields
// and builds a well-formed manifest object.
type CreateManifestRequest struct {
	IssuerDID              string                           `json:"issuerDid" validate:"required"`
	IssuerName             *string                          `json:"issuerName,omitempty"`
	ClaimFormat            *exchange.ClaimFormat            `json:"format" validate:"required,dive"`
	OutputDescriptors      []manifestsdk.OutputDescriptor   `json:"outputDescriptors" validate:"required,dive"`
	PresentationDefinition *exchange.PresentationDefinition `json:"presentationDefinition,omitempty" validate:"omitempty,dive"`
}

func (c CreateManifestRequest) ToServiceRequest() manifest.CreateManifestRequest {
	return manifest.CreateManifestRequest{
		IssuerDID:              c.IssuerDID,
		IssuerName:             c.IssuerName,
		OutputDescriptors:      c.OutputDescriptors,
		ClaimFormat:            c.ClaimFormat,
		PresentationDefinition: c.PresentationDefinition,
	}
}

type CreateManifestResponse struct {
	Manifest    manifestsdk.CredentialManifest `json:"credential_manifest"`
	ManifestJWT keyaccess.JWT                  `json:"manifestJwt"`
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

	if err := framework.ValidateRequest(request); err != nil {
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

	resp := CreateManifestResponse{Manifest: createManifestResponse.Manifest, ManifestJWT: createManifestResponse.ManifestJWT}
	return framework.Respond(ctx, w, resp, http.StatusCreated)
}

type GetManifestResponse struct {
	ID          string                         `json:"id"`
	Manifest    manifestsdk.CredentialManifest `json:"credential_manifest"`
	ManifestJWT keyaccess.JWT                  `json:"manifestJwt"`
}

// GetManifest godoc
// @Summary      Get manifest
// @Description  Get a credential manifest by its id
// @Tags         ManifestAPI
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "ID"
// @Success      200  {object}  GetManifestResponse
// @Failure      400  {string}  string  "Bad request"
// @Router       /v1/manifests/{id} [get]
func (mr ManifestRouter) GetManifest(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
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
		ID:          gotManifest.Manifest.ID,
		Manifest:    gotManifest.Manifest,
		ManifestJWT: gotManifest.ManifestJWT,
	}
	return framework.Respond(ctx, w, resp, http.StatusOK)
}

type GetManifestsResponse struct {
	Manifests []GetManifestResponse `json:"manifests,omitempty"`
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
func (mr ManifestRouter) GetManifests(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	gotManifests, err := mr.service.GetManifests()

	if err != nil {
		errMsg := fmt.Sprintf("could not get manifests")
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	var manifests []GetManifestResponse
	for _, m := range gotManifests.Manifests {
		manifests = append(manifests, GetManifestResponse{
			ID:          m.Manifest.ID,
			Manifest:    m.Manifest,
			ManifestJWT: m.ManifestJWT,
		})
	}

	resp := GetManifestsResponse{Manifests: manifests}
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
func (mr ManifestRouter) DeleteManifest(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
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

type SubmitApplicationRequest struct {
	ApplicationJWT keyaccess.JWT `json:"applicationJwt" validate:"required"`
	// Contains the following properties:
	// Application  manifestsdk.CredentialApplication `json:"credential_application" validate:"required"`
	// Credentials  []interface{}                     `json:"vcs" validate:"required"`
}

const (
	vcsJSONProperty                   = "vcs"
	verifiableCredentialsJSONProperty = "verifiableCredentials"
)

func (sar SubmitApplicationRequest) ToServiceRequest() (*manifest.SubmitApplicationRequest, error) {
	parsed, err := jwt.Parse([]byte(sar.ApplicationJWT))
	if err != nil {
		return nil, errors.Wrap(err, "could not parse Credential Application token")
	}

	// make sure the known properties are present (Application and Credentials)
	kid, ok := parsed.Get(jwk.KeyIDKey)
	if !ok || kid == "" {
		return nil, errors.New("Credential Application token missing kid")
	}
	var creds []interface{}
	credentials, ok := parsed.Get(vcsJSONProperty)
	if !ok {
		logrus.Warn("could not find vc in Credential Application token, looking for `verifiableCredentials`")
		if credentials, ok = parsed.Get(verifiableCredentialsJSONProperty); !ok {
			return nil, errors.New("could not find vc or verifiableCredentials in Credential Application token")
		}
	}
	creds = credentials.([]interface{})

	// marshal known properties into their respective types
	credAppJSON, ok := parsed.Get(manifestsdk.CredentialApplicationJSONProperty)
	if !ok {
		return nil, errors.New("could not find credential_application in Credential Application token")
	}
	applicationTokenBytes, err := json.Marshal(credAppJSON)
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal Credential Application credAppJSON")
	}
	var application manifestsdk.CredentialApplication
	if err = json.Unmarshal(applicationTokenBytes, &application); err != nil {
		errMsg := "could not reconstruct Credential Application"
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrap(err, errMsg)
	}

	credContainer, err := credential.NewCredentialContainerFromArray(creds)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse submitted credentials")
	}
	return &manifest.SubmitApplicationRequest{
		ApplicantDID:    kid.(string),
		Application:     application,
		Credentials:     credContainer,
		ApplicationJWT:  sar.ApplicationJWT,
		ApplicationJSON: parsed.PrivateClaims(),
	}, nil
}

type SubmitApplicationResponse struct {
	Response manifestsdk.CredentialResponse `json:"credential_response"`
	// this is an interface type to union Data Integrity and JWT style VCs
	Credentials []interface{} `json:"verifiableCredentials"`
	ResponseJWT keyaccess.JWT `json:"responseJwt"`
}

// SubmitApplication godoc
// @Summary      Submit application
// @Description  Submit a credential application in response to a credential manifest
// @Tags         ApplicationAPI
// @Accept       json
// @Produce      json
// @Param        request  body      SubmitApplicationRequest  true  "request body"
// @Success      201      {object}  SubmitApplicationResponse
// @Failure      400      {string}  string  "Bad request"
// @Failure      500      {string}  string  "Internal server error"
// @Router       /v1/manifests/applications [put]
func (mr ManifestRouter) SubmitApplication(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	var request SubmitApplicationRequest
	if err := framework.Decode(r, &request); err != nil {
		errMsg := "invalid submit application request"
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	req, err := request.ToServiceRequest()
	if err != nil {
		errMsg := "invalid submit application request"
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	submitApplicationResponse, err := mr.service.ProcessApplicationSubmission(*req)
	if err != nil {
		errMsg := "could not submit application"
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	resp := SubmitApplicationResponse{
		Response:    submitApplicationResponse.Response,
		Credentials: submitApplicationResponse.Credentials,
		ResponseJWT: submitApplicationResponse.ResponseJWT,
	}

	return framework.Respond(ctx, w, resp, http.StatusCreated)
}

type GetApplicationResponse struct {
	ID          string                            `json:"id"`
	Application manifestsdk.CredentialApplication `json:"application"`
}

// GetApplication godoc
// @Summary      Get application
// @Description  Get application by id
// @Tags         ApplicationAPI
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "ID"
// @Success      200  {object}  GetApplicationResponse
// @Failure      400  {string}  string  "Bad request"
// @Router       /v1/manifests/applications/{id} [get]
func (mr ManifestRouter) GetApplication(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		errMsg := "cannot get application without ID parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	gotApplication, err := mr.service.GetApplication(manifest.GetApplicationRequest{ID: *id})
	if err != nil {
		errMsg := fmt.Sprintf("could not get application with id: %s", *id)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	resp := GetApplicationResponse{
		ID:          gotApplication.Application.ID,
		Application: gotApplication.Application,
	}
	return framework.Respond(ctx, w, resp, http.StatusOK)
}

type GetApplicationsResponse struct {
	Applications []manifestsdk.CredentialApplication `json:"applications"`
}

// GetApplications godoc
// @Summary      Get applications
// @Description  Checks for the presence of a query parameter and calls the associated filtered get method
// @Tags         ApplicationAPI
// @Accept       json
// @Produce      json
// @Success      200      {object}  GetApplicationsResponse
// @Failure      400      {string}  string  "Bad request"
// @Failure      500      {string}  string  "Internal server error"
// @Router       /v1/manifests/applications [get]
func (mr ManifestRouter) GetApplications(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	gotApplications, err := mr.service.GetApplications()

	if err != nil {
		errMsg := fmt.Sprintf("could not get applications")
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	resp := GetApplicationsResponse{
		Applications: gotApplications.Applications,
	}

	return framework.Respond(ctx, w, resp, http.StatusOK)
}

// DeleteApplication godoc
// @Summary      Delete applications
// @Description  Delete application by ID
// @Tags         ApplicationAPI
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "ID"
// @Success      200  {string}  string  "OK"
// @Failure      400  {string}  string  "Bad request"
// @Failure      500  {string}  string  "Internal server error"
// @Router       /v1/manifests/applications/{id} [delete]
func (mr ManifestRouter) DeleteApplication(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		errMsg := "cannot delete application without ID parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	if err := mr.service.DeleteApplication(manifest.DeleteApplicationRequest{ID: *id}); err != nil {
		errMsg := fmt.Sprintf("could not delete application with id: %s", *id)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	return framework.Respond(ctx, w, nil, http.StatusOK)
}

type GetResponseResponse struct {
	ID       string                         `json:"id"`
	Response manifestsdk.CredentialResponse `json:"response"`
}

// GetResponse godoc
// @Summary      Get response
// @Description  Get response by id
// @Tags         ResponseAPI
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "ID"
// @Success      200  {object}  GetResponseResponse
// @Failure      400  {string}  string  "Bad request"
// @Router       /v1/manifests/responses/{id} [get]
func (mr ManifestRouter) GetResponse(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		errMsg := "cannot get response without ID parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	gotResponse, err := mr.service.GetResponse(manifest.GetResponseRequest{ID: *id})
	if err != nil {
		errMsg := fmt.Sprintf("could not get response with id: %s", *id)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	resp := GetResponseResponse{
		ID:       gotResponse.Response.ID,
		Response: gotResponse.Response,
	}
	return framework.Respond(ctx, w, resp, http.StatusOK)
}

type GetResponsesResponse struct {
	Responses []manifestsdk.CredentialResponse `json:"responses"`
}

// GetResponses godoc
// @Summary      Get responses
// @Description  Checks for the presence of a query parameter and calls the associated filtered get method
// @Tags         ResponseAPI
// @Accept       json
// @Produce      json
// @Success      200      {object}  GetResponsesResponse
// @Failure      400      {string}  string  "Bad request"
// @Failure      500      {string}  string  "Internal server error"
// @Router       /v1/manifests/responses [get]
func (mr ManifestRouter) GetResponses(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	gotResponses, err := mr.service.GetResponses()

	if err != nil {
		errMsg := fmt.Sprintf("could not get responses")
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	resp := GetResponsesResponse{
		Responses: gotResponses.Responses,
	}

	return framework.Respond(ctx, w, resp, http.StatusOK)
}

// DeleteResponse godoc
// @Summary      Delete responses
// @Description  Delete response by ID
// @Tags         ResponseAPI
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "ID"
// @Success      200  {string}  string  "OK"
// @Failure      400  {string}  string  "Bad request"
// @Failure      500  {string}  string  "Internal server error"
// @Router       /v1/manifests/responses/{id} [delete]
func (mr ManifestRouter) DeleteResponse(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		errMsg := "cannot delete response without ID parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	if err := mr.service.DeleteResponse(manifest.DeleteResponseRequest{ID: *id}); err != nil {
		errMsg := fmt.Sprintf("could not delete response with id: %s", *id)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	return framework.Respond(ctx, w, nil, http.StatusOK)
}
