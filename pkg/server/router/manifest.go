package router

import (
	"fmt"
	"net/http"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	manifestsdk "github.com/TBD54566975/ssi-sdk/credential/manifest"
	"github.com/gin-gonic/gin"
	"github.com/goccy/go-json"

	"github.com/tbd54566975/ssi-service/pkg/service/manifest/model"

	"github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/internal/util"
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
	return &ManifestRouter{service: manifestService}, nil
}

// CreateManifestRequest is the request body for creating a manifest, which populates all remaining fields
// and builds a well-formed manifest object.
type CreateManifestRequest struct {
	Name                   *string                          `json:"name,omitempty"`
	Description            *string                          `json:"description,omitempty"`
	IssuerDID              string                           `json:"issuerDid" validate:"required"`
	IssuerKID              string                           `json:"issuerKid" validate:"required"`
	IssuerName             *string                          `json:"issuerName,omitempty"`
	ClaimFormat            *exchange.ClaimFormat            `json:"format" validate:"required,dive"`
	OutputDescriptors      []manifestsdk.OutputDescriptor   `json:"outputDescriptors" validate:"required,dive"`
	PresentationDefinition *exchange.PresentationDefinition `json:"presentationDefinition,omitempty" validate:"omitempty,dive"`
}

func (c CreateManifestRequest) ToServiceRequest() model.CreateManifestRequest {
	return model.CreateManifestRequest{
		Name:                   c.Name,
		Description:            c.Description,
		IssuerDID:              c.IssuerDID,
		IssuerKID:              c.IssuerKID,
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
//
//	@Summary		Create manifest
//	@Description	Create manifest
//	@Tags			ManifestAPI
//	@Accept			json
//	@Produce		json
//	@Param			request	body		CreateManifestRequest	true	"request body"
//	@Success		201		{object}	CreateManifestResponse
//	@Failure		400		{string}	string	"Bad request"
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/v1/manifests [put]
func (mr ManifestRouter) CreateManifest(c *gin.Context) error {
	var request CreateManifestRequest
	if err := framework.Decode(c.Request, &request); err != nil {
		errMsg := "invalid create manifest request"
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
	}

	if err := framework.ValidateRequest(request); err != nil {
		errMsg := "invalid create manifest request"
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
	}

	req := request.ToServiceRequest()
	createManifestResponse, err := mr.service.CreateManifest(c, req)
	if err != nil {
		errMsg := "could not create manifest"
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}

	resp := CreateManifestResponse{Manifest: createManifestResponse.Manifest, ManifestJWT: createManifestResponse.ManifestJWT}
	return framework.Respond(c, resp, http.StatusCreated)
}

type GetManifestResponse struct {
	ID          string                         `json:"id"`
	Manifest    manifestsdk.CredentialManifest `json:"credential_manifest"`
	ManifestJWT keyaccess.JWT                  `json:"manifestJwt"`
}

// GetManifest godoc
//
//	@Summary		Get manifest
//	@Description	Get a credential manifest by its id
//	@Tags			ManifestAPI
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"ID"
//	@Success		200	{object}	GetManifestResponse
//	@Failure		400	{string}	string	"Bad request"
//	@Router			/v1/manifests/{id} [get]
func (mr ManifestRouter) GetManifest(c *gin.Context) error {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "cannot get manifest without ID parameter"
		return framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
	}

	gotManifest, err := mr.service.GetManifest(c, model.GetManifestRequest{ID: *id})
	if err != nil {
		errMsg := fmt.Sprintf("could not get manifest with id: %s", *id)
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
	}

	resp := GetManifestResponse{
		ID:          gotManifest.Manifest.ID,
		Manifest:    gotManifest.Manifest,
		ManifestJWT: gotManifest.ManifestJWT,
	}
	return framework.Respond(c, resp, http.StatusOK)
}

type GetManifestsResponse struct {
	Manifests []GetManifestResponse `json:"manifests,omitempty"`
}

// GetManifests godoc
//
//	@Summary		Get manifests
//	@Description	Checks for the presence of a query parameter and calls the associated filtered get method
//	@Tags			ManifestAPI
//	@Accept			json
//	@Produce		json
//	@Param			issuer	query		string	false	"string issuer"
//	@Param			schema	query		string	false	"string schema"
//	@Param			subject	query		string	false	"string subject"
//	@Success		200		{object}	GetManifestsResponse
//	@Failure		400		{string}	string	"Bad request"
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/v1/manifests [get]
func (mr ManifestRouter) GetManifests(c *gin.Context) error {
	gotManifests, err := mr.service.GetManifests(c)

	if err != nil {
		errMsg := "could not get manifests"
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
	}

	manifests := make([]GetManifestResponse, 0, len(gotManifests.Manifests))
	for _, m := range gotManifests.Manifests {
		manifests = append(manifests, GetManifestResponse{
			ID:          m.Manifest.ID,
			Manifest:    m.Manifest,
			ManifestJWT: m.ManifestJWT,
		})
	}

	resp := GetManifestsResponse{Manifests: manifests}
	return framework.Respond(c, resp, http.StatusOK)
}

// DeleteManifest godoc
//
//	@Summary		Delete manifests
//	@Description	Delete manifest by ID
//	@Tags			ManifestAPI
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"ID"
//	@Success		204	{string}	string	"No Content"
//	@Failure		400	{string}	string	"Bad request"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/v1/manifests/{id} [delete]
func (mr ManifestRouter) DeleteManifest(c *gin.Context) error {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "cannot delete manifest without ID parameter"
		return framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
	}

	if err := mr.service.DeleteManifest(c, model.DeleteManifestRequest{ID: *id}); err != nil {
		errMsg := fmt.Sprintf("could not delete manifest with id: %s", *id)
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}

	return framework.Respond(c, nil, http.StatusNoContent)
}

type SubmitApplicationRequest struct {
	// Contains the following properties:
	// Application  manifestsdk.CredentialApplication `json:"credential_application" validate:"required"`
	// Credentials  []interface{}                     `json:"vcs" validate:"required"`
	ApplicationJWT keyaccess.JWT `json:"applicationJwt" validate:"required"`
}

const (
	vcsJSONProperty                   = "vcs"
	verifiableCredentialsJSONProperty = "verifiableCredentials"
)

func (sar SubmitApplicationRequest) toServiceRequest() (*model.SubmitApplicationRequest, error) {
	_, token, err := util.ParseJWT(sar.ApplicationJWT)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse application JWT")
	}
	iss := token.Issuer()
	if iss == "" {
		return nil, errors.New("credential application token missing iss")
	}

	// make sure the known properties are present (Application and Credentials)

	var creds []any
	credentials, ok := token.Get(vcsJSONProperty)
	if !ok {
		logrus.Warn("could not find vc in Credential Application token, looking for `verifiableCredentials`")
		if credentials, ok = token.Get(verifiableCredentialsJSONProperty); !ok {
			return nil, errors.New("could not find vc or verifiableCredentials in Credential Application token")
		}
	}
	creds, ok = credentials.([]any)
	if !ok {
		return nil, fmt.Errorf("could not parse Credential Application token, %s is not an array", vcsJSONProperty)
	}

	// marshal known properties into their respective types
	credAppJSON, ok := token.Get(manifestsdk.CredentialApplicationJSONProperty)
	if !ok {
		return nil, errors.New("could not find credential_application in Credential Application token")
	}
	applicationTokenBytes, err := json.Marshal(credAppJSON)
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal Credential Application credAppJSON")
	}
	var application manifestsdk.CredentialApplication
	if err = json.Unmarshal(applicationTokenBytes, &application); err != nil {
		return nil, errors.Wrap(err, "could not reconstruct Credential Application")
	}

	credContainer, err := credential.NewCredentialContainerFromArray(creds)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse submitted credentials")
	}
	return &model.SubmitApplicationRequest{
		ApplicantDID:    iss,
		Application:     application,
		Credentials:     credContainer,
		ApplicationJWT:  sar.ApplicationJWT,
		ApplicationJSON: token.PrivateClaims(),
	}, nil
}

type SubmitApplicationResponse struct {
	Response manifestsdk.CredentialResponse `json:"credential_response"`
	// this is an any type to union Data Integrity and JWT style VCs
	Credentials []any         `json:"verifiableCredentials"`
	ResponseJWT keyaccess.JWT `json:"responseJwt,omitempty"`
}

// SubmitApplication godoc
//
//	@Summary		Submit application
//	@Description	Submit a credential application in response to a credential manifest. The request body is expected to
//
// be a valid JWT signed by the applicant's DID, containing two top level properties: credential_application and vcs.
//
//	@Tags			ApplicationAPI
//	@Accept			json
//	@Produce		json
//	@Param			request	body		SubmitApplicationRequest	true	"request body"
//	@Success		201		{object}	Operation					"Operation with a SubmitApplicationResponse type in the `result.response` field."
//	@Failure		400		{string}	string						"Bad request"
//	@Failure		500		{string}	string						"Internal server error"
//	@Router			/v1/manifests/applications [put]
func (mr ManifestRouter) SubmitApplication(c *gin.Context) error {
	var request SubmitApplicationRequest
	if err := framework.Decode(c.Request, &request); err != nil {
		errMsg := "invalid submit application request"
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
	}

	req, err := request.toServiceRequest()
	if err != nil {
		errMsg := "invalid submit application request"
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
	}

	op, err := mr.service.ProcessApplicationSubmission(c, *req)
	if err != nil {
		errMsg := "could not submit application"
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}

	return framework.Respond(c, routerModel(*op), http.StatusCreated)
}

type GetApplicationResponse struct {
	ID          string                            `json:"id"`
	Application manifestsdk.CredentialApplication `json:"application"`
}

// GetApplication godoc
//
//	@Summary		Get application
//	@Description	Get application by id
//	@Tags			ApplicationAPI
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"ID"
//	@Success		200	{object}	GetApplicationResponse
//	@Failure		400	{string}	string	"Bad request"
//	@Router			/v1/manifests/applications/{id} [get]
func (mr ManifestRouter) GetApplication(c *gin.Context) error {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "cannot get application without ID parameter"
		return framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
	}

	gotApplication, err := mr.service.GetApplication(c, model.GetApplicationRequest{ID: *id})
	if err != nil {
		errMsg := fmt.Sprintf("could not get application with id: %s", *id)
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
	}

	resp := GetApplicationResponse{
		ID:          gotApplication.Application.ID,
		Application: gotApplication.Application,
	}
	return framework.Respond(c, resp, http.StatusOK)
}

type GetApplicationsResponse struct {
	Applications []manifestsdk.CredentialApplication `json:"applications"`
}

// GetApplications godoc
//
//	@Summary		Get applications
//	@Description	Gets all the existing applications.
//	@Tags			ApplicationAPI
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	GetApplicationsResponse
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/v1/manifests/applications [get]
func (mr ManifestRouter) GetApplications(c *gin.Context) error {
	gotApplications, err := mr.service.GetApplications(c)
	if err != nil {
		errMsg := "could not get applications"
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}

	resp := GetApplicationsResponse{Applications: gotApplications.Applications}
	return framework.Respond(c, resp, http.StatusOK)
}

// DeleteApplication godoc
//
//	@Summary		Delete applications
//	@Description	Delete application by ID
//	@Tags			ApplicationAPI
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"ID"
//	@Success		204	{string}	string	"No Content"
//	@Failure		400	{string}	string	"Bad request"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/v1/manifests/applications/{id} [delete]
func (mr ManifestRouter) DeleteApplication(c *gin.Context) error {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "cannot delete application without ID parameter"
		return framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
	}

	if err := mr.service.DeleteApplication(c, model.DeleteApplicationRequest{ID: *id}); err != nil {
		errMsg := fmt.Sprintf("could not delete application with id: %s", *id)
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}

	return framework.Respond(c, nil, http.StatusNoContent)
}

type GetResponseResponse struct {
	Response manifestsdk.CredentialResponse `json:"credential_response"`
	// this is an interface type to union Data Integrity and JWT style VCs
	Credentials any           `json:"verifiableCredentials,omitempty"`
	ResponseJWT keyaccess.JWT `json:"responseJwt,omitempty"`
}

// GetResponse godoc
//
//	@Summary		Get response
//	@Description	Get response by id
//	@Tags			ResponseAPI
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"ID"
//	@Success		200	{object}	GetResponseResponse
//	@Failure		400	{string}	string	"Bad request"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/v1/manifests/responses/{id} [get]
func (mr ManifestRouter) GetResponse(c *gin.Context) error {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "cannot get response without ID parameter"
		return framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
	}

	gotResponse, err := mr.service.GetResponse(c, model.GetResponseRequest{ID: *id})
	if err != nil {
		errMsg := fmt.Sprintf("could not get response with id: %s", *id)
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}

	resp := GetResponseResponse{
		Response:    gotResponse.Response,
		Credentials: gotResponse.Credentials,
		ResponseJWT: gotResponse.ResponseJWT,
	}
	return framework.Respond(c, resp, http.StatusOK)
}

type GetResponsesResponse struct {
	Responses []manifestsdk.CredentialResponse `json:"responses"`
}

// GetResponses godoc
//
//	@Summary		Get responses
//	@Description	Checks for the presence of a query parameter and calls the associated filtered get method
//	@Tags			ResponseAPI
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	GetResponsesResponse
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/v1/manifests/responses [get]
func (mr ManifestRouter) GetResponses(c *gin.Context) error {
	gotResponses, err := mr.service.GetResponses(c)

	if err != nil {
		errMsg := "could not get responses"
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}

	resp := GetResponsesResponse{
		Responses: gotResponses.Responses,
	}

	return framework.Respond(c, resp, http.StatusOK)
}

// DeleteResponse godoc
//
//	@Summary		Delete responses
//	@Description	Delete response by ID
//	@Tags			ResponseAPI
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"ID"
//	@Success		200	{string}	string	"OK"
//	@Failure		400	{string}	string	"Bad request"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/v1/manifests/responses/{id} [delete]
func (mr ManifestRouter) DeleteResponse(c *gin.Context) error {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "cannot delete response without ID parameter"
		return framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
	}

	if err := mr.service.DeleteResponse(c, model.DeleteResponseRequest{ID: *id}); err != nil {
		errMsg := fmt.Sprintf("could not delete response with id: %s", *id)
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}

	return framework.Respond(c, nil, http.StatusOK)
}

type ReviewApplicationRequest struct {
	Approved bool   `json:"approved"`
	Reason   string `json:"reason"`

	// Overrides to apply to the credentials that will be created. Keys are the ID that corresponds to an
	// OutputDescriptor.ID from the manifest.
	CredentialOverrides map[string]model.CredentialOverride `json:"credential_overrides,omitempty"`
}

func (r ReviewApplicationRequest) toServiceRequest(id string) model.ReviewApplicationRequest {
	return model.ReviewApplicationRequest{
		ID:                  id,
		Approved:            r.Approved,
		Reason:              r.Reason,
		CredentialOverrides: r.CredentialOverrides,
	}
}

// ReviewApplication godoc
//
//	@Summary		Reviews an application
//	@Description	Reviewing an application either fulfills or denies the credential.
//	@Tags			ApplicationAPI
//	@Accept			json
//	@Produce		json
//	@Param			request	body		ReviewApplicationRequest	true	"request body"
//	@Success		201		{object}	SubmitApplicationResponse	"Credential Response"
//	@Failure		400		{string}	string						"Bad request"
//	@Failure		500		{string}	string						"Internal server error"
//	@Router			/v1/manifests/applications/{id}/review [put]
func (mr ManifestRouter) ReviewApplication(c *gin.Context) error {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "review application request requires id"
		return framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
	}

	var request ReviewApplicationRequest
	if err := framework.Decode(c.Request, &request); err != nil {
		errMsg := "invalid review application request"
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
	}

	applicationResponse, err := mr.service.ReviewApplication(c, request.toServiceRequest(*id))
	if err != nil {
		errMsg := "failed reviewing application"
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}
	return framework.Respond(c, SubmitApplicationResponse{
		Response:    applicationResponse.Response,
		Credentials: applicationResponse.Credentials,
		ResponseJWT: applicationResponse.ResponseJWT,
	}, http.StatusCreated)
}
