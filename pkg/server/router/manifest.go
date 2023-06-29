package router

import (
	"fmt"
	"net/http"
	"time"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	manifestsdk "github.com/TBD54566975/ssi-sdk/credential/manifest"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/gin-gonic/gin"
	"github.com/goccy/go-json"
	"github.com/tbd54566975/ssi-service/pkg/service/common"
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
	return &ManifestRouter{
		service: manifestService,
	}, nil
}

// CreateManifestRequest is the request body for creating a manifest, which populates all remaining fields
// and builds a well-formed manifest object.
type CreateManifestRequest struct {
	// Summarizing title for the Manifest in question.
	// Optional.
	Name *string `json:"name,omitempty"`

	// Explains what the Manifest in question is generally offering in exchange for meeting its requirements.
	// Optional.
	Description *string `json:"description,omitempty"`

	// DID that identifies who the issuer of the credential(s) will be.
	// Required.
	IssuerDID string `json:"issuerDid" validate:"required"`

	// The KID of the private key that will be used when signing issued credentials.
	// Required.
	IssuerKID string `json:"issuerKid" validate:"required"`

	// Human-readable name the Issuer wishes to be recognized by.
	// Optional.
	IssuerName *string `json:"issuerName,omitempty"`

	// Formats that the issuer can support when issuing the credential. At least one needs to be set. We currently only
	// support `jwt_vc` for issuance. See https://identity.foundation/claim-format-registry/#registry for the definition.
	// TODO: support different claim formats https://github.com/TBD54566975/ssi-service/issues/96
	ClaimFormat *exchange.ClaimFormat `json:"format" validate:"required,dive"`

	// Array of objects as defined in https://identity.foundation/credential-manifest/#output-descriptor.
	OutputDescriptors []manifestsdk.OutputDescriptor `json:"outputDescriptors" validate:"required,dive"`

	// Describes what proofs are required in order to issue this credential. When present, only `id` or `value` may be
	// populated, but not both.
	// Optional.
	*model.PresentationDefinitionRef
}

func (c CreateManifestRequest) ToServiceRequest() model.CreateManifestRequest {
	verificationMethodID := did.FullyQualifiedVerificationMethodID(c.IssuerDID, c.IssuerKID)
	return model.CreateManifestRequest{
		Name:                               c.Name,
		Description:                        c.Description,
		IssuerDID:                          c.IssuerDID,
		FullyQualifiedVerificationMethodID: verificationMethodID,
		IssuerName:                         c.IssuerName,
		OutputDescriptors:                  c.OutputDescriptors,
		ClaimFormat:                        c.ClaimFormat,
		PresentationDefinitionRef:          c.PresentationDefinitionRef,
	}
}

type CreateManifestResponse struct {
	Manifest manifestsdk.CredentialManifest `json:"credential_manifest"`
}

// CreateManifest godoc
//
//	@Summary		Create manifest
//	@Description	Create manifest. Most fields map to the definitions from https://identity.foundation/credential-manifest/#general-composition.
//	@Tags			ManifestAPI
//	@Accept			json
//	@Produce		json
//	@Param			request	body		CreateManifestRequest	true	"request body"
//	@Success		201		{object}	CreateManifestResponse
//	@Failure		400		{string}	string	"Bad request"
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/v1/manifests [put]
func (mr ManifestRouter) CreateManifest(c *gin.Context) {
	var request CreateManifestRequest
	if err := framework.Decode(c.Request, &request); err != nil {
		errMsg := "invalid create manifest request"
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
		return
	}

	if err := framework.ValidateRequest(request); err != nil {
		errMsg := "invalid create manifest request"
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
		return
	}

	req := request.ToServiceRequest()
	createManifestResponse, err := mr.service.CreateManifest(c, req)
	if err != nil {
		errMsg := "could not create manifest"
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}

	resp := CreateManifestResponse{Manifest: createManifestResponse.Manifest}
	framework.Respond(c, resp, http.StatusCreated)
}

type ListManifestResponse struct {
	ID       string                         `json:"id"`
	Manifest manifestsdk.CredentialManifest `json:"credential_manifest"`
}

// GetManifest godoc
//
//	@Summary		Get manifest
//	@Description	Get a credential manifest by its id
//	@Tags			ManifestAPI
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"ID"
//	@Success		200	{object}	ListManifestResponse
//	@Failure		400	{string}	string	"Bad request"
//	@Router			/v1/manifests/{id} [get]
func (mr ManifestRouter) GetManifest(c *gin.Context) {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "cannot get manifest without ID parameter"
		framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
		return
	}

	gotManifest, err := mr.service.GetManifest(c, model.GetManifestRequest{ID: *id})
	if err != nil {
		errMsg := fmt.Sprintf("could not get manifest with id: %s", *id)
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
		return
	}

	resp := ListManifestResponse{
		ID:       gotManifest.Manifest.ID,
		Manifest: gotManifest.Manifest,
	}
	framework.Respond(c, resp, http.StatusOK)
}

type ListManifestsResponse struct {
	Manifests []ListManifestResponse `json:"manifests"`
}

// ListManifests godoc
//
//	@Summary		List manifests
//	@Description	Checks for the presence of a query parameter and calls the associated filtered get method
//	@Tags			ManifestAPI
//	@Accept			json
//	@Produce		json
//	@Param			issuer	query		string	false	"string issuer"
//	@Param			schema	query		string	false	"string schema"
//	@Param			subject	query		string	false	"string subject"
//	@Success		200		{object}	ListManifestsResponse
//	@Failure		400		{string}	string	"Bad request"
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/v1/manifests [get]
func (mr ManifestRouter) ListManifests(c *gin.Context) {
	gotManifests, err := mr.service.ListManifests(c)
	if err != nil {
		errMsg := "could not list manifests"
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
		return
	}

	manifests := make([]ListManifestResponse, 0, len(gotManifests.Manifests))
	for _, m := range gotManifests.Manifests {
		manifests = append(manifests, ListManifestResponse{
			ID:       m.Manifest.ID,
			Manifest: m.Manifest,
		})
	}

	resp := ListManifestsResponse{Manifests: manifests}
	framework.Respond(c, resp, http.StatusOK)
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
func (mr ManifestRouter) DeleteManifest(c *gin.Context) {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "cannot delete manifest without ID parameter"
		framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
		return
	}

	if err := mr.service.DeleteManifest(c, model.DeleteManifestRequest{ID: *id}); err != nil {
		errMsg := fmt.Sprintf("could not delete manifest with id: %s", *id)
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}

	framework.Respond(c, nil, http.StatusNoContent)
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
	Credentials []any         `json:"verifiableCredentials,omitempty"`
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
func (mr ManifestRouter) SubmitApplication(c *gin.Context) {
	var request SubmitApplicationRequest
	if err := framework.Decode(c.Request, &request); err != nil {
		errMsg := "invalid submit application request"
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
		return
	}

	req, err := request.toServiceRequest()
	if err != nil {
		errMsg := "invalid submit application request"
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
		return
	}

	op, err := mr.service.ProcessApplicationSubmission(c, *req)
	if err != nil {
		errMsg := "could not submit application"
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}

	framework.Respond(c, routerModel(*op), http.StatusCreated)
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
func (mr ManifestRouter) GetApplication(c *gin.Context) {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "cannot get application without ID parameter"
		framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
		return
	}

	gotApplication, err := mr.service.GetApplication(c, model.GetApplicationRequest{ID: *id})
	if err != nil {
		errMsg := fmt.Sprintf("could not get application with id: %s", *id)
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
		return
	}

	resp := GetApplicationResponse{
		ID:          gotApplication.Application.ID,
		Application: gotApplication.Application,
	}
	framework.Respond(c, resp, http.StatusOK)
}

type ListApplicationsResponse struct {
	Applications []manifestsdk.CredentialApplication `json:"applications"`
}

// ListApplications godoc
//
//	@Summary		List applications
//	@Description	List all the existing applications.
//	@Tags			ApplicationAPI
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	ListApplicationsResponse
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/v1/manifests/applications [get]
func (mr ManifestRouter) ListApplications(c *gin.Context) {
	gotApplications, err := mr.service.ListApplications(c)
	if err != nil {
		errMsg := "could not list applications"
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}

	resp := ListApplicationsResponse{Applications: gotApplications.Applications}
	framework.Respond(c, resp, http.StatusOK)
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
func (mr ManifestRouter) DeleteApplication(c *gin.Context) {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "cannot delete application without ID parameter"
		framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
		return
	}

	if err := mr.service.DeleteApplication(c, model.DeleteApplicationRequest{ID: *id}); err != nil {
		errMsg := fmt.Sprintf("could not delete application with id: %s", *id)
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}

	framework.Respond(c, nil, http.StatusNoContent)
}

type GetResponseResponse struct {
	Response manifestsdk.CredentialResponse `json:"credential_response"`
	// this is an interface type to union Data Integrity and JWT style VCs
	Credentials any           `json:"verifiableCredentials,omitempty"`
	ResponseJWT keyaccess.JWT `json:"responseJwt"`
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
func (mr ManifestRouter) GetResponse(c *gin.Context) {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "cannot get response without ID parameter"
		framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
		return
	}

	gotResponse, err := mr.service.GetResponse(c, model.GetResponseRequest{ID: *id})
	if err != nil {
		errMsg := fmt.Sprintf("could not get response with id: %s", *id)
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}

	resp := GetResponseResponse{
		Response:    gotResponse.Response,
		Credentials: gotResponse.Credentials,
		ResponseJWT: gotResponse.ResponseJWT,
	}
	framework.Respond(c, resp, http.StatusOK)
}

type ListResponsesResponse struct {
	Responses []manifestsdk.CredentialResponse `json:"responses"`
}

// ListResponses godoc
//
//	@Summary		List responses
//	@Description	Lists all responses
//	@Tags			ResponseAPI
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	ListResponsesResponse
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/v1/manifests/responses [get]
func (mr ManifestRouter) ListResponses(c *gin.Context) {
	gotResponses, err := mr.service.ListResponses(c)
	if err != nil {
		errMsg := "could not list responses"
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}

	resp := ListResponsesResponse{Responses: gotResponses.Responses}
	framework.Respond(c, resp, http.StatusOK)
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
func (mr ManifestRouter) DeleteResponse(c *gin.Context) {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "cannot delete response without ID parameter"
		framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
		return
	}

	if err := mr.service.DeleteResponse(c, model.DeleteResponseRequest{ID: *id}); err != nil {
		errMsg := fmt.Sprintf("could not delete response with id: %s", *id)
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}

	framework.Respond(c, nil, http.StatusOK)
}

type ReviewApplicationRequest struct {
	Approved bool   `json:"approved"`
	Reason   string `json:"reason"`

	// Overrides to apply to the credentials that will be created. Keys are the ID that corresponds to an
	// OutputDescriptor.ID from the manifest.
	CredentialOverrides map[string]model.CredentialOverride `json:"credentialOverrides,omitempty"`
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
func (mr ManifestRouter) ReviewApplication(c *gin.Context) {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "review application request requires id"
		framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
		return
	}

	var request ReviewApplicationRequest
	if err := framework.Decode(c.Request, &request); err != nil {
		errMsg := "invalid review application request"
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
		return
	}

	applicationResponse, err := mr.service.ReviewApplication(c, request.toServiceRequest(*id))
	if err != nil {
		errMsg := "failed reviewing application"
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}
	framework.Respond(c, SubmitApplicationResponse{
		Response:    applicationResponse.Response,
		Credentials: applicationResponse.Credentials,
		ResponseJWT: applicationResponse.ResponseJWT,
	}, http.StatusCreated)
}

type CreateManifestRequestRequest struct {
	*CommonCreateRequestRequest

	// ID of the credential manifest to use for this request.
	CredentialManifestID string `json:"credentialManifestId" validate:"required"`
}

type CreateManifestRequestResponse struct {
	Request *model.Request `json:"manifestRequest"`
}

// CreateRequest godoc
//
//	@Summary		Create Manifest Request Request
//	@Description	Create manifest request from an existing credential manifest.
//	@Tags			ManifestAPI
//	@Accept			json
//	@Produce		json
//	@Param			request	body		CreateManifestRequestRequest	true	"request body"
//	@Success		201		{object}	CreateManifestRequestResponse
//	@Failure		400		{string}	string	"Bad request"
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/v1/manifests/requests [put]
func (mr ManifestRouter) CreateRequest(c *gin.Context) {
	var request CreateManifestRequestRequest
	errMsg := "Invalid Manifest Request Request"
	if err := framework.Decode(c.Request, &request); err != nil {
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
		return
	}
	if err := framework.ValidateRequest(request); err != nil {
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
		return
	}

	req, err := mr.serviceRequestFromRequest(request)
	if err != nil {
		framework.LoggingRespondError(c, err, http.StatusBadRequest)
		return
	}

	doc, err := mr.service.CreateRequest(c, model.CreateRequestRequest{ManifestRequest: *req})
	if err != nil {
		framework.LoggingRespondErrWithMsg(c, err, "signing and storing", http.StatusInternalServerError)
		return
	}
	framework.Respond(c, CreateManifestRequestResponse{Request: doc}, http.StatusCreated)
}

func (mr ManifestRouter) serviceRequestFromRequest(request CreateManifestRequestRequest) (*model.Request, error) {
	req, err := commonRequestToServiceRequest(request.CommonCreateRequestRequest)
	if err != nil {
		return nil, err
	}

	return &model.Request{
		Request:    *req,
		ManifestID: request.CredentialManifestID,
	}, nil
}

type ListManifestRequestsResponse struct {
	// The manifest requests matching the query.
	Requests []model.Request `json:"manifestRequests"`
}

// ListRequests godoc
//
//	@Summary		List Credential Manifest Requests
//	@Description	Lists all the existing credential manifest requests
//	@Tags			ManifestAPI
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	ListManifestRequestsResponse
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/v1/manifests/requests [get]
func (mr ManifestRouter) ListRequests(c *gin.Context) {
	svcResponse, err := mr.service.ListRequests(c)

	if err != nil {
		errMsg := "could not get requests"
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}
	resp := ListManifestRequestsResponse{
		Requests: svcResponse.ManifestRequests,
	}
	framework.Respond(c, resp, http.StatusOK)
}

type GetManifestRequestResponse struct {
	Request *model.Request `json:"manifestRequest"`
}

// GetRequest godoc
//
//	@Summary		Get Manifest Request
//	@Description	Get a manifest request by its ID
//	@Tags			ManifestAPI
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"ID"
//	@Success		200	{object}	GetManifestRequestResponse
//	@Failure		400	{string}	string	"Bad request"
//	@Router			/v1/manifests/requests/{id} [get]
func (mr ManifestRouter) GetRequest(c *gin.Context) {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		framework.LoggingRespondErrMsg(c, "cannot get manifest request without an ID", http.StatusBadRequest)
		return
	}

	request, err := mr.service.GetRequest(c, &model.GetRequestRequest{ID: *id})
	if err != nil {
		framework.LoggingRespondErrWithMsg(c, err, "getting manifest request", http.StatusInternalServerError)
		return
	}
	framework.Respond(c, GetManifestRequestResponse{Request: request}, http.StatusOK)
}

// DeleteRequest godoc
//
//	@Summary		Delete Manifest Request
//	@Description	Delete a manifest request by its ID
//	@Tags			ManifestAPI
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"ID"
//	@Success		204	{string}	string	"No Content"
//	@Failure		400	{string}	string	"Bad request"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/v1/manifests/requests/{id} [delete]
func (mr ManifestRouter) DeleteRequest(c *gin.Context) {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "cannot delete a manifest request without an ID parameter"
		framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
		return
	}

	if err := mr.service.DeleteRequest(c, model.DeleteRequestRequest{ID: *id}); err != nil {
		errMsg := fmt.Sprintf("could not delete manifest request with id: %s", *id)
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}

	framework.Respond(c, nil, http.StatusNoContent)
}

func commonRequestToServiceRequest(request *CommonCreateRequestRequest) (*common.Request, error) {
	req := &common.Request{
		Audience:  request.Audience,
		IssuerDID: request.IssuerDID,
		IssuerKID: request.IssuerKID,
	}
	if request.Expiration != "" {
		expiration, err := time.Parse(time.RFC3339, request.Expiration)
		if err != nil {
			return nil, err
		}
		req.Expiration = &expiration
	}
	return req, nil
}
