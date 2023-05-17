package router

import (
	"fmt"
	"net/http"

	credsdk "github.com/TBD54566975/ssi-sdk/credential"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"

	credmodel "github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/credential"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
)

const (
	IssuerParam  string = "issuer"
	SubjectParam string = "subject"
	SchemaParam  string = "schema"
)

type CredentialRouter struct {
	service *credential.Service
}

func NewCredentialRouter(s svcframework.Service) (*CredentialRouter, error) {
	if s == nil {
		return nil, errors.New("service cannot be nil")
	}
	credService, ok := s.(*credential.Service)
	if !ok {
		return nil, fmt.Errorf("could not create credential router with service type: %s", s.Type())
	}
	return &CredentialRouter{
		service: credService,
	}, nil
}

type CreateCredentialRequest struct {
	// The issuer id.
	Issuer string `json:"issuer" validate:"required" example:"did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"`

	// The KID used to sign the credential
	IssuerKID string `json:"issuerKid" validate:"required" example:"#z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"`

	// The subject id.
	Subject string `json:"subject" validate:"required" example:"did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"`

	// A context is optional. If not present, we'll apply default, required context values.
	Context string `json:"@context,omitempty"`

	// A schema ID is optional. If present, we'll attempt to look it up and validate the data against it.
	SchemaID string `json:"schemaId,omitempty"`

	// Claims about the subject. The keys should be predicates (e.g. "alumniOf"), and the values can be any object.
	Data map[string]any `json:"data" validate:"required" swaggertype:"object,string" example:"alumniOf:did_for_uni"`

	// Optional. Corresponds to `expirationDate` in https://www.w3.org/TR/vc-data-model/#expiration.
	Expiry string `json:"expiry" example:"2020-01-01T19:23:24Z"`

	// Whether this credential can be revoked. When true, the created VC will have the "credentialStatus"
	// property set.
	Revocable bool `json:"revocable"`

	// Whether this credential can be suspended. When true, the created VC will have the "credentialStatus"
	// property set.
	Suspendable bool `json:"suspendable"`
	// TODO(gabe) support more capabilities like signature type, format, and more.
}

func (c CreateCredentialRequest) ToServiceRequest() credential.CreateCredentialRequest {
	return credential.CreateCredentialRequest{
		Issuer:      c.Issuer,
		IssuerKID:   c.IssuerKID,
		Subject:     c.Subject,
		Context:     c.Context,
		SchemaID:    c.SchemaID,
		Data:        c.Data,
		Expiry:      c.Expiry,
		Revocable:   c.Revocable,
		Suspendable: c.Suspendable,
	}
}

type CreateCredentialResponse struct {
	// A verifiable credential conformant to the media type `application/vc+ld+json`.
	Credential *credsdk.VerifiableCredential `json:"credential,omitempty"`

	// The same verifiable credential, but using the syntax defined for the media type `application/vc+jwt`. See
	// https://w3c.github.io/vc-jwt/ for more details.
	CredentialJWT *keyaccess.JWT `json:"credentialJwt,omitempty"`
}

// CreateCredential godoc
//
// @Summary     Create Credential
// @Description Create a verifiable credential
// @Tags        CredentialAPI
// @Accept      json
// @Produce     json
// @Param       request body     CreateCredentialRequest true "request body"
// @Success     201     {object} CreateCredentialResponse
// @Failure     400     {string} string "Bad request"
// @Failure     500     {string} string "Internal server error"
// @Router      /v1/credentials [put]
func (cr CredentialRouter) CreateCredential(c *gin.Context) error {
	var request CreateCredentialRequest
	invalidCreateCredentialRequest := "invalid create credential request"
	if err := framework.Decode(c.Request, &request); err != nil {
		return framework.LoggingRespondErrWithMsg(c, err, invalidCreateCredentialRequest, http.StatusBadRequest)
	}

	if err := framework.ValidateRequest(request); err != nil {
		return framework.LoggingRespondErrWithMsg(c, err, invalidCreateCredentialRequest, http.StatusBadRequest)
	}

	req := request.ToServiceRequest()
	createCredentialResponse, err := cr.service.CreateCredential(c, req)
	if err != nil {
		errMsg := "could not create credential"
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}

	resp := CreateCredentialResponse{Credential: createCredentialResponse.Credential, CredentialJWT: createCredentialResponse.CredentialJWT}
	return framework.Respond(c, resp, http.StatusCreated)
}

type GetCredentialResponse struct {
	ID            string                        `json:"id"`
	Credential    *credsdk.VerifiableCredential `json:"credential,omitempty"`
	CredentialJWT *keyaccess.JWT                `json:"credentialJwt,omitempty"`
}

// GetCredential godoc
//
// @Summary     Get Credential
// @Description Get credential by id
// @Tags        CredentialAPI
// @Accept      json
// @Produce     json
// @Param       id  path     string true "ID"
// @Success     200 {object} GetCredentialResponse
// @Failure     400 {string} string "Bad request"
// @Failure     500 {string} string "Internal server error"
// @Router      /v1/credentials/{id} [get]
func (cr CredentialRouter) GetCredential(c *gin.Context) error {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "cannot get credential without ID parameter"
		return framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
	}

	gotCredential, err := cr.service.GetCredential(c, credential.GetCredentialRequest{ID: *id})
	if err != nil {
		errMsg := fmt.Sprintf("could not get credential with id: %s", *id)
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}

	resp := GetCredentialResponse{
		ID:            gotCredential.ID,
		Credential:    gotCredential.Credential,
		CredentialJWT: gotCredential.CredentialJWT,
	}
	return framework.Respond(c, resp, http.StatusOK)
}

type GetCredentialStatusResponse struct {
	// Whether the credential has been revoked.
	Revoked bool `json:"revoked"`
	// Whether the credential has been suspended.
	Suspended bool `json:"suspended"`
}

// GetCredentialStatus godoc
//
// @Summary     Get Credential Status
// @Description Get credential status by id
// @Tags        CredentialAPI
// @Accept      json
// @Produce     json
// @Param       id  path     string true "ID"
// @Success     200 {object} GetCredentialStatusResponse
// @Failure     400 {string} string "Bad request"
// @Failure     500 {string} string "Internal server error"
// @Router      /v1/credentials/{id}/status [get]
func (cr CredentialRouter) GetCredentialStatus(c *gin.Context) error {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "cannot get credential without ID parameter"
		return framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
	}

	getCredentialStatusResponse, err := cr.service.GetCredentialStatus(c, credential.GetCredentialStatusRequest{ID: *id})
	if err != nil {
		errMsg := fmt.Sprintf("could not get credential with id: %s", *id)
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}

	resp := GetCredentialStatusResponse{
		Revoked:   getCredentialStatusResponse.Revoked,
		Suspended: getCredentialStatusResponse.Suspended,
	}

	return framework.Respond(c, resp, http.StatusOK)
}

type GetCredentialStatusListResponse struct {
	ID string `json:"id"`
	// Credential where type includes "VerifiableCredential" and "StatusList2021".
	Credential *credsdk.VerifiableCredential `json:"credential,omitempty"`

	// The JWT signed with the associated issuer's private key.
	CredentialJWT *keyaccess.JWT `json:"credentialJwt,omitempty"`
}

// GetCredentialStatusList godoc
//
// @Summary     Get Credential Status List
// @Description Get credential status list by id.
// @Tags        CredentialAPI
// @Accept      json
// @Produce     json
// @Param       id  path     string true "ID"
// @Success     200 {object} GetCredentialStatusListResponse
// @Failure     400 {string} string "Bad request"
// @Failure     500 {string} string "Internal server error"
// @Router      /v1/credentials/status/{id} [get]
func (cr CredentialRouter) GetCredentialStatusList(c *gin.Context) error {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "cannot get credential without ID parameter"
		return framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
	}

	gotCredential, err := cr.service.GetCredentialStatusList(c, credential.GetCredentialStatusListRequest{ID: *id})
	if err != nil {
		errMsg := fmt.Sprintf("could not get credential status list with id: %s", *id)
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}

	resp := GetCredentialStatusListResponse{
		ID:            gotCredential.ID,
		Credential:    gotCredential.Credential,
		CredentialJWT: gotCredential.CredentialJWT,
	}

	return framework.Respond(c, resp, http.StatusOK)
}

type UpdateCredentialStatusRequest struct {
	// The new revoked status of this credential. The status will be saved in the encodedList of the StatusList2021
	// credential associated with this VC.
	Revoked   bool `json:"revoked,omitempty"`
	Suspended bool `json:"suspended,omitempty"`
}

func (c UpdateCredentialStatusRequest) ToServiceRequest(id string) credential.UpdateCredentialStatusRequest {
	return credential.UpdateCredentialStatusRequest{
		ID:        id,
		Revoked:   c.Revoked,
		Suspended: c.Suspended,
	}
}

type UpdateCredentialStatusResponse struct {
	// The updated status of this credential.
	Revoked   bool `json:"revoked"`
	Suspended bool `json:"suspended"`
}

// UpdateCredentialStatus godoc
//
// @Summary     Update Credential Status
// @Description Update a credential's status
// @Tags        CredentialAPI
// @Accept      json
// @Produce     json
// @Param       request body     UpdateCredentialStatusRequest true "request body"
// @Success     201     {object} UpdateCredentialStatusResponse
// @Failure     400     {string} string "Bad request"
// @Failure     500     {string} string "Internal server error"
// @Router      /v1/credentials/{id}/status [put]
func (cr CredentialRouter) UpdateCredentialStatus(c *gin.Context) error {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "cannot get credential without ID parameter"
		return framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
	}

	var request UpdateCredentialStatusRequest
	invalidCreateCredentialRequest := "invalid update credential request"
	if err := framework.Decode(c.Request, &request); err != nil {
		errMsg := invalidCreateCredentialRequest
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
	}

	if err := framework.ValidateRequest(request); err != nil {
		errMsg := invalidCreateCredentialRequest
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
	}

	req := request.ToServiceRequest(*id)
	gotCredential, err := cr.service.UpdateCredentialStatus(c, req)

	if err != nil {
		errMsg := fmt.Sprintf("could not update credential with id: %s", req.ID)
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}

	resp := UpdateCredentialStatusResponse{
		Revoked:   gotCredential.Revoked,
		Suspended: gotCredential.Suspended,
	}

	return framework.Respond(c, resp, http.StatusOK)
}

type VerifyCredentialRequest struct {
	// A credential secured via data integrity. Must have the "proof" property set.
	DataIntegrityCredential *credsdk.VerifiableCredential `json:"credential,omitempty"`

	// A JWT that encodes a credential.
	CredentialJWT *keyaccess.JWT `json:"credentialJwt,omitempty"`
}

func (vcr VerifyCredentialRequest) IsValid() bool {
	return (vcr.DataIntegrityCredential != nil && vcr.CredentialJWT == nil) ||
		(vcr.DataIntegrityCredential == nil && vcr.CredentialJWT != nil)
}

type VerifyCredentialResponse struct {
	// Whether the credential was verified.
	Verified bool `json:"verified"`

	// The reason why this credential couldn't be verified.
	Reason string `json:"reason,omitempty"`
}

// VerifyCredential godoc
//
// @Summary     Verify Credential
// @Description Verify a given credential by its id. The system does the following levels of verification:
// @Description 1. Makes sure the credential has a valid signature
// @Description 2. Makes sure the credential has is not expired
// @Description 3. Makes sure the credential complies with the VC Data Model
// @Description 4. If the credential has a schema, makes sure its data complies with the schema
// @Tags        CredentialAPI
// @Accept      json
// @Produce     json
// @Param       request body     VerifyCredentialRequest true "request body"
// @Success     200     {object} VerifyCredentialResponse
// @Failure     400     {string} string "Bad request"
// @Failure     500     {string} string "Internal server error"
// @Router      /v1/credentials/verification [put]
func (cr CredentialRouter) VerifyCredential(c *gin.Context) error {
	var request VerifyCredentialRequest
	if err := framework.Decode(c.Request, &request); err != nil {
		errMsg := "invalid verify credential request"
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
	}

	if !request.IsValid() {
		errMsg := "request must contain either a Data Integrity Credential or a JWT Credential"
		return framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
	}

	verificationResult, err := cr.service.VerifyCredential(c, credential.VerifyCredentialRequest{
		DataIntegrityCredential: request.DataIntegrityCredential,
		CredentialJWT:           request.CredentialJWT,
	})
	if err != nil {
		errMsg := "could not verify credential"
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}

	resp := VerifyCredentialResponse{Verified: verificationResult.Verified, Reason: verificationResult.Reason}
	return framework.Respond(c, resp, http.StatusOK)
}

type GetCredentialsResponse struct {
	// Array of credential containers.
	Credentials []credmodel.Container `json:"credentials,omitempty"`
}

// GetCredentials godoc
//
// @Summary     Get Credentials
// @Description Checks for the presence of a query parameter and calls the associated filtered get method. Only one parameter is allowed to be specified.
// @Tags        CredentialAPI
// @Accept      json
// @Produce     json
// @Param       issuer  query    string false "The issuer id" example(did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp)
// @Param       schema  query    string false "The credentialSchema.id value to filter by"
// @Param       subject query    string false "The credentialSubject.id value to filter by"
// @Success     200     {object} GetCredentialsResponse
// @Failure     400     {string} string "Bad request"
// @Failure     500     {string} string "Internal server error"
// @Router      /v1/credentials [get]
func (cr CredentialRouter) GetCredentials(c *gin.Context) error {
	issuer := framework.GetQueryValue(c, IssuerParam)
	schema := framework.GetQueryValue(c, SchemaParam)
	subject := framework.GetQueryValue(c, SubjectParam)

	errMsg := "must use one of the following query parameters: issuer, subject, schema"
	err := framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)

	// check if there are multiple parameters set, which is not allowed
	if (issuer != nil && subject != nil) || (issuer != nil && schema != nil) || (subject != nil && schema != nil) {
		return err
	}

	if issuer != nil {
		return cr.getCredentialsByIssuer(c, *issuer)
	}
	if subject != nil {
		return cr.getCredentialsBySubject(c, *subject)
	}
	if schema != nil {
		return cr.getCredentialsBySchema(c, *schema)
	}
	return err
}

func (cr CredentialRouter) getCredentialsByIssuer(c *gin.Context, issuer string) error {
	gotCredentials, err := cr.service.GetCredentialsByIssuer(c, credential.GetCredentialByIssuerRequest{Issuer: issuer})
	if err != nil {
		errMsg := fmt.Sprintf("could not get credentials for issuer: %s", util.SanitizeLog(issuer))
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}

	resp := GetCredentialsResponse{Credentials: gotCredentials.Credentials}
	return framework.Respond(c, resp, http.StatusOK)
}

func (cr CredentialRouter) getCredentialsBySubject(c *gin.Context, subject string) error {
	gotCredentials, err := cr.service.GetCredentialsBySubject(c, credential.GetCredentialBySubjectRequest{Subject: subject})
	if err != nil {
		errMsg := fmt.Sprintf("could not get credentials for subject: %s", util.SanitizeLog(subject))
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}

	resp := GetCredentialsResponse{Credentials: gotCredentials.Credentials}
	return framework.Respond(c, resp, http.StatusOK)
}

func (cr CredentialRouter) getCredentialsBySchema(c *gin.Context, schema string) error {
	gotCredentials, err := cr.service.GetCredentialsBySchema(c, credential.GetCredentialBySchemaRequest{Schema: schema})
	if err != nil {
		errMsg := fmt.Sprintf("could not get credentials for schema: %s", util.SanitizeLog(schema))
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}

	resp := GetCredentialsResponse{Credentials: gotCredentials.Credentials}
	return framework.Respond(c, resp, http.StatusOK)
}

// DeleteCredential godoc
//
// @Summary     Delete Credentials
// @Description Delete credential by ID
// @Tags        CredentialAPI
// @Accept      json
// @Produce     json
// @Param       id  path     string true "ID"
// @Success     204 {string} string "No Content"
// @Failure     400 {string} string "Bad request"
// @Failure     500 {string} string "Internal server error"
// @Router      /v1/credentials/{id} [delete]
func (cr CredentialRouter) DeleteCredential(c *gin.Context) error {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "cannot delete credential without ID parameter"
		return framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
	}

	if err := cr.service.DeleteCredential(c, credential.DeleteCredentialRequest{ID: *id}); err != nil {
		errMsg := fmt.Sprintf("could not delete credential with id: %s", *id)
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}

	return framework.Respond(c, nil, http.StatusNoContent)
}
