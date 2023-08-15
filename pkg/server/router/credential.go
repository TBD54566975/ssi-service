package router

import (
	"fmt"
	"net/http"

	credsdk "github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	credmodel "github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	"github.com/tbd54566975/ssi-service/pkg/server/pagination"
	"github.com/tbd54566975/ssi-service/pkg/service/credential"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
	"go.einride.tech/aip/filtering"
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
	return &CredentialRouter{service: credService}, nil
}

type BatchCreateCredentialsRequest struct {
	// Required. The list of create credential requests. Cannot be more than {{.Services.CredentialConfig.BatchCreateMaxItems}} items.
	Requests []CreateCredentialRequest `json:"requests" maxItems:"1000" validate:"required,dive"`
}

func (r BatchCreateCredentialsRequest) toServiceRequest() credential.BatchCreateCredentialsRequest {
	var req credential.BatchCreateCredentialsRequest
	for _, routerReq := range r.Requests {
		req.Requests = append(req.Requests, routerReq.toServiceRequest())
	}
	return req
}

type BatchCreateCredentialsResponse struct {
	// The credentials created.
	Credentials []credmodel.Container `json:"credentials"`
}

// BatchCreateCredentials godoc
//
//	@Summary		Batch create Credentials
//	@Description	Create a batch of Verifiable Credentials.
//	@Tags			Credentials
//	@Accept			json
//	@Produce		json
//	@Param			request	body		BatchCreateCredentialsRequest	true	"The batch requests"
//	@Success		201		{object}	BatchCreateCredentialsResponse
//	@Failure		400		{string}	string	"Bad request"
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/v1/credentials/batch [put]
func (cr CredentialRouter) BatchCreateCredentials(c *gin.Context) {
	invalidCreateCredentialRequest := "invalid batch create credential request"
	var batchRequest BatchCreateCredentialsRequest
	if err := framework.Decode(c.Request, &batchRequest); err != nil {
		framework.LoggingRespondErrWithMsg(c, err, invalidCreateCredentialRequest, http.StatusBadRequest)
		return
	}

	batchCreateMaxItems := cr.service.Config().BatchCreateMaxItems
	if len(batchRequest.Requests) > batchCreateMaxItems {
		framework.LoggingRespondErrMsg(c, fmt.Sprintf("max number of requests is %d", batchCreateMaxItems), http.StatusBadRequest)
		return
	}

	req := batchRequest.toServiceRequest()
	batchCreateCredentialsResponse, err := cr.service.BatchCreateCredentials(c, req)
	if err != nil {
		errMsg := "could not create credentials"
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}

	var resp BatchCreateCredentialsResponse
	for _, cred := range batchCreateCredentialsResponse.Credentials {
		resp.Credentials = append(resp.Credentials, cred)
	}
	framework.Respond(c, resp, http.StatusCreated)
}

type CreateCredentialRequest struct {
	// The issuer id.
	Issuer string `json:"issuer" validate:"required" example:"did:key:z6MkkZDjunoN4gyPMx5TSy7Mfzw22D2RZQZUcx46bii53Ex3"`

	// The id of the verificationMethod (see https://www.w3.org/TR/did-core/#verification-methods) who's privateKey is
	// stored in ssi-service. The verificationMethod must be part of the did document associated with `issuer`.
	// The private key associated with the verificationMethod's publicKey will be used to sign the credential.
	VerificationMethodID string `json:"verificationMethodId" validate:"required" example:"did:key:z6MkkZDjunoN4gyPMx5TSy7Mfzw22D2RZQZUcx46bii53Ex3#z6MkkZDjunoN4gyPMx5TSy7Mfzw22D2RZQZUcx46bii53Ex3"`

	// The subject id.
	Subject string `json:"subject" validate:"required" example:"did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"`

	// A context is optional. If not present, we'll apply default, required context values.
	Context string `json:"@context,omitempty" example:""`

	// A schema ID is optional. If present, we'll attempt to look it up and validate the data against it.
	SchemaID string `json:"schemaId,omitempty" example:"30e3f9b7-0528-4f6f-8aac-b74c8843187a"`

	// Claims about the subject. The keys should be predicates (e.g. "alumniOf"), and the values can be any object.
	Data map[string]any `json:"data" validate:"required" swaggertype:"object,string" example:"alumniOf:did_for_uni"`

	// Optional. Corresponds to `expirationDate` in https://www.w3.org/TR/vc-data-model/#expiration.
	Expiry string `json:"expiry,omitempty" example:"2029-01-01T19:23:24Z"`

	// Whether this credential can be revoked. When true, the created VC will have the "credentialStatus"
	// property set.
	Revocable bool `json:"revocable,omitempty" example:"true"`

	// Whether this credential can be suspended. When true, the created VC will have the "credentialStatus"
	// property set.
	Suspendable bool `json:"suspendable,omitempty" example:"false"`

	// Optional. Corresponds to `evidence` in https://www.w3.org/TR/vc-data-model-2.0/#evidence
	Evidence []any `json:"evidence" example:"[{\"id\":\"https://example.edu/evidence/f2aeec97-fc0d-42bf-8ca7-0548192d4231\",\"type\":[\"DocumentVerification\"]}]"`
	// TODO(gabe) support more capabilities like signature type, format, and more.
}

func (c CreateCredentialRequest) toServiceRequest() credential.CreateCredentialRequest {
	verificationMethodID := did.FullyQualifiedVerificationMethodID(c.Issuer, c.VerificationMethodID)
	return credential.CreateCredentialRequest{
		Issuer:                             c.Issuer,
		FullyQualifiedVerificationMethodID: verificationMethodID,
		Subject:                            c.Subject,
		Context:                            c.Context,
		SchemaID:                           c.SchemaID,
		Data:                               c.Data,
		Expiry:                             c.Expiry,
		Revocable:                          c.Revocable,
		Suspendable:                        c.Suspendable,
		Evidence:                           c.Evidence,
	}
}

type CreateCredentialResponse struct {
	credmodel.Container
}

// CreateCredential godoc
//
//	@Summary		Create a Verifiable Credential
//	@Description	Create a Verifiable Credential
//	@Tags			Credentials
//	@Accept			json
//	@Produce		json
//	@Param			request	body		CreateCredentialRequest	true	"request body"
//	@Success		201		{object}	CreateCredentialResponse
//	@Failure		400		{string}	string	"Bad request"
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/v1/credentials [put]
func (cr CredentialRouter) CreateCredential(c *gin.Context) {
	invalidCreateCredentialRequest := "invalid create credential request"
	var request CreateCredentialRequest
	if err := framework.Decode(c.Request, &request); err != nil {
		framework.LoggingRespondErrWithMsg(c, err, invalidCreateCredentialRequest, http.StatusBadRequest)
		return
	}

	if err := framework.ValidateRequest(request); err != nil {
		framework.LoggingRespondErrWithMsg(c, err, invalidCreateCredentialRequest, http.StatusBadRequest)
		return
	}

	req := request.toServiceRequest()
	createCredentialResponse, err := cr.service.CreateCredential(c, req)
	if err != nil {
		errMsg := "could not create credential"
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}

	resp := CreateCredentialResponse{Container: createCredentialResponse.Container}
	framework.Respond(c, resp, http.StatusCreated)
}

type GetCredentialResponse struct {
	// The `id` of this credential within SSI-Service. Same as the `id` passed in the query parameter.
	ID string `json:"id"`
	credmodel.Container
}

// GetCredential godoc
//
//	@Summary		Get a Verifiable Credential
//	@Description	Get a Verifiable Credential by its ID
//	@Tags			Credentials
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"ID of the credential within SSI-Service. Must be a UUID."
//	@Success		200	{object}	GetCredentialResponse
//	@Failure		400	{string}	string	"Bad request"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/v1/credentials/{id} [get]
func (cr CredentialRouter) GetCredential(c *gin.Context) {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "cannot get credential without ID parameter"
		framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
		return
	}

	gotCredential, err := cr.service.GetCredential(c, credential.GetCredentialRequest{ID: *id})
	if err != nil {
		errMsg := fmt.Sprintf("could not get credential with id: %s", *id)
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}

	resp := GetCredentialResponse{
		ID:        *id,
		Container: gotCredential.Container,
	}
	framework.Respond(c, resp, http.StatusOK)
}

type GetCredentialStatusResponse struct {
	// Whether the credential has been revoked.
	Revoked bool `json:"revoked"`
	// Whether the credential has been suspended.
	Suspended bool `json:"suspended"`
}

// GetCredentialStatus godoc
//
//	@Summary		Get a Verifiable Credential's status
//	@Description	Get a Verifiable Credential's status by the credential's ID
//	@Tags			Credentials
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"ID"
//	@Success		200	{object}	GetCredentialStatusResponse
//	@Failure		400	{string}	string	"Bad request"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/v1/credentials/{id}/status [get]
func (cr CredentialRouter) GetCredentialStatus(c *gin.Context) {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "cannot get credential without ID parameter"
		framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
		return
	}

	getCredentialStatusResponse, err := cr.service.GetCredentialStatus(c, credential.GetCredentialStatusRequest{ID: *id})
	if err != nil {
		errMsg := fmt.Sprintf("could not get credential with id: %s", *id)
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}

	resp := GetCredentialStatusResponse{
		Revoked:   getCredentialStatusResponse.Revoked,
		Suspended: getCredentialStatusResponse.Suspended,
	}

	framework.Respond(c, resp, http.StatusOK)
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
//	@Summary		Get a Credential Status List
//	@Description	Get a credential status list by its ID
//	@Tags			Credentials
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"ID"
//	@Success		200	{object}	GetCredentialStatusListResponse
//	@Failure		400	{string}	string	"Bad request"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/v1/credentials/status/{id} [get]
func (cr CredentialRouter) GetCredentialStatusList(c *gin.Context) {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "cannot get credential without ID parameter"
		framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
		return
	}

	gotCredential, err := cr.service.GetCredentialStatusList(c, credential.GetCredentialStatusListRequest{ID: *id})
	if err != nil {
		errMsg := fmt.Sprintf("could not get credential status list with id: %s", *id)
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}

	resp := GetCredentialStatusListResponse{
		ID:            gotCredential.ID,
		Credential:    gotCredential.Credential,
		CredentialJWT: gotCredential.CredentialJWT,
	}

	framework.Respond(c, resp, http.StatusOK)
}

type UpdateCredentialStatusRequest struct {
	// The new revoked status of this credential. The status will be saved in the encodedList of the StatusList2021
	// credential associated with this VC.
	Revoked   bool `json:"revoked,omitempty"`
	Suspended bool `json:"suspended,omitempty"`
}

func (c UpdateCredentialStatusRequest) toServiceRequest(id string) credential.UpdateCredentialStatusRequest {
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

type SingleUpdateCredentialStatusRequest struct {
	// ID of the credential who's status should be updated.
	ID string `json:"id"`
	UpdateCredentialStatusRequest
}

type BatchUpdateCredentialStatusRequest struct {
	// Required. The list of update credential requests. Cannot be more than the config value in `services.credentials.batch_update_status_max_items`.
	Requests []SingleUpdateCredentialStatusRequest `json:"requests" maxItems:"100" validate:"required,dive"`
}

func (r BatchUpdateCredentialStatusRequest) toServiceRequest() *credential.BatchUpdateCredentialStatusRequest {
	var req credential.BatchUpdateCredentialStatusRequest
	for _, routerReq := range r.Requests {
		serviceReq := routerReq.toServiceRequest(routerReq.ID)
		req.Requests = append(req.Requests, serviceReq)
	}
	return &req
}

type BatchUpdateCredentialStatusResponse struct {
	CredentialStatuses []credential.Status `json:"credentialStatuses"`
}

// BatchUpdateCredentialStatus godoc
//
//	@Summary		Batch Update a Verifiable Credential's status
//	@Description	Updates the status all a batch of Verifiable Credentials.
//	@Tags			Credentials
//	@Accept			json
//	@Produce		json
//	@Param			request	body		BatchUpdateCredentialStatusRequest	true	"request body"
//	@Success		201		{object}	BatchUpdateCredentialStatusResponse
//	@Failure		400		{string}	string	"Bad request"
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/v1/credentials/status/batch [put]
func (cr CredentialRouter) BatchUpdateCredentialStatus(c *gin.Context) {
	var batchRequest BatchUpdateCredentialStatusRequest
	invalidCreateCredentialRequest := "invalid batch update credential request"
	if err := framework.Decode(c.Request, &batchRequest); err != nil {
		errMsg := invalidCreateCredentialRequest
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
		return
	}

	batchUpdateMaxItems := cr.service.Config().BatchUpdateStatusMaxItems
	if len(batchRequest.Requests) > batchUpdateMaxItems {
		framework.LoggingRespondErrMsg(c, fmt.Sprintf("max number of requests is %d", batchUpdateMaxItems), http.StatusBadRequest)
		return
	}

	req := batchRequest.toServiceRequest()
	batchUpdateResponse, err := cr.service.BatchUpdateCredentialStatus(c, *req)

	if err != nil {
		errMsg := "could not update credentials"
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}

	var resp BatchUpdateCredentialStatusResponse
	resp.CredentialStatuses = append(resp.CredentialStatuses, batchUpdateResponse.CredentialStatuses...)

	framework.Respond(c, resp, http.StatusOK)
}

// UpdateCredentialStatus godoc
//
//	@Summary		Update a Verifiable Credential's status
//	@Description	Update a Verifiable Credential's status
//	@Tags			Credentials
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string							true	"ID"
//	@Param			request	body		UpdateCredentialStatusRequest	true	"request body"
//	@Success		201		{object}	UpdateCredentialStatusResponse
//	@Failure		400		{string}	string	"Bad request"
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/v1/credentials/{id}/status [put]
func (cr CredentialRouter) UpdateCredentialStatus(c *gin.Context) {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "cannot get credential without ID parameter"
		framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
		return
	}

	var request UpdateCredentialStatusRequest
	invalidCreateCredentialRequest := "invalid update credential request"
	if err := framework.Decode(c.Request, &request); err != nil {
		errMsg := invalidCreateCredentialRequest
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
		return
	}

	if err := framework.ValidateRequest(request); err != nil {
		errMsg := invalidCreateCredentialRequest
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
		return
	}

	req := request.toServiceRequest(*id)
	gotCredential, err := cr.service.UpdateCredentialStatus(c, req)

	if err != nil {
		errMsg := fmt.Sprintf("could not update credential with id: %s", req.ID)
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}

	resp := UpdateCredentialStatusResponse{
		Revoked:   gotCredential.Revoked,
		Suspended: gotCredential.Suspended,
	}

	framework.Respond(c, resp, http.StatusOK)
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
//	@Summary		Verify a Verifiable Credential
//	@Description	Verifies a given verifiable credential. The system does the following levels of verification:
//	@Description	1. Makes sure the credential has a valid signature
//	@Description	2. Makes sure the credential has is not expired
//	@Description	3. Makes sure the credential complies with the VC Data Model v1.1
//	@Description	4. If the credential has a schema, makes sure its data complies with the schema
//	@Tags			Credentials
//	@Accept			json
//	@Produce		json
//	@Param			request	body		VerifyCredentialRequest	true	"request body"
//	@Success		200		{object}	VerifyCredentialResponse
//	@Failure		400		{string}	string	"Bad request"
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/v1/credentials/verification [put]
func (cr CredentialRouter) VerifyCredential(c *gin.Context) {
	var request VerifyCredentialRequest
	if err := framework.Decode(c.Request, &request); err != nil {
		errMsg := "invalid verify credential request"
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
		return
	}

	if !request.IsValid() {
		errMsg := "request must contain either a Data Integrity Credential or a JWT Credential"
		framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
		return
	}

	verificationResult, err := cr.service.VerifyCredential(c, credential.VerifyCredentialRequest{
		DataIntegrityCredential: request.DataIntegrityCredential,
		CredentialJWT:           request.CredentialJWT,
	})
	if err != nil {
		errMsg := "could not verify credential"
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}

	resp := VerifyCredentialResponse{Verified: verificationResult.Verified, Reason: verificationResult.Reason}
	framework.Respond(c, resp, http.StatusOK)
}

type ListCredentialsResponse struct {
	// Array of credentials that match the query parameters.
	Credentials []credmodel.Container `json:"credentials,omitempty"`

	// Pagination token to retrieve the next page of results. If the value is "", it means no further results for the request.
	NextPageToken string `json:"nextPageToken"`
}

type listCredentialsRequest struct {
	issuer  *string
	schema  *string
	subject *string
}

func (l listCredentialsRequest) GetFilter() string {
	filter := ""
	if l.issuer != nil {
		filter += fmt.Sprintf(`issuer="%s"`, *l.issuer)
	}
	if l.schema != nil {
		filter += fmt.Sprintf(`schema="%s"`, *l.schema)
	}
	if l.subject != nil {
		filter += fmt.Sprintf(`subject="%s"`, *l.subject)
	}
	return filter
}

var listCredentialsFilterDeclarations *filtering.Declarations

func init() {
	var err error
	listCredentialsFilterDeclarations, err = filtering.NewDeclarations(
		filtering.DeclareFunction(
			filtering.FunctionEquals,
			// Below we're declaring the function for `=`.
			filtering.NewFunctionOverload(
				filtering.FunctionOverloadEqualsString,
				filtering.TypeBool,
				filtering.TypeString,
				filtering.TypeString,
			),
		),
		filtering.DeclareIdent("issuer", filtering.TypeString),
		filtering.DeclareIdent("schema", filtering.TypeString),
		filtering.DeclareIdent("subject", filtering.TypeString),
	)
	if err != nil {
		panic(err)
	}
}

// ListCredentials godoc
//
//	@Summary		List Verifiable Credentials
//	@Description	Checks for the presence of an optional query parameter and calls the associated filtered get method.
//	@Description	Only one optional parameter is allowed to be specified.
//	@Tags			Credentials
//	@Accept			json
//	@Produce		json
//	@Param			issuer		query		string	false	"The issuer id, e.g. did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
//	@Param			schema		query		string	false	"The credentialSchema.id value to filter by"
//	@Param			subject		query		string	false	"The credentialSubject.id value to filter by"
//	@Param			pageSize	query		number	false	"Hint to the server of the maximum elements to return. More may be returned. When not set, the server will return all elements."
//	@Param			pageToken	query		string	false	"Used to indicate to the server to return a specific page of the list results. Must match a previous requests' `nextPageToken`."
//	@Success		200			{object}	ListCredentialsResponse
//	@Failure		400			{string}	string	"Bad request"
//	@Failure		500			{string}	string	"Internal server error"
//	@Router			/v1/credentials [get]
func (cr CredentialRouter) ListCredentials(c *gin.Context) {
	var pageRequest pagination.PageRequest
	if pagination.ParsePaginationQueryValues(c, &pageRequest) {
		return
	}

	issuer := framework.GetQueryValue(c, IssuerParam)
	schema := framework.GetQueryValue(c, SchemaParam)
	subject := framework.GetQueryValue(c, SubjectParam)

	errMsg := "must use only one of the following optional query parameters: issuer, subject, schema"

	// check if there are multiple parameters set, which is not allowed
	if (issuer != nil && subject != nil) || (issuer != nil && schema != nil) || (subject != nil && schema != nil) {
		framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
		return
	}

	req := listCredentialsRequest{
		issuer:  issuer,
		schema:  schema,
		subject: subject,
	}

	filter, err := filtering.ParseFilter(req, listCredentialsFilterDeclarations)
	if err != nil {
		framework.LoggingRespondErrMsg(c, "the filter request is malformed", http.StatusBadRequest)
		return
	}

	listCredentialsResponse, err := cr.service.ListCredentials(c, filter, pageRequest)
	if err != nil {
		errMsg := fmt.Sprintf("could not get credentials")
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}

	resp := ListCredentialsResponse{Credentials: listCredentialsResponse.Credentials}

	if pagination.MaybeSetNextPageToken(c, listCredentialsResponse.NextPageToken, &resp.NextPageToken) {
		return
	}
	framework.Respond(c, resp, http.StatusOK)
}

// DeleteCredential godoc
//
//	@Summary		Delete a Verifiable Credential
//	@Description	Delete a Verifiable Credential by its ID
//	@Tags			Credentials
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"ID of the credential to delete"
//	@Success		204	{string}	string	"No Content"
//	@Failure		400	{string}	string	"Bad request"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/v1/credentials/{id} [delete]
func (cr CredentialRouter) DeleteCredential(c *gin.Context) {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "cannot delete credential without ID parameter"
		framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
		return
	}

	if err := cr.service.DeleteCredential(c, credential.DeleteCredentialRequest{ID: *id}); err != nil {
		errMsg := fmt.Sprintf("could not delete credential with id: %s", *id)
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}

	framework.Respond(c, nil, http.StatusNoContent)
}
