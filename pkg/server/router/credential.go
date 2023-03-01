package router

import (
	"context"
	"fmt"
	"net/http"

	credsdk "github.com/TBD54566975/ssi-sdk/credential"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	credmodel "github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/credential"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/webhook"
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

	// The subject id.
	Subject string `json:"subject" validate:"required" example:"did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"`

	// A context is optional. If not present, we'll apply default, required context values.
	Context string `json:"@context"`

	// A schema is optional. If present, we'll attempt to look it up and validate the data against it.
	Schema string `json:"schema"`

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
	// TODO(gabe) support more capabilities like signature type, format, status, and more.
}

func (c CreateCredentialRequest) ToServiceRequest() credential.CreateCredentialRequest {
	return credential.CreateCredentialRequest{
		Issuer:      c.Issuer,
		Subject:     c.Subject,
		Context:     c.Context,
		JSONSchema:  c.Schema,
		Data:        c.Data,
		Expiry:      c.Expiry,
		Revocable:   c.Revocable,
		Suspendable: c.Suspendable,
	}
}

type CreateCredentialResponse struct {
	Credential    *credsdk.VerifiableCredential `json:"credential,omitempty"`
	CredentialJWT *keyaccess.JWT                `json:"credentialJwt,omitempty"`
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
func (cr CredentialRouter) CreateCredential(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	var request CreateCredentialRequest
	invalidCreateCredentialRequest := "invalid create credential request"
	if err := framework.Decode(r, &request); err != nil {
		errMsg := invalidCreateCredentialRequest
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	if err := framework.ValidateRequest(request); err != nil {
		errMsg := invalidCreateCredentialRequest
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	req := request.ToServiceRequest()
	createCredentialResponse, err := cr.service.CreateCredential(ctx, req)
	if err != nil {
		errMsg := "could not create credential"
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	resp := CreateCredentialResponse{Credential: createCredentialResponse.Credential, CredentialJWT: createCredentialResponse.CredentialJWT}

	go cr.service.Webhook.PublishWebhook(webhook.Credential, webhook.Create, resp)
	return framework.Respond(ctx, w, resp, http.StatusCreated)
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
func (cr CredentialRouter) GetCredential(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		errMsg := "cannot get credential without ID parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	gotCredential, err := cr.service.GetCredential(ctx, credential.GetCredentialRequest{ID: *id})
	if err != nil {
		errMsg := fmt.Sprintf("could not get credential with id: %s", *id)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	resp := GetCredentialResponse{
		ID:            gotCredential.ID,
		Credential:    gotCredential.Credential,
		CredentialJWT: gotCredential.CredentialJWT,
	}
	return framework.Respond(ctx, w, resp, http.StatusOK)
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
func (cr CredentialRouter) GetCredentialStatus(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		errMsg := "cannot get credential without ID parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	getCredentialStatusResponse, err := cr.service.GetCredentialStatus(ctx, credential.GetCredentialStatusRequest{ID: *id})
	if err != nil {
		errMsg := fmt.Sprintf("could not get credential with id: %s", *id)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	resp := GetCredentialStatusResponse{
		Revoked:   getCredentialStatusResponse.Revoked,
		Suspended: getCredentialStatusResponse.Suspended,
	}

	return framework.Respond(ctx, w, resp, http.StatusOK)
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
func (cr CredentialRouter) GetCredentialStatusList(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		errMsg := "cannot get credential without ID parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	gotCredential, err := cr.service.GetCredentialStatusList(ctx, credential.GetCredentialStatusListRequest{ID: *id})
	if err != nil {
		errMsg := fmt.Sprintf("could not get credential status list with id: %s", *id)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	resp := GetCredentialStatusListResponse{
		ID:            gotCredential.ID,
		Credential:    gotCredential.Credential,
		CredentialJWT: gotCredential.CredentialJWT,
	}

	return framework.Respond(ctx, w, resp, http.StatusOK)
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
func (cr CredentialRouter) UpdateCredentialStatus(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		errMsg := "cannot get credential without ID parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	var request UpdateCredentialStatusRequest
	invalidCreateCredentialRequest := "invalid update credential request"
	if err := framework.Decode(r, &request); err != nil {
		errMsg := invalidCreateCredentialRequest
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	if err := framework.ValidateRequest(request); err != nil {
		errMsg := invalidCreateCredentialRequest
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	req := request.ToServiceRequest(*id)
	gotCredential, err := cr.service.UpdateCredentialStatus(ctx, req)

	if err != nil {
		errMsg := fmt.Sprintf("could not update credential with id: %s", req.ID)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	resp := UpdateCredentialStatusResponse{
		Revoked:   gotCredential.Revoked,
		Suspended: gotCredential.Suspended,
	}

	return framework.Respond(ctx, w, resp, http.StatusOK)
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
func (cr CredentialRouter) VerifyCredential(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	var request VerifyCredentialRequest
	if err := framework.Decode(r, &request); err != nil {
		errMsg := "invalid verify credential request"
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	if !request.IsValid() {
		err := errors.New("request must contain either a Data Integrity Credential or a JWT Credential")
		logrus.WithError(err).Error()
		return framework.NewRequestError(err, http.StatusBadRequest)
	}

	verificationResult, err := cr.service.VerifyCredential(ctx, credential.VerifyCredentialRequest{
		DataIntegrityCredential: request.DataIntegrityCredential,
		CredentialJWT:           request.CredentialJWT,
	})
	if err != nil {
		errMsg := "could not verify credential"
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	resp := VerifyCredentialResponse{Verified: verificationResult.Verified, Reason: verificationResult.Reason}
	return framework.Respond(ctx, w, resp, http.StatusOK)
}

type GetCredentialsResponse struct {
	Credentials []credmodel.Container `json:"credentials"`
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
func (cr CredentialRouter) GetCredentials(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	issuer := framework.GetQueryValue(r, IssuerParam)
	schema := framework.GetQueryValue(r, SchemaParam)
	subject := framework.GetQueryValue(r, SubjectParam)

	err := framework.NewRequestErrorMsg("must use one of the following query parameters: issuer, subject, schema", http.StatusBadRequest)

	// check if there are multiple parameters set, which is not allowed
	if (issuer != nil && subject != nil) || (issuer != nil && schema != nil) || (subject != nil && schema != nil) {
		return err
	}

	if issuer != nil {
		return cr.getCredentialsByIssuer(ctx, *issuer, w, r)
	}
	if subject != nil {
		return cr.getCredentialsBySubject(ctx, *subject, w, r)
	}
	if schema != nil {
		return cr.getCredentialsBySchema(ctx, *schema, w, r)
	}
	return err
}

func (cr CredentialRouter) getCredentialsByIssuer(ctx context.Context, issuer string, w http.ResponseWriter, _ *http.Request) error {
	gotCredentials, err := cr.service.GetCredentialsByIssuer(ctx, credential.GetCredentialByIssuerRequest{Issuer: issuer})
	if err != nil {
		errMsg := fmt.Sprintf("could not get credentials for issuer: %s", util.SanitizeLog(issuer))
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	resp := GetCredentialsResponse{Credentials: gotCredentials.Credentials}
	return framework.Respond(ctx, w, resp, http.StatusOK)
}

func (cr CredentialRouter) getCredentialsBySubject(ctx context.Context, subject string, w http.ResponseWriter, _ *http.Request) error {
	gotCredentials, err := cr.service.GetCredentialsBySubject(ctx, credential.GetCredentialBySubjectRequest{Subject: subject})
	if err != nil {
		errMsg := fmt.Sprintf("could not get credentials for subject: %s", util.SanitizeLog(subject))
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	resp := GetCredentialsResponse{Credentials: gotCredentials.Credentials}
	return framework.Respond(ctx, w, resp, http.StatusOK)
}

func (cr CredentialRouter) getCredentialsBySchema(ctx context.Context, schema string, w http.ResponseWriter, _ *http.Request) error {
	gotCredentials, err := cr.service.GetCredentialsBySchema(ctx, credential.GetCredentialBySchemaRequest{Schema: schema})
	if err != nil {
		errMsg := fmt.Sprintf("could not get credentials for schema: %s", util.SanitizeLog(schema))
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	resp := GetCredentialsResponse{Credentials: gotCredentials.Credentials}
	return framework.Respond(ctx, w, resp, http.StatusOK)
}

// DeleteCredential godoc
//
// @Summary     Delete Credentials
// @Description Delete credential by ID
// @Tags        CredentialAPI
// @Accept      json
// @Produce     json
// @Param       id  path     string true "ID"
// @Success     200 {string} string "OK"
// @Failure     400 {string} string "Bad request"
// @Failure     500 {string} string "Internal server error"
// @Router      /v1/credentials/{id} [delete]
func (cr CredentialRouter) DeleteCredential(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		errMsg := "cannot delete credential without ID parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	if err := cr.service.DeleteCredential(ctx, credential.DeleteCredentialRequest{ID: *id}); err != nil {
		errMsg := fmt.Sprintf("could not delete credential with id: %s", *id)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	go cr.service.Webhook.PublishWebhook(webhook.Credential, webhook.Delete, id)
	return framework.Respond(ctx, w, nil, http.StatusOK)
}
