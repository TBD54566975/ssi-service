package router

import (
	"context"
	"net/http"

	"github.com/pkg/errors"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/oidc"
	"github.com/tbd54566975/ssi-service/pkg/service/oidc/model"
)

type OIDCCredentialRouter struct {
	service *oidc.Service
}

// IssueCredential implements https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-endpoint
func (r OIDCCredentialRouter) IssueCredential(ctx context.Context, w http.ResponseWriter, req *http.Request) error {
	var credRequest model.CredentialRequest
	if err := framework.Decode(req, &credRequest); err != nil {
		return framework.NewRequestError(errors.Wrap(err, "decoding request"), http.StatusBadRequest)
	}

	resp, err := r.service.CredentialEndpoint(ctx, &credRequest)
	if err != nil {
		return r.responseFromError(ctx, w, err)
	}

	return framework.Respond(ctx, w, resp, http.StatusOK)
}

// CredentialError implements https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-response
type CredentialError struct {
	// Error is a string that describes the type of error that occurred.
	Error string `json:"error"`

	// ErrorDescription is a string that provides additional information about the error that occurred.
	ErrorDescription string `json:"error_description"`

	// CNonce is an optional JSON string nonce used to create a proof of possession of key material when requesting a Credential (see Section 7.2).
	// When received, the Wallet must use this nonce value for subsequent credential requests until the Credential Issuer provides a fresh nonce.
	CNonce string `json:"c_nonce,omitempty"`

	// CNonceExpiresIn is an optional JSON integer denoting the lifetime in seconds of the c_nonce.
	CNonceExpiresIn int `json:"c_nonce_expires_in,omitempty"`

	// AcceptanceToken is an optional JSON string containing a security token used to subsequently obtain a Credential.
	// It is required to be present when the Credential is not returned.
	// Note that this is currently not implemented.
	AcceptanceToken string `json:"acceptance_token,omitempty"`
}

const InvalidOrMissingProof = "invalid_or_missing_proof"

func (r OIDCCredentialRouter) responseFromError(ctx context.Context, w http.ResponseWriter, err error) error {
	switch {
	case errors.Is(err, oidc.ErrNonceNotString) || errors.Is(err, oidc.ErrNonceDifferent) || errors.Is(err, oidc.ErrNonceNotPresent):
		nonce, nonceErr := r.service.CurrentNonce()
		if nonceErr != nil {
			return framework.RespondError(ctx, w, nonceErr)
		}
		return framework.Respond(ctx, w, CredentialError{
			Error:            InvalidOrMissingProof,
			ErrorDescription: err.Error(),
			CNonce:           nonce,
			CNonceExpiresIn:  r.service.NonceExpiresIn(),
		}, http.StatusBadRequest)
	default:
		return framework.RespondError(ctx, w, err)
	}
}

func NewOIDCCredentialRouter(s svcframework.Service) (*OIDCCredentialRouter, error) {
	svc, ok := s.(*oidc.Service)
	if !ok {
		return nil, errors.New("cannot provide oidc service")
	}
	return &OIDCCredentialRouter{service: svc}, nil
}
