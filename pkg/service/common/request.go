package common

import (
	"context"
	"time"

	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
)

type Request struct {
	// ID for this request. It matches the "jti" claim in the JWT.
	// This is an output only field.
	ID string `json:"id,omitempty"`

	// Audience as defined in https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.3.
	Audience []string `json:"audience,omitempty"`

	// Expiration as defined in https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.4
	Expiration *time.Time `json:"expiration,omitempty"`

	// DID of the issuer of this presentation definition.
	IssuerDID string `json:"issuerId" validate:"required"`

	// The id of the verificationMethod (see https://www.w3.org/TR/did-core/#verification-methods) who's privateKey is
	// stored in ssi-service. The verificationMethod must be part of the did document associated with `issuer`.
	// The private key associated with the verificationMethod's publicKey will be used to sign the JWT.
	VerificationMethodID string `json:"verificationMethodId" validate:"required" example:"did:key:z6MkkZDjunoN4gyPMx5TSy7Mfzw22D2RZQZUcx46bii53Ex3#z6MkkZDjunoN4gyPMx5TSy7Mfzw22D2RZQZUcx46bii53Ex3"`
}

// ToServiceModel converts a storage model to a service model.
func ToServiceModel(stored *StoredRequest) (*Request, error) {
	request := &Request{
		ID:                   stored.ID,
		Audience:             stored.Audience,
		IssuerDID:            stored.IssuerDID,
		VerificationMethodID: stored.VerificationMethodID,
	}
	if stored.Expiration != "" {
		expiration, err := time.Parse(time.RFC3339, stored.Expiration)
		if err != nil {
			return nil, errors.Wrap(err, "parsing expiration time")
		}
		request.Expiration = &expiration
	}
	return request, nil
}

// CreateStoredRequest creates a StoredRequest with the associated signed JWT populated. In addition to the fields
// present in request, the JWT will also include a claim with claimName and claimValue.
func CreateStoredRequest(ctx context.Context, keyStore *keystore.Service, claimName string, claimValue any, request Request, id string) (*StoredRequest, error) {
	requestID := uuid.NewString()
	builder := jwt.NewBuilder().
		Claim(claimName, claimValue).
		Audience(request.Audience).
		Issuer(request.IssuerDID).
		NotBefore(time.Now()).
		JwtID(requestID)
	var expirationString string
	if request.Expiration != nil {
		builder.Expiration(*request.Expiration)
		expirationString = request.Expiration.Format(time.RFC3339)
	}
	token, err := builder.Build()
	if err != nil {
		return nil, errors.Wrap(err, "building jwt")
	}

	keyStoreID := did.FullyQualifiedVerificationMethodID(request.IssuerDID, request.VerificationMethodID)
	signedToken, err := keyStore.Sign(ctx, keyStoreID, token)
	if err != nil {
		return nil, errors.Wrapf(err, "signing payload with KID %q", request.VerificationMethodID)
	}

	stored := &StoredRequest{
		ID:                   requestID,
		Audience:             request.Audience,
		Expiration:           expirationString,
		IssuerDID:            request.IssuerDID,
		VerificationMethodID: request.VerificationMethodID,
		ReferenceID:          id,
		JWT:                  signedToken.String(),
	}
	return stored, nil
}
