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

	// The privateKey associated with the KID used to sign the JWT.
	IssuerKID string `json:"issuerKid" validate:"required"`
}

// ToServiceModel converts a storage model to a service model.
func ToServiceModel(stored *StoredRequest) (*Request, error) {
	request := &Request{
		ID:        stored.ID,
		Audience:  stored.Audience,
		IssuerDID: stored.IssuerDID,
		IssuerKID: stored.IssuerKID,
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

	keyStoreID := did.FullyQualifiedVerificationMethodID(request.IssuerDID, request.IssuerKID)
	signedToken, err := keyStore.Sign(ctx, keyStoreID, token)
	if err != nil {
		return nil, errors.Wrapf(err, "signing payload with KID %q", request.IssuerKID)
	}

	stored := &StoredRequest{
		ID:          requestID,
		Audience:    request.Audience,
		Expiration:  expirationString,
		IssuerDID:   request.IssuerDID,
		IssuerKID:   request.IssuerKID,
		ReferenceID: id,
		JWT:         signedToken.String(),
	}
	return stored, nil
}
