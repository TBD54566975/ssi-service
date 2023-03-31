package authorizationserver

import (
	"context"
	"net/http"

	"github.com/TBD54566975/ssi-sdk/oidc/issuance"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
)

// Allow retrieval of credential issuer metadata according to https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata
func credentialIssuerMetadata(im *issuance.IssuerMetadata) func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		return framework.Respond(ctx, w, im, http.StatusOK)
	}
}
