package authorizationserver

import (
	"context"
	"net/http"
	"os"

	"github.com/TBD54566975/ssi-sdk/oidc/issuance"
	"github.com/goccy/go-json"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
)

// Allow retrieval of credential issuer metadata according to https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata
func credentialIssuerMetadata(config *AuthConfig) func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	// It's ok to panic inside this function because this is only called during startup.
	jsonData, err := os.ReadFile(config.CredentialIssuerFile)
	if err != nil {
		panic(err)
	}

	var im issuance.IssuerMetadata
	if err := json.Unmarshal(jsonData, &im); err != nil {
		panic(err)
	}
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		return framework.Respond(ctx, w, im, http.StatusOK)
	}
}
