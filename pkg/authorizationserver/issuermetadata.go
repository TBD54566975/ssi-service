package authorizationserver

import (
	"context"
	"net/http"
	"net/url"

	"github.com/TBD54566975/ssi-sdk/oidc/issuance"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
)

// Allow retrieval of credential issuer metadata according to https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata
func credentialIssuerMetadata(config *AuthConfig) func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	issuer, err := url.Parse("https://" + config.Server.APIHost + oidcPrefix)
	if err != nil {
		panic(err)
	}
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		im := issuance.IssuerMetadata{
			CredentialIssuer: util.URL{
				URL: *issuer,
			},
			AuthorizationServer:     nil,
			CredentialEndpoint:      util.URL{},
			BatchCredentialEndpoint: nil,
			CredentialsSupported:    nil,
			Display:                 nil,
		}
		return framework.Respond(ctx, w, im, http.StatusOK)
	}
}
