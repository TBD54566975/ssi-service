package authorizationserver

import (
	"net/http"

	"github.com/TBD54566975/ssi-sdk/oidc/issuance"
	"github.com/gin-gonic/gin"

	"github.com/tbd54566975/ssi-service/pkg/server/framework"
)

// Allow retrieval of credential issuer metadata according to https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata
func credentialIssuerMetadata(im *issuance.IssuerMetadata) framework.Handler {
	return func(c *gin.Context) error {
		return framework.Respond(c, im, http.StatusOK)
	}
}
