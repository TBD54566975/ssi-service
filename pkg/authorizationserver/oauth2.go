package authorizationserver

import (
	"net/http"
	"os"

	"github.com/ardanlabs/conf"
	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	"github.com/tbd54566975/ssi-service/pkg/server/middleware"
)

type Server struct {
	*framework.Server
}

const (
	oidcPrefix         = "/oidc/issuer"
	issuerMetadataPath = oidcPrefix + "/.well-known/openid-credential-issuer"
)

func NewServer(shutdown chan os.Signal, config *AuthConfig) *Server {
	middlewares := []framework.Middleware{
		middleware.Logger(),
		middleware.Errors(),
	}
	httpServer := framework.NewHTTPServer(config.Server, shutdown, middlewares...)

	httpServer.Handle(http.MethodGet, issuerMetadataPath, credentialIssuerMetadata(config))

	return &Server{
		Server: httpServer,
	}
}

type AuthConfig struct {
	conf.Version
	Server               config.ServerConfig
	CredentialIssuerFile string `toml:"credential_issuer_file" conf:"default:config/credential_issuer_metadata.json"`
}
