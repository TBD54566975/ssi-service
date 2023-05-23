package authorizationserver

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"time"

	"github.com/TBD54566975/ssi-sdk/oidc/issuance"
	"github.com/ardanlabs/conf"
	"github.com/gin-gonic/gin"
	"github.com/goccy/go-json"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/jwt"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	"github.com/tbd54566975/ssi-service/pkg/server/middleware"
)

// A session is passed from the `/auth` to the `/token` endpoint. You probably want to store data like: "Who made the request",
// "What organization does that person belong to" and so on.
// For our use case, the session will meet the requirements imposed by JWT access tokens, HMAC access tokens and OpenID Connect
// ID Tokens plus a custom field

// newSession is a helper function for creating a new session. This may look like a lot of code but since we are
// setting up multiple strategies it is a bit longer.
// Usually, you could do:
//
//	session = new(fosite.DefaultSession)
func newSession(user string) *openid.DefaultSession {
	return &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Issuer:      "https://fosite.my-application.com",
			Subject:     user,
			Audience:    []string{"https://my-client.my-application.com"},
			ExpiresAt:   time.Now().Add(time.Hour * 6),
			IssuedAt:    time.Now(),
			RequestedAt: time.Now(),
			AuthTime:    time.Now(),
		},
		Headers: &jwt.Headers{
			Extra: make(map[string]interface{}),
		},
	}
}

type Server struct {
	*framework.Server
}

const (
	oidcPrefix         = "/oidc/issuer"
	issuerMetadataPath = oidcPrefix + "/.well-known/openid-credential-issuer"
)

func NewServer(shutdown chan os.Signal, config *AuthConfig, store *storage.MemoryStore) (*Server, error) {
	// This secret is used to sign authorize codes, access and refresh tokens.
	// It has to be 32-bytes long for HMAC signing. This requirement can be configured via `compose.Config`
	secret := make([]byte, 32)

	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}

	// fosite requires four parameters for the server to get up and running:
	//  1. config - for any enforcement you may desire, you can do this using `compose.Config`. You like PKCE, enforce it!
	//  2. store - no auth service is generally useful unless it can remember clients and users.
	//     fosite is incredibly composable, and the store parameter enables you to build and BYODb (Bring Your Own Database)
	//  3. secret - required for code, access and refresh token generation.
	//  4. privateKey - required for id/jwt token generation.

	var (
		// Check the api documentation of `compose.Config` for further configuration options.
		fositeConfig = &fosite.Config{
			AccessTokenLifespan:        time.Minute * 30,
			GlobalSecret:               secret,
			SendDebugMessagesToClients: true,
			// ...
		}

		// privateKey is used to sign JWT tokens. The default strategy uses RS256 (RSA Signature with SHA-256)
		privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)

		// Build a fosite instance with all OAuth2 and OpenID Connect handlers enabled, plugging in our configurations as specified above.
		oauth2 = compose.ComposeAllEnabled(fositeConfig, store, privateKey)
	)

	middlewares := gin.HandlersChain{
		gin.Logger(),
		gin.Recovery(),
		middleware.Errors(shutdown),
	}

	engine := gin.New()
	engine.Use(middlewares...)
	httpServer := framework.NewServer(config.Server, engine, shutdown)

	im, err := loadIssuerMetadata(config)
	if err != nil {
		logrus.WithError(err).Fatal("could not load issuer metadata")
		os.Exit(1)
	}

	engine.GET(issuerMetadataPath, credentialIssuerMetadata(im))

	// Set up oauth2 endpoints.
	authService := NewAuthService(im, oauth2)
	engine.GET("/oauth2/auth", authService.AuthEndpoint)
	engine.POST("/oauth2/auth", authService.AuthEndpoint)

	return &Server{
		Server: httpServer,
	}, nil
}

func loadIssuerMetadata(config *AuthConfig) (*issuance.IssuerMetadata, error) {
	jsonData, err := os.ReadFile(config.CredentialIssuerFile)
	if err != nil {
		return nil, err
	}

	var im issuance.IssuerMetadata
	if err := json.Unmarshal(jsonData, &im); err != nil {
		return nil, err
	}
	return &im, nil
}

type AuthConfig struct {
	conf.Version
	Server               config.ServerConfig
	CredentialIssuerFile string `toml:"credential_issuer_file" conf:"default:config/credential_issuer_metadata.example.json"`
}
