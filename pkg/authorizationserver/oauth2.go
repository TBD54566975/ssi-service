package authorizationserver

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"os"
	"time"

	"github.com/ardanlabs/conf"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/jwt"
	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	"github.com/tbd54566975/ssi-service/pkg/server/middleware"
)

// fosite requires four parameters for the server to get up and running:
//  1. config - for any enforcement you may desire, you can do this using `compose.Config`. You like PKCE, enforce it!
//  2. store - no auth service is generally useful unless it can remember clients and users.
//     fosite is incredibly composable, and the store parameter enables you to build and BYODb (Bring Your Own Database)
//  3. secret - required for code, access and refresh token generation.
//  4. privateKey - required for id/jwt token generation.
var (
	// Check the api documentation of `compose.Config` for further configuration options.
	fositeConfig = &fosite.Config{
		AccessTokenLifespan: time.Minute * 30,
		GlobalSecret:        secret,
		// ...
	}

	// This is the example storage that contains:
	// * an OAuth2 Client with id "my-client" and secrets "foobar" and "foobaz" capable of all oauth2 and open id connect grant and response types.
	// * a User for the resource owner password credentials grant type with username "peter" and password "secret".
	//
	// You will most likely replace this with your own logic once you set up a real world application.
	store = storage.NewExampleStore()

	// This secret is used to sign authorize codes, access and refresh tokens.
	// It has to be 32-bytes long for HMAC signing. This requirement can be configured via `compose.Config` above.
	// In order to generate secure keys, the best thing to do is use crypto/rand:
	//
	// ```
	// package main
	//
	// import (
	//	"crypto/rand"
	//	"encoding/hex"
	//	"fmt"
	// )
	//
	// func main() {
	//	var secret = make([]byte, 32)
	//	_, err := rand.Read(secret)
	//	if err != nil {
	//		panic(err)
	//	}
	// }
	// ```
	//
	// If you require this to key to be stable, for example, when running multiple fosite servers, you can generate the
	// 32byte random key as above and push it out to a base64 encoded string.
	// This can then be injected and decoded as the `var secret []byte` on server start.
	secret = []byte("some-cool-secret-that-is-32bytes")

	// privateKey is used to sign JWT tokens. The default strategy uses RS256 (RSA Signature with SHA-256)
	privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
)

// Build a fosite instance with all OAuth2 and OpenID Connect handlers enabled, plugging in our configurations as specified above.
var oauth2 = compose.ComposeAllEnabled(fositeConfig, store, privateKey)

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

func NewServer(shutdown chan os.Signal, config *AuthConfig) *Server {
	middlewares := []framework.Middleware{
		middleware.Logger(),
		middleware.Errors(),
	}
	httpServer := framework.NewHTTPServer(config.Server, shutdown, middlewares...)

	httpServer.Handle(http.MethodGet, issuerMetadataPath, credentialIssuerMetadata(config))

	// Set up oauth2 endpoints.
	httpServer.Handle(http.MethodGet, "/oauth2/auth", authEndpoint)
	httpServer.Handle(http.MethodPost, "/oauth2/token", tokenEndpoint)

	// revoke tokens
	httpServer.Handle(http.MethodPost, "/oauth2/revoke", revokeEndpoint)
	httpServer.Handle(http.MethodPost, "/oauth2/introspect", introspectionEndpoint)

	return &Server{
		Server: httpServer,
	}
}

type AuthConfig struct {
	conf.Version
	Server config.ServerConfig
}
