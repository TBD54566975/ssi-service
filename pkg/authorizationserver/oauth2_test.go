package authorizationserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/TBD54566975/ssi-sdk/oidc/issuance"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tbd54566975/ssi-service/config"
)

func fetchMetadata(url string) (*issuance.IssuerMetadata, error) {
	resp, err := http.Get(url) // #nosec: testing only.
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	var metadata issuance.IssuerMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, err
	}

	return &metadata, nil
}

func TestCredentialIssuerMetadata(t *testing.T) {
	// Create an httptest server with the metadataHandler
	server := httptest.NewServer(NewServer(make(chan os.Signal, 1), &AuthConfig{
		Server: config.ServerConfig{
			APIHost: "my-authorization-server.com:8488",
		},
	}))
	defer server.Close()

	// Fetch the metadata from the test server
	metadata, err := fetchMetadata(server.URL + "/oidc/issuer/.well-known/openid-credential-issuer")
	require.NoError(t, err)

	// Check that the issuer matches the URL that was fetched
	assert.Equal(t, "https://my-authorization-server.com:8488/oidc/issuer", metadata.CredentialIssuer.String())
}
