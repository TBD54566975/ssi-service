package authorizationserver

import (
	_ "embed"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fetchMetadata(url string) ([]byte, error) {
	resp, err := http.Get(url) // #nosec: testing only.
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return data, nil
}

//go:embed expected_issuer_metadata.json
var expectedIssuerMetadata []byte

func TestCredentialIssuerMetadata(t *testing.T) {
	// Create an httptest server with the metadataHandler
	server := httptest.NewServer(NewServer(make(chan os.Signal, 1), &AuthConfig{
		CredentialIssuerFile: "../../config/credential_issuer_metadata.json",
	}))
	defer server.Close()

	// Fetch the metadata from the test server
	metadata, err := fetchMetadata(server.URL + "/oidc/issuer/.well-known/openid-credential-issuer")
	require.NoError(t, err)

	// Check that the issuer matches the URL that was fetched
	assert.JSONEq(t, string(expectedIssuerMetadata), string(metadata))
}
