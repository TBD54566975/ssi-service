package authorizationserver

import (
	_ "embed"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	server *httptest.Server
	store  *storage.MemoryStore
)

func TestMain(m *testing.M) {
	store = storage.NewMemoryStore()

	// Create a httptest server with the metadataHandler
	authServer, err := NewServer(make(chan os.Signal, 1), &AuthConfig{
		CredentialIssuerFile: "../../config/testdata/credential_issuer_metadata.example.json",
	}, store)
	if err != nil {
		logrus.WithError(err).Fatal("cannot create authserver")
		os.Exit(1)
	}
	server = httptest.NewServer(authServer.Handler)

	code := m.Run()

	server.Close()
	os.Exit(code)
}

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
	// Fetch the metadata from the test server
	metadata, err := fetchMetadata(server.URL + "/oidc/issuer/.well-known/openid-credential-issuer")
	require.NoError(t, err)

	// Check that the issuer matches the DIDWebID that was fetched
	assert.JSONEq(t, string(expectedIssuerMetadata), string(metadata))
}

func TestAuthorizationEndpoint(t *testing.T) {
	callbackCalled := false
	h := new(handler)
	clientServer := httptest.NewServer(http.HandlerFunc(h.callbackHandler(t, &callbackCalled)))

	clientID := createClient(clientServer)

	testCases := []struct {
		name                 string
		authorizationDetails string
		wantError            string
		callbackAssertion    *doAssert
	}{
		{
			name: "no location returns error",
			authorizationDetails: `[
			  {
				 "type":"openid_credential",
				 "format":"jwt_vc_json",
				 "types":[
				   "VerifiableCredential",
				   "UniversityDegreeCredential"
				 ]
			  }
			]`,
			wantError: "locations expected to have a single element",
		},
		{
			name: "location that's not the credential issuer id fails",
			authorizationDetails: `[
			  {
				 "type":"openid_credential",
				 "format":"jwt_vc_json",
				 "locations":["hello"],
				 "types":[
				   "VerifiableCredential",
				   "UniversityDegreeCredential"
				 ]
			  }
			]`,
			wantError: "locations[0] expected to be equal to 'https://credential-issuer.example.com', but received 'hello'",
		},
		{
			name: "authorization code is granted",
			authorizationDetails: `[
			  {
				 "type":"openid_credential",
				 "format":"jwt_vc_json",
				 "locations":["https://credential-issuer.example.com"],
				 "types":[
				   "VerifiableCredential",
				   "UniversityDegreeCredential"
				 ]
			  }
			]`,
			callbackAssertion: &doAssert{
				with: func(t *testing.T, r *http.Request) {
					require.Equal(t, "my-state", r.URL.Query().Get("state"))
					require.NotEmpty(t, r.URL.Query().Get("code"))
				},
			},
		},
		{
			name: "unknown type returns error",
			authorizationDetails: `[
			  {
				 "type":"crazy_type"
			  }
			]`,
			wantError: "the value of authorization_details[0].type found was 'crazy_type', which is not recognized",
		},
	}
	for _, tc := range testCases {
		callbackCalled = false

		u, err := url.Parse(server.URL + "/oauth2/auth")
		require.NoError(t, err)

		q := createQuery(u, clientID, clientServer.URL, tc.authorizationDetails)
		form := createForm()

		h.errorWanted = tc.wantError
		h.assert = tc.callbackAssertion

		u.RawQuery = q.Encode()
		require.False(t, callbackCalled)

		resp, err := http.Post(u.String(), "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
		require.True(t, callbackCalled)
		require.NoError(t, err)
		require.NotEmpty(t, resp)
	}
}

func createForm() url.Values {
	form := url.Values{}
	form.Set("username", "peter")
	form.Add("scopes", "openid")
	form.Add("scopes", "photos")
	return form
}

func createQuery(u *url.URL, clientID string, clientServerURL string, authorizationDetails string) url.Values {
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", "http://localhost:3846/callback")
	q.Set("state", "my-state")
	q.Set("username", "my-state")
	q.Set("redirect_uri", clientServerURL)
	q.Set("authorization_details", authorizationDetails)
	return q
}

func createClient(clientServer *httptest.Server) string {
	clientID := "my-test-client"
	store.Clients[clientID] = &fosite.DefaultClient{
		ID:             clientID,
		Secret:         []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`),            // = "foobar"
		RotatedSecrets: [][]byte{[]byte(`$2y$10$X51gLxUQJ.hGw1epgHTE5u0bt64xM0COU7K9iAp.OFg8p2pUd.1zC `)}, // = "foobaz",
		RedirectURIs:   []string{clientServer.URL},
		ResponseTypes:  []string{"id_token", "code", "token", "id_token token", "code id_token", "code token", "code id_token token"},
		GrantTypes:     []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
		Scopes:         []string{"fosite", "openid", "photos", "offline"},
	}
	return clientID
}

type doAssert struct {
	with func(t *testing.T, r *http.Request)
}

type handler struct {
	errorWanted string
	assert      *doAssert
}

func (h *handler) callbackHandler(t *testing.T, wasCalled *bool) func(writer http.ResponseWriter, request *http.Request) {
	return func(writer http.ResponseWriter, request *http.Request) {
		require.Contains(t, request.URL.Query().Get("error_description"), h.errorWanted)
		if h.assert != nil {
			h.assert.with(t, request)
		}
		*wasCalled = true
	}
}
