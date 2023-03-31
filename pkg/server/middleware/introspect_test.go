package middleware

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tbd54566975/ssi-service/pkg/testutil"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

func TestIntrospect(t *testing.T) {
	mockTokenServer := simpleOauthTokenServer()
	defer mockTokenServer.Close()
	conf := newConfig(mockTokenServer)

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"active":true}`))
	}))
	defer mockServer.Close()

	introspectMiddleware := Introspect(mockServer.URL, conf)

	handlerCalled := false
	handler := introspectMiddleware(func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		handlerCalled = true
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/some_protected_url", strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer my-awesome-token")
	require.NoError(t, handler(context.Background(), httptest.NewRecorder(), req))
	require.True(t, handlerCalled)
}

func TestIntrospectReturnsError(t *testing.T) {
	mockTokenServer := simpleOauthTokenServer()
	defer mockTokenServer.Close()
	conf := newConfig(mockTokenServer)

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"active":false}`))
	}))
	defer mockServer.Close()

	introspectMiddleware := Introspect(mockServer.URL, conf)

	handler := introspectMiddleware(noOpHandler)
	req := httptest.NewRequest(http.MethodPost, "/some_protected_url", strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer my-awesome-token")
	w := httptest.NewRecorder()
	err := handler(testutil.NewRequestContext(), w, req)
	require.NoError(t, err)
	assertCredentialErrorResponseEquals(t, w, `{"error":"invalid_token"}`)
}

func assertCredentialErrorResponseEquals(t *testing.T, w *httptest.ResponseRecorder, s string) {
	respBody, err := io.ReadAll(w.Body)
	require.NoError(t, err)
	require.JSONEq(t, s, string(respBody))
}

func noOpHandler(context.Context, http.ResponseWriter, *http.Request) error {
	return nil
}

func simpleOauthTokenServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		values := url.Values{}
		values.Set("access_token", "my-client-token")
		_, _ = w.Write([]byte(values.Encode()))
	}))
}

func newConfig(mockTokenServer *httptest.Server) clientcredentials.Config {
	conf := clientcredentials.Config{
		ClientID:       "my-test-client",
		ClientSecret:   "",
		TokenURL:       mockTokenServer.URL,
		Scopes:         []string{"notsurewhatscope"},
		EndpointParams: nil,
		AuthStyle:      oauth2.AuthStyleInHeader,
	}
	return conf
}
