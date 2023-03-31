package middleware

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type introspecter struct {
	// Introspection endpoint according to https://www.rfc-editor.org/rfc/rfc7662.
	endpoint string

	// Config of the client credentials to use for authenticating with Endpoint.
	conf clientcredentials.Config
}

func newIntrospect(endpoint string, config clientcredentials.Config) *introspecter {
	return &introspecter{
		endpoint: endpoint,
		conf:     config,
	}
}

// Introspect extracts a token from the `Authorization` header, and determines whether it's active by using the
// Endpoint configured. A `nil` error represents an active token.
func (s introspecter) introspect(ctx context.Context, req *http.Request) error {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, http.Client{Transport: otelhttp.NewTransport(http.DefaultTransport)})
	client := s.conf.Client(ctx)
	// Send a request to the introspect endpoint to decide whether this is allowed.
	authHeader := req.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return errors.New("no bearer")
	}
	token := authHeader[len("Bearer "):]

	body := make(url.Values)
	body.Set("token", token)
	introspectionReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return err
	}
	introspectionReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	introspectionResp, err := client.Do(introspectionReq)
	if err != nil {
		return err
	}
	defer func(body io.ReadCloser) {
		err := body.Close()
		if err != nil {
			logrus.WithError(err).Warn("closing body")
		}
	}(introspectionResp.Body)

	if introspectionResp.StatusCode != http.StatusOK {
		return fmt.Errorf("status does not indicate success: code: %d, body: %v", introspectionResp.StatusCode, introspectionResp.Body)
	}

	result, err := extractIntrospectResult(introspectionResp.Body)
	if err != nil {
		return err
	}
	if !result.Active {
		return errors.New("invalid token")
	}
	return nil
}

func extractIntrospectResult(r io.Reader) (*result, error) {
	res := result{
		Optionals: make(map[string]json.RawMessage),
	}

	if err := json.NewDecoder(r).Decode(&res.Optionals); err != nil {
		return nil, err
	}

	if val, ok := res.Optionals["active"]; ok {
		if err := json.Unmarshal(val, &res.Active); err != nil {
			return nil, err
		}

		delete(res.Optionals, "active")
	}

	return &res, nil
}

// result is the OAuth2 Introspection Result
type result struct {
	Active bool

	Optionals map[string]json.RawMessage
}

// Introspect creates a middleware which can be used to gate access to protected resources.
// This middleware works by extracting the token from the `Authorization` header and then sending a request to the
// introspect endpoint (which should be compliant with https://www.rfc-editor.org/rfc/rfc7662) to obtain the
// whether the token is active. A `nil` error represents an active token.
// config represents the client credentials to use for authenticating with the introspect endpoint.
func Introspect(endpoint string, config clientcredentials.Config) framework.Middleware {
	intro := newIntrospect(endpoint, config)
	return func(handler framework.Handler) framework.Handler {
		return func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
			if err := intro.introspect(ctx, r); err != nil {
				frameworkErr := framework.NewRequestErrorMsg("invalid_token", http.StatusUnauthorized)
				return framework.RespondError(ctx, w, frameworkErr)
			}
			return handler(ctx, w, r)
		}
	}
}
