package resolution

import (
	"bufio"
	"context"
	"io"
	"net/http"

	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/resolution"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// universalResolver is a struct that implements the Resolver interface. It calls the universal resolver endpoint
// to resolve any DID according to https://github.com/decentralized-identity/universal-resolver.
type universalResolver struct {
	client           *http.Client
	url              string
	supportedMethods []didsdk.Method
}

var _ resolution.Resolver = (*universalResolver)(nil)

func newUniversalResolver(url string) (*universalResolver, error) {
	if url == "" {
		return nil, errors.New("universal resolver url cannot be empty")
	}
	return &universalResolver{
		client: &http.Client{Transport: otelhttp.NewTransport(http.DefaultTransport)},
		url:    url,
	}, nil
}

// Resolve results resolution results by doing a GET on <url>/1.0.identifiers/<did>.
func (ur *universalResolver) Resolve(ctx context.Context, did string, _ ...resolution.ResolutionOption) (*resolution.ResolutionResult, error) {
	url := ur.url + "/1.0/identifiers/" + did
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "creating request")
	}

	resp, err := ur.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "performing http get")
	}

	respBody, err := io.ReadAll(bufio.NewReader(resp.Body))
	if err != nil {
		return nil, err
	}
	var result resolution.ResolutionResult
	if err = json.Unmarshal(respBody, &result); err != nil {
		return nil, errors.Wrap(err, "unmarshalling JSON")
	}
	return &result, nil
}

// Methods returns the methods that this resolver supports
// as per https://github.com/decentralized-identity/universal-resolver/blob/main/swagger/api.yml#L121
func (ur *universalResolver) Methods() []didsdk.Method {
	// check if we've cached the methods
	if len(ur.supportedMethods) > 0 {
		return ur.supportedMethods
	}

	url := ur.url + "/1.0/methods"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		logrus.WithError(err).Error("Failed to create request for universal resolver methods")
	}

	resp, err := ur.client.Do(req)
	if err != nil {
		logrus.WithError(err).Error("Failed to perform http get for universal resolver methods")
		return nil
	}

	respBody, err := io.ReadAll(bufio.NewReader(resp.Body))
	if err != nil {
		logrus.WithError(err).Error("Failed to read response body for universal resolver methods")
		return nil
	}
	var methods []didsdk.Method
	if err = json.Unmarshal(respBody, &methods); err != nil {
		logrus.WithError(err).Error("Failed to unmarshal response body for universal resolver methods")
		return nil
	}

	// update the method cache
	ur.supportedMethods = methods
	return methods
}
