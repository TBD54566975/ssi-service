package resolve

import (
	"bufio"
	"context"
	"io"
	"net/http"

	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
)

// universalResolver is a struct that implements the Resolver interface. It calls the universal resolver endpoint
// to resolve any DID according to https://github.com/decentralized-identity/universal-resolver.
type universalResolver struct {
	Client *http.Client
	URL    string
}

func newUniversalResolver(url string) (*universalResolver, error) {
	if url == "" {
		return nil, errors.New("universal resolver URL cannot be empty")
	}
	return &universalResolver{
		Client: http.DefaultClient,
		URL:    url,
	}, nil
}

// Resolve results resolution results by doing a GET on <URL>/1.0.identifiers/<did>.
func (ur universalResolver) Resolve(ctx context.Context, did string, _ ...didsdk.ResolutionOptions) (*didsdk.ResolutionResult, error) {
	url := ur.URL + "/1.0/identifiers/" + did
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "creating request")
	}

	resp, err := ur.Client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "performing http get")
	}

	respBody, err := io.ReadAll(bufio.NewReader(resp.Body))
	if err != nil {
		return nil, err
	}
	var result didsdk.ResolutionResult
	if err = json.Unmarshal(respBody, &result); err != nil {
		return nil, errors.Wrap(err, "unmarshalling JSON")
	}
	return &result, nil
}
