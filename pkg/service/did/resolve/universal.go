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

// UniversalResolver is a struct that implements the Resolver interface. It calls the universal resolver endpoint
// to resolve any DID according to https://github.com/decentralized-identity/universal-resolver.
type UniversalResolver struct {
	Client http.Client
	URL    string
}

type Resolver interface {
	Resolve(ctx context.Context, did string, opts ...didsdk.ResolutionOptions) (*didsdk.DIDResolutionResult, error)
}

// Resolve results resolution results by doing a GET on <URL>/1.0.identifiers/<did>.
func (ur UniversalResolver) Resolve(ctx context.Context, did string, _ ...didsdk.ResolutionOptions) (*didsdk.DIDResolutionResult, error) {
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
	var result ResolutionResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, errors.Wrap(err, "unmarshalling JSON")
	}
	return &didsdk.DIDResolutionResult{
		DIDResolutionMetadata: result.DIDResolutionMetadata,
		DIDDocument:           result.DIDDocument,
		DIDDocumentMetadata:   result.DIDDocumentMetadata,
	}, nil
}

type ResolutionResult struct {
	Context                      any `json:"@context"`
	didsdk.DIDResolutionMetadata `json:"didResolutionMetadata"`
	didsdk.DIDDocument           `json:"didDocument"`
	didsdk.DIDDocumentMetadata   `json:"didDocumentMetadata"`
}

// LocalResolver is an implementation of Resolver that passes through the parameters into the sdk implementation that
// resolves DIDs. This is done because, when this is being written, the didsdk.Resolution interface does not let callers
// pass in their own context.
type LocalResolver struct {
	*didsdk.Resolver
}

func (lr LocalResolver) Resolve(_ context.Context, did string, opts ...didsdk.ResolutionOptions) (*didsdk.DIDResolutionResult, error) {
	return lr.Resolver.Resolve(did, opts...)
}
