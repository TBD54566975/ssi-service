package resolve

import (
	"bufio"
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
	Resolve(did string, opts ...didsdk.ResolutionOptions) (*didsdk.DIDResolutionResult, error)
}

// Resolve results resolution results by doing a GET on <URL>/1.0.identifiers/<did>.
func (ur UniversalResolver) Resolve(did string, _ ...didsdk.ResolutionOptions) (*didsdk.DIDResolutionResult, error) {
	resp, err := ur.Client.Get(ur.URL + "/1.0/identifiers/" + did)
	if err != nil {
		return nil, errors.Wrap(err, "performing http get")
	}

	respBody, err := io.ReadAll(bufio.NewReader(resp.Body))
	if err != nil {
		return nil, err
	}
	var result ResolutionResult
	err = json.Unmarshal(respBody, &result)
	if err != nil {
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
