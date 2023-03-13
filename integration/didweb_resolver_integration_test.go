package integration

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveDIDWebIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	// A .well-known file exists at https://tbd.website/.well-known/did.json
	didWebOutput, err := put(endpoint+version+"dids/web", `{ "keyType":"Ed25519", "didWebId":"did:web:tbd.website"}`)
	assert.NoError(t, err)

	did, err := getJSONElement(didWebOutput, "$.did.id")
	assert.NoError(t, err)
	resolvedOutput, err := ResolveDID(did)
	assert.NoError(t, err)

	didError, err := getJSONElement(resolvedOutput, "$.didResolutionMetadata.Error")
	assert.NoError(t, err)
	assert.Equal(t, "<nil>", didError)

	didDocumentID, err := getJSONElement(resolvedOutput, "$.didDocument.id")
	assert.NoError(t, err)
	assert.Equal(t, "did:web:tbd.website", didDocumentID)
}
