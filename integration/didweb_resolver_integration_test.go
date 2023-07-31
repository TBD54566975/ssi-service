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
	didWebOutput, err := put(endpoint+version+"dids/web", `{ "keyType":"Ed25519", "options": {"didWebId":"did:web:i-made-up-this.website"}}`)
	assert.NoError(t, err)

	did, err := getJSONElement(didWebOutput, "$.did.id")
	assert.NoError(t, err)
	resolvedOutput, err := ResolveDID(did)
	assert.NoError(t, err)

	_, err = getJSONElement(resolvedOutput, "$.didResolutionMetadata.Error")
	assert.ErrorContains(t, err, "key error: Error not found in object")

	didDocumentID, err := getJSONElement(resolvedOutput, "$.didDocument.id")
	assert.NoError(t, err)
	assert.Equal(t, "did:web:i-made-up-this.website", didDocumentID)

}
