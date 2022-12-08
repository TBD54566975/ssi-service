package integration

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestResolveDIDWebIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	//A .wellKnown exists at https://identity.foundation/.well-known/did.json
	didWebOutput, err := put(endpoint+version+"dids/web", `{ "keyType":"Ed25519", "didWebId":"did:web:identity.foundation"}`)
	assert.NoError(t, err)

	did, err := getJSONElement(didWebOutput, "$.did.id")

	resolvedOutput, err := ResolveDID(did)
	assert.NoError(t, err)

	didError, err := getJSONElement(resolvedOutput, "$.didResolutionMetadata.Error")
	assert.NoError(t, err)
	assert.Equal(t, "<nil>", didError)

	didDocumentID, err := getJSONElement(resolvedOutput, "$.didDocument.id")
	assert.NoError(t, err)
	assert.Equal(t, "did:web:identity.foundation", didDocumentID)
}
