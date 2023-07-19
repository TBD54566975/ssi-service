package integration

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBatchCreateDIDKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	didKeyOutput, err := BatchCreateDIDKeys()
	assert.NoError(t, err)

	issuedDIDs, err := getJSONElement(didKeyOutput, "$.dids[*].id")
	assert.NoError(t, err)
	assert.Equal(t, 7, strings.Count(issuedDIDs, "did:key"))
}
