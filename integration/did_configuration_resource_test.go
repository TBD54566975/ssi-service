package integration

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDIDResourceIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	didKeyOutput, err := CreateDIDKey()
	assert.NoError(t, err)
	verificationMethodID, err := getJSONElement(didKeyOutput, "$.did.verificationMethod[0].id")
	assert.NoError(t, err)
	didKeyID, err := getJSONElement(didKeyOutput, "$.did.id")
	assert.NoError(t, err)

	didConfigOutput, err := CreateDIDConfigurationResource(didConfigurationResourceParams{
		IssuerDID:            didKeyID,
		VerificationMethodID: verificationMethodID,
	})
	assert.NoError(t, err)
	linkedDIDs, err := getJSONElement(didConfigOutput, "$.didConfiguration.linked_dids")
	assert.NoError(t, err)
	assert.Regexp(t, regexp.MustCompilePOSIX(`^\[[[:ascii:]]*\.[[:ascii:]]*\.[[:ascii:]]*]$`), linkedDIDs)
}
