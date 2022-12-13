package integration

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

// This test creates several DID keys and verifiable credentials, then concurrently updates the credential status, and finally checks that the revocation was successful and that each credential has a status list URL.
func TestRevocationConcurrencyCreateIssuerDIDKeyIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	didKeyOutput, err := CreateDIDKey()
	assert.NoError(t, err)

	issuerDID, err := getJSONElement(didKeyOutput, "$.did.id")
	assert.NoError(t, err)
	assert.Contains(t, issuerDID, "did:key")

	schemaOutput, err := CreateKYCSchema()
	assert.NoError(t, err)

	schemaID, err := getJSONElement(schemaOutput, "$.id")
	assert.NoError(t, err)
	assert.NotEmpty(t, schemaID)

	var vcStatusURLs []string
	var vcStatusListURLs []string
	const vcCount = 20
	for i := 0; i < vcCount; i++ {
		vcOutput, err := CreateVerifiableCredential(issuerDID, schemaID, true)
		assert.NoError(t, err)
		assert.NotEmpty(t, vcOutput)

		credStatusURL, err := getJSONElement(vcOutput, "$.credential.credentialStatus.id")
		assert.NoError(t, err)
		assert.NotEmpty(t, credStatusURL)
		assert.Contains(t, credStatusURL, "http")
		vcStatusURLs = append(vcStatusURLs, credStatusURL)

		credStatusListURL, err := getJSONElement(vcOutput, "$.credential.credentialStatus.statusListCredential")
		assert.NoError(t, err)
		assert.NotEmpty(t, credStatusListURL)
		assert.Contains(t, credStatusListURL, "http")
		vcStatusListURLs = append(vcStatusListURLs, credStatusListURL)
	}

	sliceLength := len(vcStatusURLs)
	var wg sync.WaitGroup
	wg.Add(sliceLength)

	for i := 0; i < sliceLength; i++ {
		go func(i int) {
			defer wg.Done()
			revokedOutput, err := put(vcStatusURLs[i], getJSONFromFile("revoked-input.json"))
			assert.NoError(t, err)
			revoked, err := getJSONElement(revokedOutput, "$.revoked")
			assert.NoError(t, err)
			assert.Equal(t, "true", revoked)
		}(i)
	}

	wg.Wait()

	var statusListSet = make(map[string]bool)
	for i := 0; i < vcCount; i++ {
		revokedOutput, err := get(vcStatusURLs[i])
		assert.NoError(t, err)
		revoked, err := getJSONElement(revokedOutput, "$.revoked")
		assert.NoError(t, err)
		assert.Equal(t, "true", revoked)

		statusListCred, err := get(vcStatusListURLs[i])
		assert.NoError(t, err)
		assert.NotEmpty(t, statusListCred)
		statusListSet[vcStatusListURLs[i]] = true
	}

	assert.Equal(t, vcCount, len(statusListSet))
}
