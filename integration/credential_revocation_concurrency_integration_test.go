package integration

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateRevocationVerifiableCredentialIntegration(t *testing.T) {
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

	vcOutput, err := CreateVerifiableCredential(credInputParams{IssuerID: issuerDID, SchemaID: schemaID, SubjectID: issuerDID}, true)
	assert.NoError(t, err)
	assert.NotEmpty(t, vcOutput)

	credStatusURL, err := getJSONElement(vcOutput, "$.credential.credentialStatus.id")
	assert.NoError(t, err)
	assert.NotEmpty(t, credStatusURL)
	assert.Contains(t, credStatusURL, "http")

	credStatusListURL, err := getJSONElement(vcOutput, "$.credential.credentialStatus.statusListCredential")
	assert.NoError(t, err)
	assert.NotEmpty(t, credStatusListURL)
	assert.Contains(t, credStatusListURL, "http")
}

func TestCreateRevocationVerifiableCredentialShareStatusListIntegration(t *testing.T) {
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

	vcOutput, err := CreateVerifiableCredential(credInputParams{IssuerID: issuerDID, SchemaID: schemaID, SubjectID: issuerDID}, true)
	assert.NoError(t, err)
	assert.NotEmpty(t, vcOutput)

	credStatusURL, err := getJSONElement(vcOutput, "$.credential.credentialStatus.id")
	assert.NoError(t, err)
	assert.NotEmpty(t, credStatusURL)
	assert.Contains(t, credStatusURL, "http")

	credStatusListURL, err := getJSONElement(vcOutput, "$.credential.credentialStatus.statusListCredential")
	assert.NoError(t, err)
	assert.NotEmpty(t, credStatusListURL)
	assert.Contains(t, credStatusListURL, "http")

	vcOutputTwo, err := CreateVerifiableCredential(credInputParams{IssuerID: issuerDID, SchemaID: schemaID, SubjectID: issuerDID}, true)
	assert.NoError(t, err)
	assert.NotEmpty(t, vcOutputTwo)

	credStatusURLTwo, err := getJSONElement(vcOutput, "$.credential.credentialStatus.id")
	assert.NoError(t, err)
	assert.NotEmpty(t, credStatusURLTwo)
	assert.Contains(t, credStatusURLTwo, "http")

	credStatusListURLTwo, err := getJSONElement(vcOutput, "$.credential.credentialStatus.statusListCredential")
	assert.NoError(t, err)
	assert.NotEmpty(t, credStatusListURLTwo)
	assert.Contains(t, credStatusListURLTwo, "http")

	assert.Equal(t, credStatusListURLTwo, credStatusListURL)
}

func TestConcurrencyRevocationVerifiableCredentialIntegration(t *testing.T) {
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

	const vcCount = 200
	credStatusListIndexes := make([]string, vcCount)

	var wg sync.WaitGroup
	wg.Add(vcCount)

	for i := 0; i < vcCount; i++ {
		go func(i int) {
			defer wg.Done()

			vcOutput, err := CreateVerifiableCredential(credInputParams{IssuerID: issuerDID, SchemaID: schemaID, SubjectID: issuerDID}, true)
			assert.NoError(t, err)
			assert.NotEmpty(t, vcOutput)

			credStatusURL, err := getJSONElement(vcOutput, "$.credential.credentialStatus.id")
			assert.NoError(t, err)
			assert.NotEmpty(t, credStatusURL)
			assert.Contains(t, credStatusURL, "http")

			credStatusListURL, err := getJSONElement(vcOutput, "$.credential.credentialStatus.statusListCredential")
			assert.NoError(t, err)
			assert.NotEmpty(t, credStatusListURL)
			assert.Contains(t, credStatusListURL, "http")

			credStatusListIndex, err := getJSONElement(vcOutput, "$.credential.credentialStatus.statusListIndex")
			assert.NoError(t, err)
			assert.NotEmpty(t, credStatusListIndex)

			credStatusListIndexes[i] = credStatusListIndex
		}(i)
	}

	wg.Wait()

	assert.True(t, areElementsUnique(credStatusListIndexes))
}

func areElementsUnique(arr []string) bool {
	m := make(map[string]bool)

	for _, v := range arr {
		if m[v] {
			return false
		}
		m[v] = true
	}

	return true
}
