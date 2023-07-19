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

	verificationMethodID, err := getJSONElement(didKeyOutput, "$.did.verificationMethod[0].id")
	assert.NoError(t, err)
	assert.NotEmpty(t, verificationMethodID)

	schemaOutput, err := CreateKYCSchema()
	assert.NoError(t, err)

	schemaID, err := getJSONElement(schemaOutput, "$.id")
	assert.NoError(t, err)
	assert.NotEmpty(t, schemaID)

	vcOutput, err := CreateVerifiableCredential(credInputParams{IssuerID: issuerDID, VerificationMethodID: verificationMethodID, SchemaID: schemaID, SubjectID: issuerDID, Revocable: true})
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

	verificationMethodID, err := getJSONElement(didKeyOutput, "$.did.verificationMethod[0].id")
	assert.NoError(t, err)
	assert.NotEmpty(t, verificationMethodID)

	schemaOutput, err := CreateKYCSchema()
	assert.NoError(t, err)

	schemaID, err := getJSONElement(schemaOutput, "$.id")
	assert.NoError(t, err)
	assert.NotEmpty(t, schemaID)

	vcOutput, err := CreateVerifiableCredential(credInputParams{IssuerID: issuerDID, VerificationMethodID: verificationMethodID, SchemaID: schemaID, SubjectID: issuerDID, Revocable: true})
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

	vcOutputTwo, err := CreateVerifiableCredential(credInputParams{IssuerID: issuerDID, VerificationMethodID: verificationMethodID, SchemaID: schemaID, SubjectID: issuerDID, Revocable: true})
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

	verificationMethodID, err := getJSONElement(didKeyOutput, "$.did.verificationMethod[0].id")
	assert.NoError(t, err)
	assert.NotEmpty(t, verificationMethodID)

	schemaOutput, err := CreateKYCSchema()
	assert.NoError(t, err)

	schemaID, err := getJSONElement(schemaOutput, "$.id")
	assert.NoError(t, err)
	assert.NotEmpty(t, schemaID)

	const vcCount = 100
	credStatusListIndexes := make([]string, 0, vcCount)

	var wg sync.WaitGroup
	wg.Add(vcCount)

	var m sync.Mutex
	credStatusListURLSet := make(map[string]struct{}, vcCount)

	for i := 0; i < vcCount; i++ {
		go func() {
			defer wg.Done()

			vcOutput, err := CreateVerifiableCredential(credInputParams{IssuerID: issuerDID, VerificationMethodID: verificationMethodID, SchemaID: schemaID, SubjectID: issuerDID, Revocable: true})

			// We're hammering the DB, so some calls might fail due to internal timeouts or similar. Upon failure, we
			// shouldn't check any assertions, since we know they'll fail.
			if err != nil {
				return
			}
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

			m.Lock()
			credStatusListIndexes = append(credStatusListIndexes, credStatusListIndex)
			credStatusListURLSet[credStatusListURL] = struct{}{}
			m.Unlock()
		}()
	}

	wg.Wait()

	assert.Len(t, credStatusListURLSet, 1)
	assert.True(t, areElementsUnique(credStatusListIndexes), "elements should be unique")
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
