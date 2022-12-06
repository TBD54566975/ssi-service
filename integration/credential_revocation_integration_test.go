package integration

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var credentialRevocationContext = NewTestContext("CredentialRevocation")

func TestRevocationCreateIssuerDIDKeyIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	didKeyOutput, err := CreateDIDKey()
	assert.NoError(t, err)

	issuerDID, err := getJSONElement(didKeyOutput, "$.did.id")
	SetValue(credentialRevocationContext, "issuerDID", issuerDID)

	assert.NoError(t, err)
	assert.Contains(t, issuerDID, "did:key")

}

func TestRevocationCreateSchemaIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	output, err := CreateKYCSchema()
	assert.NoError(t, err)

	schemaID, err := getJSONElement(output, "$.id")
	SetValue(credentialRevocationContext, "schemaID", schemaID)

	assert.NoError(t, err)
	assert.NotEmpty(t, schemaID)
}

func TestRevocationCreateVerifiableCredentialIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	issuerDID, err := GetValue(credentialRevocationContext, "issuerDID")
	assert.NoError(t, err)
	assert.NotEmpty(t, issuerDID)

	schemaID, err := GetValue(credentialRevocationContext, "schemaID")
	assert.NoError(t, err)
	assert.NotEmpty(t, schemaID)

	vcOutput, err := CreateVerifiableCredential(issuerDID.(string), schemaID.(string), true)
	assert.NoError(t, err)
	assert.NotEmpty(t, vcOutput)

	credStatusURL, err := getJSONElement(vcOutput, "$.credential.credentialStatus.id")
	SetValue(credentialRevocationContext, "credStatusURL", credStatusURL)
	assert.NoError(t, err)
	assert.NotEmpty(t, credStatusURL)
	assert.Contains(t, credStatusURL, "http")

	statusListCredentialURL, err := getJSONElement(vcOutput, "$.credential.credentialStatus.statusListCredential")
	SetValue(credentialRevocationContext, "statusListCredentialURL", statusListCredentialURL)
	assert.NoError(t, err)
	assert.NotEmpty(t, statusListCredentialURL)
	assert.Contains(t, statusListCredentialURL, "http")

	credStatusListCredentialOutput, err := get(statusListCredentialURL)
	assert.NoError(t, err)
	assert.NotEmpty(t, credStatusListCredentialOutput)

	encodedListOriginal, err := getJSONElement(credStatusListCredentialOutput, "$.credential.credentialSubject.encodedList")
	assert.NoError(t, err)
	assert.NotEmpty(t, encodedListOriginal)
	SetValue(credentialRevocationContext, "encodedListOriginal", encodedListOriginal)

}

func TestRevocationCheckStatusIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	credStatusURL, err := GetValue(credentialRevocationContext, "credStatusURL")
	assert.NoError(t, err)
	assert.NotEmpty(t, credStatusURL)

	credStatusOutput, err := get(credStatusURL.(string))
	assert.NoError(t, err)
	assert.NotEmpty(t, credStatusOutput)

	revoked, err := getJSONElement(credStatusOutput, "$.revoked")
	assert.NoError(t, err)
	assert.Equal(t, "false", revoked)

	revokedOutput, err := put(credStatusURL.(string), getJSONFromFile("revoked-input.json"))
	assert.NoError(t, err)

	revoked, err = getJSONElement(revokedOutput, "$.revoked")
	assert.NoError(t, err)
	assert.Equal(t, "true", revoked)

	credStatusOutput, err = get(credStatusURL.(string))
	assert.NoError(t, err)
	assert.NotEmpty(t, credStatusOutput)

	revoked, err = getJSONElement(credStatusOutput, "$.revoked")
	assert.NoError(t, err)
	assert.Equal(t, "true", revoked)
}

func TestRevocationCheckStatusListCredentialIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	statusListCredentialURL, err := GetValue(credentialRevocationContext, "statusListCredentialURL")
	assert.NoError(t, err)
	assert.NotEmpty(t, statusListCredentialURL)

	credStatusListCredentialOutput, err := get(statusListCredentialURL.(string))
	assert.NoError(t, err)
	assert.NotEmpty(t, credStatusListCredentialOutput)

	statusListType, err := getJSONElement(credStatusListCredentialOutput, "$.credential.credentialSubject.type")
	assert.NoError(t, err)
	assert.NotEmpty(t, statusListType)
	assert.Equal(t, "StatusList2021", statusListType)

	encodedList, err := getJSONElement(credStatusListCredentialOutput, "$.credential.credentialSubject.encodedList")
	assert.NoError(t, err)
	assert.NotEmpty(t, encodedList)

	encodedListOriginal, err := GetValue(credentialRevocationContext, "encodedListOriginal")
	assert.NoError(t, err)
	assert.NotEmpty(t, encodedListOriginal)

	assert.NotEqual(t, encodedListOriginal.(string), encodedList)
}
