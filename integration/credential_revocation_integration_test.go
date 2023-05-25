package integration

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/status"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
)

var credentialRevocationContext = NewTestContext("CredentialRevocation")

func TestRevocationCreateIssuerDIDKeyIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	didKeyOutput, err := CreateDIDKey()
	assert.NoError(t, err)

	issuerDID, err := getJSONElement(didKeyOutput, "$.did.id")
	assert.NoError(t, err)
	assert.Contains(t, issuerDID, "did:key")
	SetValue(credentialRevocationContext, "issuerDID", issuerDID)

	issuerKID, err := getJSONElement(didKeyOutput, "$.did.verificationMethod[0].id")
	assert.NoError(t, err)
	assert.NotEmpty(t, issuerKID)
	SetValue(credentialRevocationContext, "issuerKID", issuerKID)
}

func TestRevocationCreateSchemaIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	output, err := CreateKYCSchema()
	assert.NoError(t, err)

	schemaID, err := getJSONElement(output, "$.id")
	assert.NoError(t, err)
	assert.NotEmpty(t, schemaID)
	SetValue(credentialRevocationContext, "schemaID", schemaID)
}

func TestRevocationCreateVerifiableCredentialIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	issuerDID, err := GetValue(credentialRevocationContext, "issuerDID")
	assert.NoError(t, err)
	assert.NotEmpty(t, issuerDID)

	issuerKID, err := GetValue(credentialRevocationContext, "issuerKID")
	assert.NoError(t, err)
	assert.NotEmpty(t, issuerKID)

	schemaID, err := GetValue(credentialRevocationContext, "schemaID")
	assert.NoError(t, err)
	assert.NotEmpty(t, schemaID)

	vcOutput, err := CreateVerifiableCredentialWithStatus(credInputParams{
		IssuerID:  issuerDID.(string),
		IssuerKID: issuerKID.(string),
		SchemaID:  schemaID.(string),
		SubjectID: issuerDID.(string),
	}, true, false)
	assert.NoError(t, err)
	assert.NotEmpty(t, vcOutput)

	cred, err := getJSONElement(vcOutput, "$.credential")
	assert.NoError(t, err)
	assert.NotEmpty(t, cred)
	SetValue(credentialRevocationContext, "cred", cred)

	credStatusURL, err := getJSONElement(vcOutput, "$.credential.credentialStatus.id")
	assert.NoError(t, err)
	assert.NotEmpty(t, credStatusURL)
	assert.Contains(t, credStatusURL, "http")
	SetValue(credentialRevocationContext, "credStatusURL", credStatusURL)

	statusListCredentialURL, err := getJSONElement(vcOutput, "$.credential.credentialStatus.statusListCredential")
	assert.NoError(t, err)
	assert.NotEmpty(t, statusListCredentialURL)
	assert.Contains(t, statusListCredentialURL, "http")
	SetValue(credentialRevocationContext, "statusListCredentialURL", statusListCredentialURL)

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

func TestRevocationValidateCredentialInStatusListIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	credJSON, err := GetValue(credentialRevocationContext, "cred")
	assert.NoError(t, err)
	assert.NotEmpty(t, credJSON)

	var vc credential.VerifiableCredential
	err = json.Unmarshal([]byte(credJSON.(string)), &vc)
	assert.NoError(t, err)
	assert.NotEmpty(t, vc)

	statusListCredentialURL, err := GetValue(credentialRevocationContext, "statusListCredentialURL")
	assert.NoError(t, err)
	assert.NotEmpty(t, statusListCredentialURL)

	credStatusListCredentialOutput, err := get(statusListCredentialURL.(string))
	assert.NoError(t, err)
	assert.NotEmpty(t, credStatusListCredentialOutput)

	credStatusListCredentialJSON, err := getJSONElement(credStatusListCredentialOutput, "$.credential")
	assert.NoError(t, err)
	assert.NotEmpty(t, credStatusListCredentialJSON)

	var vcStatusList credential.VerifiableCredential
	err = json.Unmarshal([]byte(credStatusListCredentialJSON), &vcStatusList)
	assert.NoError(t, err)
	assert.NotEmpty(t, vcStatusList)

	// Validate the StatusListIndex in flipped in the credStatusList
	valid, err := status.ValidateCredentialInStatusList(vc, vcStatusList)
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestRevocationUnRevokeCredential(t *testing.T) {
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
	assert.Equal(t, "true", revoked)

	revokedOutput, err := put(credStatusURL.(string), `{"revoked":false}`)
	assert.NoError(t, err)

	revoked, err = getJSONElement(revokedOutput, "$.revoked")
	assert.NoError(t, err)
	assert.Equal(t, "false", revoked)

	credStatusOutput, err = get(credStatusURL.(string))
	assert.NoError(t, err)
	assert.NotEmpty(t, credStatusOutput)

	revoked, err = getJSONElement(credStatusOutput, "$.revoked")
	assert.NoError(t, err)
	assert.Equal(t, "false", revoked)
}
