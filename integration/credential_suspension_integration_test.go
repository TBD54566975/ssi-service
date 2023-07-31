package integration

import (
	"fmt"
	"testing"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/status"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
)

var credentialSuspensionContext = NewTestContext("CredentialSuspension")

func TestSuspensionCreateIssuerDIDKeyIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	didKeyOutput, err := CreateDIDKey()
	assert.NoError(t, err)

	issuerDID, err := getJSONElement(didKeyOutput, "$.did.id")
	assert.NoError(t, err)
	assert.Contains(t, issuerDID, "did:key")
	SetValue(credentialSuspensionContext, "issuerDID", issuerDID)

	verificationMethodID, err := getJSONElement(didKeyOutput, "$.did.verificationMethod[0].id")
	assert.NoError(t, err)
	assert.NotEmpty(t, verificationMethodID)
	SetValue(credentialSuspensionContext, "verificationMethodID", verificationMethodID)
}

func TestSuspensionCreateSchemaIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	output, err := CreateKYCSchema()
	assert.NoError(t, err)

	schemaID, err := getJSONElement(output, "$.id")
	assert.NoError(t, err)
	assert.NotEmpty(t, schemaID)
	SetValue(credentialSuspensionContext, "schemaID", schemaID)
}

func TestSuspensionCreateVerifiableCredentialIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	issuerDID, err := GetValue(credentialSuspensionContext, "issuerDID")
	assert.NoError(t, err)
	assert.NotEmpty(t, issuerDID)

	verificationMethodID, err := GetValue(credentialSuspensionContext, "verificationMethodID")
	assert.NoError(t, err)
	assert.NotEmpty(t, verificationMethodID)

	schemaID, err := GetValue(credentialSuspensionContext, "schemaID")
	assert.NoError(t, err)
	assert.NotEmpty(t, schemaID)

	vcOutput, err := CreateVerifiableCredential(credInputParams{
		IssuerID:             issuerDID.(string),
		VerificationMethodID: verificationMethodID.(string),
		SchemaID:             schemaID.(string),
		SubjectID:            issuerDID.(string),
		Suspendable:          true,
	})
	assert.NoError(t, err)
	assert.NotEmpty(t, vcOutput)

	cred, err := getJSONElement(vcOutput, "$.credential")
	assert.NoError(t, err)
	assert.NotEmpty(t, cred)
	SetValue(credentialSuspensionContext, "cred", cred)

	credStatusURL, err := getJSONElement(vcOutput, "$.credential.credentialStatus.id")
	assert.NoError(t, err)
	assert.NotEmpty(t, credStatusURL)
	assert.Contains(t, credStatusURL, "http")
	SetValue(credentialSuspensionContext, "credStatusURL", credStatusURL)

	fmt.Print(credStatusURL)

	statusListCredentialURL, err := getJSONElement(vcOutput, "$.credential.credentialStatus.statusListCredential")
	assert.NoError(t, err)
	assert.NotEmpty(t, statusListCredentialURL)
	assert.Contains(t, statusListCredentialURL, "http")
	SetValue(credentialSuspensionContext, "statusListCredentialURL", statusListCredentialURL)

	credStatusListCredentialOutput, err := get(statusListCredentialURL)
	assert.NoError(t, err)
	assert.NotEmpty(t, credStatusListCredentialOutput)

	encodedListOriginal, err := getJSONElement(credStatusListCredentialOutput, "$.credential.credentialSubject.encodedList")
	assert.NoError(t, err)
	assert.NotEmpty(t, encodedListOriginal)
	SetValue(credentialSuspensionContext, "encodedListOriginal", encodedListOriginal)
}

func TestSuspensionCheckStatusIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	credStatusURL, err := GetValue(credentialSuspensionContext, "credStatusURL")
	assert.NoError(t, err)
	assert.NotEmpty(t, credStatusURL)

	credStatusOutput, err := get(credStatusURL.(string))
	assert.NoError(t, err)
	assert.NotEmpty(t, credStatusOutput)

	suspended, err := getJSONElement(credStatusOutput, "$.suspended")
	assert.NoError(t, err)
	assert.Equal(t, "false", suspended)

	suspendedOutput, err := put(credStatusURL.(string), getJSONFromFile("suspended-input.json"))
	assert.NoError(t, err)

	suspended, err = getJSONElement(suspendedOutput, "$.suspended")
	assert.NoError(t, err)
	assert.Equal(t, "true", suspended)

	credStatusOutput, err = get(credStatusURL.(string))
	assert.NoError(t, err)
	assert.NotEmpty(t, credStatusOutput)

	suspended, err = getJSONElement(credStatusOutput, "$.suspended")
	assert.NoError(t, err)
	assert.Equal(t, "true", suspended)
}

func TestSuspensionCheckStatusListCredentialIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	statusListCredentialURL, err := GetValue(credentialSuspensionContext, "statusListCredentialURL")
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

	encodedListOriginal, err := GetValue(credentialSuspensionContext, "encodedListOriginal")
	assert.NoError(t, err)
	assert.NotEmpty(t, encodedListOriginal)

	assert.NotEqual(t, encodedListOriginal.(string), encodedList)
}

func TestSuspensionValidateCredentialInStatusListIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	credJSON, err := GetValue(credentialSuspensionContext, "cred")
	assert.NoError(t, err)
	assert.NotEmpty(t, credJSON)

	var vc credential.VerifiableCredential
	err = json.Unmarshal([]byte(credJSON.(string)), &vc)
	assert.NoError(t, err)
	assert.NotEmpty(t, vc)

	statusListCredentialURL, err := GetValue(credentialSuspensionContext, "statusListCredentialURL")
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

func TestSuspensionUnSuspendCredential(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	credStatusURL, err := GetValue(credentialSuspensionContext, "credStatusURL")
	assert.NoError(t, err)
	assert.NotEmpty(t, credStatusURL)

	credStatusOutput, err := get(credStatusURL.(string))
	assert.NoError(t, err)
	assert.NotEmpty(t, credStatusOutput)

	suspended, err := getJSONElement(credStatusOutput, "$.suspended")
	assert.NoError(t, err)
	assert.Equal(t, "true", suspended)

	suspendedOutput, err := put(credStatusURL.(string), `{"suspended":false}`)
	assert.NoError(t, err)

	suspended, err = getJSONElement(suspendedOutput, "$.suspended")
	assert.NoError(t, err)
	assert.Equal(t, "false", suspended)

	credStatusOutput, err = get(credStatusURL.(string))
	assert.NoError(t, err)
	assert.NotEmpty(t, credStatusOutput)

	suspended, err = getJSONElement(credStatusOutput, "$.suspended")
	assert.NoError(t, err)
	assert.Equal(t, "false", suspended)
}
