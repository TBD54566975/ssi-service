package integration

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did/key"
	"github.com/stretchr/testify/assert"

	"github.com/tbd54566975/ssi-service/pkg/service/operation/storage"
)

var didWebContext = NewTestContext("DIDWeb")

func TestCreateIssuerDIDWebIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	didWebOutput, err := CreateDIDWeb()
	assert.NoError(t, err)

	issuerDID, err := getJSONElement(didWebOutput, "$.did.id")
	assert.NoError(t, err)
	assert.Contains(t, issuerDID, "did:web")
	SetValue(didWebContext, "issuerDID", issuerDID)

	verificationMethodID, err := getJSONElement(didWebOutput, "$.did.verificationMethod[0].id")
	assert.NoError(t, err)
	assert.NotEmpty(t, verificationMethodID)
	SetValue(didWebContext, "verificationMethodID", verificationMethodID)
}

func TestListDIDWebIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	listWebDIDsOutput, err := ListWebDIDs()
	assert.NoError(t, err)

	issuerDID, err := GetValue(didWebContext, "issuerDID")
	assert.NoError(t, err)
	assert.NotEmpty(t, issuerDID)

	assert.Contains(t, listWebDIDsOutput, issuerDID)
}

func TestCreateAliceDIDKeyForDIDWebIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	applicantPrivKey, applicantDIDKey, err := key.GenerateDIDKey(crypto.Ed25519)
	assert.NoError(t, err)
	assert.NotEmpty(t, applicantPrivKey)
	assert.NotEmpty(t, applicantDIDKey)

	applicantDID, err := applicantDIDKey.Expand()
	assert.NoError(t, err)
	assert.NotEmpty(t, applicantDID)

	aliceDID := applicantDID.ID
	assert.Contains(t, aliceDID, "did:key")
	SetValue(didWebContext, "aliceDID", aliceDID)

	aliceKID := applicantDID.VerificationMethod[0].ID
	assert.NotEmpty(t, aliceKID)
	SetValue(didWebContext, "aliceKID", aliceKID)
	SetValue(didWebContext, "aliceDIDPrivateKey", applicantPrivKey)
}

func TestDIDWebCreateSchemaIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	output, err := CreateKYCSchema()
	assert.NoError(t, err)

	schemaID, err := getJSONElement(output, "$.id")
	assert.NoError(t, err)
	assert.NotEmpty(t, schemaID)
	SetValue(didWebContext, "schemaID", schemaID)
}

func TestDIDWebCreateVerifiableCredentialIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	issuerDID, err := GetValue(didWebContext, "issuerDID")
	assert.NoError(t, err)
	assert.NotEmpty(t, issuerDID)

	verificationMethodID, err := GetValue(didWebContext, "verificationMethodID")
	assert.NoError(t, err)
	assert.NotEmpty(t, verificationMethodID)

	schemaID, err := GetValue(didWebContext, "schemaID")
	assert.NoError(t, err)
	assert.NotEmpty(t, schemaID)

	vcOutput, err := CreateVerifiableCredential(credInputParams{
		IssuerID:             issuerDID.(string),
		VerificationMethodID: verificationMethodID.(string),
		SchemaID:             schemaID.(string),
		SubjectID:            issuerDID.(string),
	})
	assert.NoError(t, err)
	assert.NotEmpty(t, vcOutput)

	credentialJWT, err := getJSONElement(vcOutput, "$.credentialJwt")
	assert.NoError(t, err)
	assert.NotEmpty(t, credentialJWT)
	SetValue(didWebContext, "credentialJWT", credentialJWT)
}

func TestDIDWebCreateCredentialManifestIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	issuerDID, err := GetValue(didWebContext, "issuerDID")
	assert.NoError(t, err)
	assert.NotEmpty(t, issuerDID)

	verificationMethodID, err := GetValue(didWebContext, "verificationMethodID")
	assert.NoError(t, err)
	assert.NotEmpty(t, verificationMethodID)

	schemaID, err := GetValue(didWebContext, "schemaID")
	assert.NoError(t, err)
	assert.NotEmpty(t, schemaID)

	cmOutput, err := CreateCredentialManifest(credManifestParams{
		IssuerID:             issuerDID.(string),
		VerificationMethodID: verificationMethodID.(string),
		SchemaID:             schemaID.(string),
	})
	assert.NoError(t, err)

	presentationDefinitionID, err := getJSONElement(cmOutput, "$.credential_manifest.presentation_definition.id")
	assert.NoError(t, err)
	assert.NotEmpty(t, presentationDefinitionID)
	SetValue(didWebContext, "presentationDefinitionID", presentationDefinitionID)

	manifestID, err := getJSONElement(cmOutput, "$.credential_manifest.id")
	assert.NoError(t, err)
	assert.NotEmpty(t, manifestID)
	SetValue(didWebContext, "manifestID", manifestID)
}

func TestDIDWebSubmitAndReviewApplicationIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	credentialJWT, err := GetValue(didWebContext, "credentialJWT")
	assert.NoError(t, err)
	assert.NotEmpty(t, credentialJWT)

	presentationDefinitionID, err := GetValue(didWebContext, "presentationDefinitionID")
	assert.NoError(t, err)
	assert.NotEmpty(t, presentationDefinitionID)

	manifestID, err := GetValue(didWebContext, "manifestID")
	assert.NoError(t, err)
	assert.NotEmpty(t, manifestID)

	aliceDID, err := GetValue(didWebContext, "aliceDID")
	assert.NoError(t, err)
	assert.NotEmpty(t, aliceDID)

	aliceKID, err := GetValue(didWebContext, "aliceKID")
	assert.NoError(t, err)
	assert.NotEmpty(t, aliceKID)

	aliceDIDPrivateKey, err := GetValue(didWebContext, "aliceDIDPrivateKey")
	assert.NoError(t, err)
	assert.NotEmpty(t, aliceDIDPrivateKey)

	credAppJWT, err := CreateCredentialApplicationJWT(credApplicationParams{
		DefinitionID: presentationDefinitionID.(string),
		ManifestID:   manifestID.(string),
	}, credentialJWT.(string), aliceDID.(string), aliceKID.(string), aliceDIDPrivateKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, credAppJWT)

	submitApplicationOutput, err := SubmitApplication(applicationParams{
		ApplicationJWT: credAppJWT,
	})
	assert.NoError(t, err)
	assert.NotEmpty(t, submitApplicationOutput)

	isDone, err := getJSONElement(submitApplicationOutput, "$.done")
	assert.NoError(t, err)
	assert.Equal(t, "false", isDone)
	opID, err := getJSONElement(submitApplicationOutput, "$.id")
	assert.NoError(t, err)

	params := reviewApplicationParams{
		ID:       storage.StatusObjectID(opID),
		Approved: true,
		Reason:   "oh yeah im testing",
	}
	reviewApplicationOutput, err := ReviewApplication(params)
	assert.NoError(t, err)
	crManifestID, err := getJSONElement(reviewApplicationOutput, "$.credential_response.manifest_id")
	assert.NoError(t, err)
	assert.Equal(t, manifestID, crManifestID)

	vc, err := getJSONElement(reviewApplicationOutput, "$.verifiableCredentials[0]")
	assert.NoError(t, err)
	assert.NotEmpty(t, vc)

	operationOutput, err := get(endpoint + version + "operations/" + opID)
	assert.NoError(t, err)
	isDone, err = getJSONElement(operationOutput, "$.done")
	assert.NoError(t, err)
	assert.Equal(t, "true", isDone)

	opCredentialResponse, err := getJSONElement(operationOutput, "$.result.response")
	assert.NoError(t, err)
	assert.JSONEq(t, reviewApplicationOutput, opCredentialResponse)
}
