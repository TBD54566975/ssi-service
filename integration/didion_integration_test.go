package integration

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/stretchr/testify/assert"

	"github.com/tbd54566975/ssi-service/pkg/service/operation/storage"
)

var didIONContext = NewTestContext("DIDION")

func TestCreateIssuerDIDIONIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	didIONOutput, err := CreateDIDION()
	assert.NoError(t, err)

	issuerDID, err := getJSONElement(didIONOutput, "$.did.id")
	assert.NoError(t, err)
	assert.Contains(t, issuerDID, "did:ion")
	SetValue(didIONContext, "issuerDID", issuerDID)

	issuerKID, err := getJSONElement(didIONOutput, "$.did.verificationMethod[0].id")
	assert.NoError(t, err)
	assert.NotEmpty(t, issuerKID)
	SetValue(didIONContext, "issuerKID", issuerKID)
}

func TestCreateAliceDIDKeyForDIDIONIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	applicantPrivKey, applicantDIDKey, err := didsdk.GenerateDIDKey(crypto.Ed25519)
	assert.NoError(t, err)
	assert.NotEmpty(t, applicantPrivKey)
	assert.NotEmpty(t, applicantDIDKey)

	applicantDID, err := applicantDIDKey.Expand()
	assert.NoError(t, err)
	assert.NotEmpty(t, applicantDID)

	aliceDID := applicantDID.ID
	assert.Contains(t, aliceDID, "did:key")
	SetValue(didIONContext, "aliceDID", aliceDID)

	aliceKID := applicantDID.VerificationMethod[0].ID
	assert.NotEmpty(t, aliceKID)
	SetValue(didIONContext, "aliceKID", aliceKID)
	SetValue(didIONContext, "aliceDIDPrivateKey", applicantPrivKey)
}

func TestDIDIONCreateSchemaIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	output, err := CreateKYCSchema()
	assert.NoError(t, err)

	schemaID, err := getJSONElement(output, "$.id")
	SetValue(didIONContext, "schemaID", schemaID)

	assert.NoError(t, err)
	assert.NotEmpty(t, schemaID)
}

func TestDIDIONCreateVerifiableCredentialIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	issuerDID, err := GetValue(didIONContext, "issuerDID")
	assert.NoError(t, err)
	assert.NotEmpty(t, issuerDID)

	issuerKID, err := GetValue(didIONContext, "issuerKID")
	assert.NoError(t, err)
	assert.NotEmpty(t, issuerKID)

	schemaID, err := GetValue(didIONContext, "schemaID")
	assert.NoError(t, err)
	assert.NotEmpty(t, schemaID)

	vcOutput, err := CreateVerifiableCredential(credInputParams{
		IssuerID:  issuerDID.(string),
		IssuerKID: issuerKID.(string),
		SchemaID:  schemaID.(string),
		SubjectID: issuerDID.(string),
	}, false)
	assert.NoError(t, err)
	assert.NotEmpty(t, vcOutput)

	credentialJWT, err := getJSONElement(vcOutput, "$.credentialJwt")
	assert.NoError(t, err)
	assert.NotEmpty(t, credentialJWT)
	SetValue(didIONContext, "credentialJWT", credentialJWT)
}

func TestDIDIONCreateCredentialManifestIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	issuerDID, err := GetValue(didIONContext, "issuerDID")
	assert.NoError(t, err)
	assert.NotEmpty(t, issuerDID)

	issuerKID, err := GetValue(didIONContext, "issuerKID")
	assert.NoError(t, err)
	assert.NotEmpty(t, issuerKID)

	schemaID, err := GetValue(didIONContext, "schemaID")
	assert.NoError(t, err)
	assert.NotEmpty(t, schemaID)

	cmOutput, err := CreateCredentialManifest(credManifestParams{
		IssuerID:  issuerDID.(string),
		IssuerKID: issuerKID.(string),
		SchemaID:  schemaID.(string),
	})
	assert.NoError(t, err)

	presentationDefinitionID, err := getJSONElement(cmOutput, "$.credential_manifest.presentation_definition.id")
	assert.NoError(t, err)
	assert.NotEmpty(t, presentationDefinitionID)
	SetValue(didIONContext, "presentationDefinitionID", presentationDefinitionID)

	manifestID, err := getJSONElement(cmOutput, "$.credential_manifest.id")
	assert.NoError(t, err)
	assert.NotEmpty(t, manifestID)
	SetValue(didIONContext, "manifestID", manifestID)
}

func TestDIDIONSubmitAndReviewApplicationIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	credentialJWT, err := GetValue(didIONContext, "credentialJWT")
	assert.NoError(t, err)
	assert.NotEmpty(t, credentialJWT)

	presentationDefinitionID, err := GetValue(didIONContext, "presentationDefinitionID")
	assert.NoError(t, err)
	assert.NotEmpty(t, presentationDefinitionID)

	manifestID, err := GetValue(didIONContext, "manifestID")
	assert.NoError(t, err)
	assert.NotEmpty(t, manifestID)

	aliceDID, err := GetValue(didIONContext, "aliceDID")
	assert.NoError(t, err)
	assert.NotEmpty(t, aliceDID)

	aliceKID, err := GetValue(didIONContext, "aliceKID")
	assert.NoError(t, err)
	assert.NotEmpty(t, aliceKID)

	aliceDIDPrivateKey, err := GetValue(didIONContext, "aliceDIDPrivateKey")
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

	reviewApplicationOutput, err := ReviewApplication(reviewApplicationParams{
		ID:       storage.StatusObjectID(opID),
		Approved: true,
		Reason:   "oh yeah im testing",
	})
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
