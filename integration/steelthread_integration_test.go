package integration

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var steelThreadContext = NewTestContext("SteelThread")

func TestCreateIssuerDIDKeyIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	didKeyOutput, err := CreateDIDKey()
	assert.NoError(t, err)

	issuerDID, err := getJSONElement(didKeyOutput, "$.did.id")
	SetValue(steelThreadContext, "issuerDID", issuerDID)

	assert.NoError(t, err)
	assert.Contains(t, issuerDID, "did:key")

}

func TestCreateAliceDIDKeyIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	didKeyOutput, err := CreateDIDKey()
	assert.NoError(t, err)
	assert.NotEmpty(t, didKeyOutput)

	aliceDID, err := getJSONElement(didKeyOutput, "$.did.id")
	SetValue(steelThreadContext, "aliceDID", aliceDID)

	assert.NoError(t, err)
	assert.Contains(t, aliceDID, "did:key")

	aliceDIDPrivateKey, err := getJSONElement(didKeyOutput, "$.privateKeyBase58")
	SetValue(steelThreadContext, "aliceDIDPrivateKey", aliceDIDPrivateKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, aliceDID)

}

func TestCreateSchemaIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	output, err := CreateKYCSchema()
	assert.NoError(t, err)

	schemaID, err := getJSONElement(output, "$.id")
	SetValue(steelThreadContext, "schemaID", schemaID)

	assert.NoError(t, err)
	assert.NotEmpty(t, schemaID)
}

func TestCreateVerifiableCredentialIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	issuerDID, err := GetValue(steelThreadContext, "issuerDID")
	assert.NoError(t, err)
	assert.NotEmpty(t, issuerDID)

	schemaID, err := GetValue(steelThreadContext, "schemaID")
	assert.NoError(t, err)
	assert.NotEmpty(t, schemaID)

	vcOutput, err := CreateVerifiableCredential(credInputParams{
		IssuerID:  issuerDID.(string),
		SchemaID:  schemaID.(string),
		SubjectID: issuerDID.(string),
	}, false)
	assert.NoError(t, err)
	assert.NotEmpty(t, vcOutput)

	credentialJWT, err := getJSONElement(vcOutput, "$.credentialJwt")
	SetValue(steelThreadContext, "credentialJWT", credentialJWT)
	assert.NoError(t, err)
	assert.NotEmpty(t, credentialJWT)
}

func TestCreateCredentialManifestIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	issuerDID, err := GetValue(steelThreadContext, "issuerDID")
	assert.NoError(t, err)
	assert.NotEmpty(t, issuerDID)

	schemaID, err := GetValue(steelThreadContext, "schemaID")
	assert.NoError(t, err)
	assert.NotEmpty(t, schemaID)

	cmOutput, err := CreateCredentialManifest(credManifestParams{
		IssuerID: issuerDID.(string),
		SchemaID: schemaID.(string),
	})
	assert.NoError(t, err)

	presentationDefinitionID, err := getJSONElement(cmOutput, "$.credential_manifest.presentation_definition.id")
	SetValue(steelThreadContext, "presentationDefinitionID", presentationDefinitionID)
	assert.NoError(t, err)
	assert.NotEmpty(t, presentationDefinitionID)

	manifestID, err := getJSONElement(cmOutput, "$.credential_manifest.id")
	SetValue(steelThreadContext, "manifestID", manifestID)
	assert.NoError(t, err)
	assert.NotEmpty(t, manifestID)
}

func TestSubmitApplicationIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	credentialJWT, err := GetValue(steelThreadContext, "credentialJWT")
	assert.NoError(t, err)
	assert.NotEmpty(t, credentialJWT)

	presentationDefinitionID, err := GetValue(steelThreadContext, "presentationDefinitionID")
	assert.NoError(t, err)
	assert.NotEmpty(t, presentationDefinitionID)

	manifestID, err := GetValue(steelThreadContext, "manifestID")
	assert.NoError(t, err)
	assert.NotEmpty(t, manifestID)

	aliceDID, err := GetValue(steelThreadContext, "aliceDID")
	assert.NoError(t, err)
	assert.NotEmpty(t, aliceDID)

	aliceDIDPrivateKey, err := GetValue(steelThreadContext, "aliceDIDPrivateKey")
	assert.NoError(t, err)
	assert.NotEmpty(t, aliceDIDPrivateKey)

	credAppJWT, err := CreateCredentialApplicationJWT(credApplicationParams{
		DefinitionID: presentationDefinitionID.(string),
		ManifestID:   manifestID.(string),
	}, credentialJWT.(string), aliceDID.(string), aliceDIDPrivateKey.(string))
	assert.NoError(t, err)
	assert.NotEmpty(t, credAppJWT)

	credentialResponseOutput, err := SubmitApplication(applicationParams{
		ApplicationJWT: credAppJWT,
	})
	assert.NoError(t, err)
	assert.NotEmpty(t, credentialResponseOutput)

	crManifestID, err := getJSONElement(credentialResponseOutput, "$.result.response.credential_response.manifest_id")
	assert.NoError(t, err)
	assert.Equal(t, manifestID, crManifestID)

	vc, err := getJSONElement(credentialResponseOutput, "$.result.response.verifiableCredentials[0]")
	assert.NoError(t, err)
	assert.NotEmpty(t, vc)
}
