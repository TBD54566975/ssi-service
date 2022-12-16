package integration

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var didWebContext = NewTestContext("DIDWeb")

func TestCreateIssuerDIDWebIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	didWebOutput, err := CreateDIDWeb()
	assert.NoError(t, err)

	issuerDID, err := getJSONElement(didWebOutput, "$.did.id")
	SetValue(didWebContext, "issuerDID", issuerDID)

	assert.NoError(t, err)
	assert.Contains(t, issuerDID, "did:web")

}

func TestCreateAliceDIDWebIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	didWebOutput, err := CreateDIDWeb()
	assert.NoError(t, err)
	assert.NotEmpty(t, didWebOutput)

	aliceDID, err := getJSONElement(didWebOutput, "$.did.id")
	SetValue(didWebContext, "aliceDID", aliceDID)

	assert.NoError(t, err)
	assert.Contains(t, aliceDID, "did:web")

	aliceDIDPrivateKey, err := getJSONElement(didWebOutput, "$.privateKeyBase58")
	SetValue(didWebContext, "aliceDIDPrivateKey", aliceDIDPrivateKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, aliceDID)

}

func TestDidWebCreateSchemaIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	output, err := CreateKYCSchema()
	assert.NoError(t, err)

	schemaID, err := getJSONElement(output, "$.id")
	SetValue(didWebContext, "schemaID", schemaID)

	assert.NoError(t, err)
	assert.NotEmpty(t, schemaID)
}

func TestDidWebCreateVerifiableCredentialIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	issuerDID, err := GetValue(didWebContext, "issuerDID")
	assert.NoError(t, err)
	assert.NotEmpty(t, issuerDID)

	schemaID, err := GetValue(didWebContext, "schemaID")
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
	SetValue(didWebContext, "credentialJWT", credentialJWT)
	assert.NoError(t, err)
	assert.NotEmpty(t, credentialJWT)
}

func TestDidWebCreateCredentialManifestIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	issuerDID, err := GetValue(didWebContext, "issuerDID")
	assert.NoError(t, err)
	assert.NotEmpty(t, issuerDID)

	schemaID, err := GetValue(didWebContext, "schemaID")
	assert.NoError(t, err)
	assert.NotEmpty(t, schemaID)

	cmOutput, err := CreateCredentialManifest(credManifestParams{
		IssuerID: issuerDID.(string),
		SchemaID: schemaID.(string),
	})
	assert.NoError(t, err)

	presentationDefinitionID, err := getJSONElement(cmOutput, "$.credential_manifest.presentation_definition.id")
	SetValue(didWebContext, "presentationDefinitionID", presentationDefinitionID)
	assert.NoError(t, err)
	assert.NotEmpty(t, presentationDefinitionID)

	manifestID, err := getJSONElement(cmOutput, "$.credential_manifest.id")
	SetValue(didWebContext, "manifestID", manifestID)
	assert.NoError(t, err)
	assert.NotEmpty(t, manifestID)
}

func TestDidWebSubmitApplicationIntegration(t *testing.T) {
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

	aliceDIDPrivateKey, err := GetValue(didWebContext, "aliceDIDPrivateKey")
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

	crManifestID, err := getJSONElement(credentialResponseOutput, "$.credential_response.manifest_id")
	assert.NoError(t, err)
	assert.Equal(t, manifestID, crManifestID)

	vc, err := getJSONElement(credentialResponseOutput, "$.verifiableCredentials[0]")
	assert.NoError(t, err)
	assert.NotEmpty(t, vc)
}
