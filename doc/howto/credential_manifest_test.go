package howto

import (
	"context"
	gocrypto "crypto"
	"fmt"
	"testing"
	"time"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/credential/integrity"
	"github.com/TBD54566975/ssi-sdk/credential/manifest"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/did/key"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/require"
)

func TestCredentialApplication(t *testing.T) {
	// create an issuer DID for the manifest
	issuerPrivKey, issuerDID, err := key.GenerateDIDKey(crypto.Ed25519)
	require.NoError(t, err)

	// Get a Credential Manifest that we're going to apply to
	manifestJWT := CreateCredentialManifest(t, issuerPrivKey, *issuerDID)

	// create a holder DID for the application
	holderPrivKey, holderDID, err := key.GenerateDIDKey(crypto.Ed25519)
	require.NoError(t, err)

	// self sign a credential with a first name to respond to the manifest with
	credJWT := CreateNameCredential(t, holderPrivKey, *holderDID)

	// create a credential application against the manifest using the credential
	credAppJWT := CreateCredentialApplication(t, holderPrivKey, *holderDID, manifestJWT, credJWT)
	fmt.Printf("Credential Application JWT: %s\n", string(credAppJWT))

	// submit and process the credential application to get a credential response
	success := ProcessCredentialApplication(t, manifestJWT, credAppJWT)
	require.True(t, success)
}

func ProcessCredentialApplication(t *testing.T, manifestJWT, credAppJWT []byte) bool {
	// TODO we won't actually issue a credential here, but you can see what validation looks like

	// decode the manifest
	manifestToken, err := jwt.Parse(manifestJWT)
	require.NoError(t, err)

	var m manifest.CredentialManifest
	manifestClaim, ok := manifestToken.Get("credential_manifest")
	if !ok {
		t.Fatal("credential_manifest claim not found")
	}
	manifestClaimBytes, err := json.Marshal(manifestClaim)
	require.NoError(t, err)
	err = json.Unmarshal(manifestClaimBytes, &m)
	require.NoError(t, err)

	// decode the application to JSON
	token, err := jwt.Parse(credAppJWT)
	require.NoError(t, err)
	tokenMap, err := token.AsMap(context.Background())
	require.NoError(t, err)

	_, err = manifest.IsValidCredentialApplicationForManifest(m, tokenMap)
	return err == nil
}

func CreateCredentialApplication(t *testing.T, privKey gocrypto.PrivateKey, holderDID key.DIDKey, manifestJWT, credJWT []byte) []byte {
	// decode the manifest
	manifestToken, err := jwt.Parse(manifestJWT)
	require.NoError(t, err)

	var m manifest.CredentialManifest
	manifestClaim, ok := manifestToken.Get("credential_manifest")
	if !ok {
		t.Fatal("credential_manifest claim not found")
	}
	manifestClaimBytes, err := json.Marshal(manifestClaim)
	require.NoError(t, err)
	err = json.Unmarshal(manifestClaimBytes, &m)
	require.NoError(t, err)

	// TODO: we could validate the manifest here, but skipped for simplicity

	credAppBuilder := manifest.NewCredentialApplicationBuilder(m.ID)
	err = credAppBuilder.SetApplicantID(holderDID.String())
	require.NoError(t, err)

	err = credAppBuilder.SetApplicationClaimFormat(exchange.ClaimFormat{
		JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
	})
	require.NoError(t, err)

	err = credAppBuilder.SetPresentationSubmission(exchange.PresentationSubmission{
		ID:           "test-submission",
		DefinitionID: m.PresentationDefinition.ID,
		DescriptorMap: []exchange.SubmissionDescriptor{
			{
				ID:     m.PresentationDefinition.InputDescriptors[0].ID,
				Format: exchange.JWTVC.String(),
				Path:   "$.verifiableCredentials[0]",
			},
		},
	})
	require.NoError(t, err)
	credApplication, err := credAppBuilder.Build()
	require.NoError(t, err)

	// wrap the credential application in a JSON structure that's expected with a top-level credential_application claim
	credApplicationWrapper := manifest.CredentialApplicationWrapper{
		CredentialApplication: *credApplication,
		Credentials:           []any{string(credJWT)},
	}
	credAppBytes, err := json.Marshal(credApplicationWrapper)
	require.NoError(t, err)

	// sign the cred app as a JWT
	didDoc, err := holderDID.Expand()
	require.NoError(t, err)
	signer, err := jwx.NewJWXSigner(holderDID.String(), didDoc.VerificationMethod[0].ID, privKey)
	require.NoError(t, err)

	credAppJWT, err := signer.SignJWS(credAppBytes)
	require.NoError(t, err)

	return credAppJWT
}

func CreateNameCredential(t *testing.T, privKey gocrypto.PrivateKey, holderDID key.DIDKey) []byte {
	credBuilder := credential.NewVerifiableCredentialBuilder()
	err := credBuilder.SetIssuer(holderDID.String())
	require.NoError(t, err)

	err = credBuilder.SetIssuanceDate(time.Now().Format(time.RFC3339))
	require.NoError(t, err)

	err = credBuilder.SetCredentialSubject(map[string]interface{}{
		credential.VerifiableCredentialIDProperty: holderDID.String(),
		"firstName": "Alice",
	})
	require.NoError(t, err)

	cred, err := credBuilder.Build()
	require.NoError(t, err)

	// sign the cred as a JWT
	didDoc, err := holderDID.Expand()
	require.NoError(t, err)
	signer, err := jwx.NewJWXSigner(holderDID.String(), didDoc.VerificationMethod[0].ID, privKey)
	require.NoError(t, err)

	credJWT, err := integrity.SignVerifiableCredentialJWT(*signer, *cred)
	require.NoError(t, err)

	return credJWT
}

func CreateCredentialManifest(t *testing.T, privKey gocrypto.PrivateKey, issuerDID key.DIDKey) []byte {
	manifestBuilder := manifest.NewCredentialManifestBuilder()
	did := issuerDID.String()
	err := manifestBuilder.SetIssuer(manifest.Issuer{
		ID:   did,
		Name: "Test Issuer",
	})
	require.NoError(t, err)

	err = manifestBuilder.SetName("Test Credential Manifest")
	require.NoError(t, err)

	descriptors := []manifest.OutputDescriptor{
		{
			ID:     "name-cred",
			Schema: "https://test.com/schema",
			Name:   "Name Credential",
		},
	}
	err = manifestBuilder.SetOutputDescriptors(descriptors)
	require.NoError(t, err)

	// only accept JWTs signed with EdDSA
	err = manifestBuilder.SetClaimFormat(exchange.ClaimFormat{
		JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
	})

	// accept a VC with a first name as an input
	err = manifestBuilder.SetPresentationDefinition(exchange.PresentationDefinition{
		ID: "require-name-credential",
		InputDescriptors: []exchange.InputDescriptor{
			{
				ID: "name",
				Constraints: &exchange.Constraints{
					Fields: []exchange.Field{
						{
							Path: []string{"$.vc.credentialSubject.firstName"},
							Filter: &exchange.Filter{
								Type:      "string",
								MinLength: 3,
							},
						},
					},
				},
			},
		},
	})

	m, err := manifestBuilder.Build()
	require.NoError(t, err)

	// sign the manifest as a JWT
	didDoc, err := issuerDID.Expand()
	require.NoError(t, err)

	signer, err := jwx.NewJWXSigner(did, didDoc.VerificationMethod[0].ID, privKey)
	require.NoError(t, err)

	// marshal the manifest into JSON before signing over it as a JWS
	manifestWrapper := struct {
		Manifest manifest.CredentialManifest `json:"credential_manifest"`
	}{
		Manifest: *m,
	}
	manifestBytes, err := json.Marshal(manifestWrapper)
	require.NoError(t, err)
	manifestJWT, err := signer.SignJWS(manifestBytes)
	require.NoError(t, err)
	return manifestJWT
}
