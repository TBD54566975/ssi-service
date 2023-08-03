package howto

import (
	"testing"
	"time"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/integrity"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/did/key"
	"github.com/stretchr/testify/require"
)

func TestVerifiablePresentation(t *testing.T) {
	// create a new DID to use to self-issue a credential and present it to a verifier
	privateKey, didKey, err := key.GenerateDIDKey(crypto.Ed25519)
	require.NoError(t, err)

	// expand the DID Document to access the key ID
	didKeyDocument, err := didKey.Expand()
	require.NoError(t, err)
	didKeyID := didKeyDocument.VerificationMethod[0].ID

	// first create a credential we wish to present
	credBuilder := credential.NewVerifiableCredentialBuilder()

	// set our DID as the issuer of the credential, since it will be self-signed
	err = credBuilder.SetIssuer(didKey.String())
	require.NoError(t, err)

	// set the issuance date as the current time
	err = credBuilder.SetIssuanceDate(time.Now().Format(time.RFC3339))
	require.NoError(t, err)

	// add the data to the body of the credential
	err = credBuilder.SetCredentialSubject(
		map[string]any{
			// set the ID property of the credential subject to our DID, since the credential is about us
			credential.VerifiableCredentialIDProperty: didKey.String(),
			"jobTitle": "Tutorial Author",
			"employer": "TBD",
		},
	)
	require.NoError(t, err)

	// build the credential
	unsignedCredential, err := credBuilder.Build()
	require.NoError(t, err)

	// sign the credential using our DID's private key
	signer, err := jwx.NewJWXSigner(didKey.String(), didKeyID, privateKey)
	require.NoError(t, err)

	// sign as a JWT
	signedCredentialBytes, err := integrity.SignVerifiableCredentialJWT(*signer, *unsignedCredential)
	require.NoError(t, err)
	signedCredentialJWTString := string(signedCredentialBytes)

	// construct a Verifiable Presentation for the credential
	presBuilder := credential.NewVerifiablePresentationBuilder()
	err = presBuilder.SetHolder(didKey.String())
	err = presBuilder.AddVerifiableCredentials(signedCredentialJWTString)
	require.NoError(t, err)

	// build the presentation
	unsignedPresentation, err := presBuilder.Build()
	require.NoError(t, err)

	// sign the presentation using our DID's private key, passing no additional parameters
	signedPresentationBytes, err := integrity.SignVerifiablePresentationJWT(*signer, integrity.JWTVVPParameters{}, *unsignedPresentation)
	require.NoError(t, err)
	signedPresentationJWTString := string(signedPresentationBytes)

	// print the signed presentation JWT
	println(signedPresentationJWTString)
}
