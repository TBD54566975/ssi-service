package howto

import (
	gocrypto "crypto"
	"fmt"
	"testing"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/did/key"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/require"
)

func TestPresentationSubmission(t *testing.T) {
	// create an issuer DID for the manifest
	issuerPrivKey, issuerDID, err := key.GenerateDIDKey(crypto.Ed25519)
	require.NoError(t, err)

	// Get a Presentation Request that we're going to respond to
	presentationRequestJWT := CreatePresentationRequest(t, issuerPrivKey, *issuerDID)

	// create a holder DID for the submission
	holderPrivKey, holderDID, err := key.GenerateDIDKey(crypto.Ed25519)
	require.NoError(t, err)

	// self sign a credential with a first name to respond to the request with
	credJWT := CreateNameCredential(t, holderPrivKey, *holderDID)

	// create a presentation submission against the request using the credential
	presentationSubmissionJWT := CreatePresentationSubmission(t, holderPrivKey, *holderDID, presentationRequestJWT, credJWT)
	fmt.Printf("Presentation Submission JWT: %s\n", string(presentationSubmissionJWT))

	// submit and process the credential application to get a credential response
	success := ProcessPresentationSubmission(t, presentationRequestJWT, presentationSubmissionJWT)
	require.True(t, success)
}

func ProcessPresentationSubmission(t *testing.T, requestJWT, submissionJWT []byte) bool {
	// decode the presentation request
	requestToken, err := jwt.Parse(requestJWT)
	require.NoError(t, err)

	var d exchange.PresentationDefinition
	definitionClaim, ok := requestToken.Get("presentation_definition")
	if !ok {
		t.Fatal("presentation_definition claim not found")
	}
	definitionClaimBytes, err := json.Marshal(definitionClaim)
	require.NoError(t, err)
	err = json.Unmarshal(definitionClaimBytes, &d)
	require.NoError(t, err)

	// decode the submission to JSON
	submissionToken, err := jwt.Parse(submissionJWT)
	require.NoError(t, err)
	vpToken, ok := submissionToken.Get("vp")
	if !ok {
		t.Fatal("vp claim not found")
	}
	vpBytes, err := json.Marshal(vpToken)
	require.NoError(t, err)
	var vp credential.VerifiablePresentation
	err = json.Unmarshal(vpBytes, &vp)
	require.NoError(t, err)

	_, err = exchange.VerifyPresentationSubmissionVP(d, vp)
	return err == nil
}

func CreatePresentationSubmission(t *testing.T, privKey gocrypto.PrivateKey, submitterDID key.DIDKey, requestJWT, credJWT []byte) []byte {
	// TODO(gabe) we could verify the presentation request here, but we won't for now
	requestToken, err := jwt.Parse(requestJWT)
	require.NoError(t, err)

	requester := requestToken.Issuer()
	var d exchange.PresentationDefinition
	definitionClaim, ok := requestToken.Get("presentation_definition")
	if !ok {
		t.Fatal("presentation_definition claim not found")
	}
	definitionClaimBytes, err := json.Marshal(definitionClaim)
	require.NoError(t, err)
	err = json.Unmarshal(definitionClaimBytes, &d)
	require.NoError(t, err)

	// construct signer for the submitter
	signer, err := jwx.NewJWXSigner(submitterDID.String(), submitterDID.String()+"#+"+submitterDID.String(), privKey)
	require.NoError(t, err)

	presentationSubmissionVPJWT, err := exchange.BuildPresentationSubmission(*signer, requester, d, []exchange.PresentationClaim{
		{
			Token:                         util.StringPtr(string(credJWT)),
			JWTFormat:                     exchange.JWTVC.Ptr(),
			SignatureAlgorithmOrProofType: string(crypto.EdDSA),
		},
	}, exchange.JWTVPTarget)
	require.NoError(t, err)

	return presentationSubmissionVPJWT
}

func CreatePresentationRequest(t *testing.T, privKey gocrypto.PrivateKey, issuerDID key.DIDKey) []byte {
	definitionBuilder := exchange.NewPresentationDefinitionBuilder()
	did := issuerDID.String()
	err := definitionBuilder.SetName("Test Presentation Definition")
	require.NoError(t, err)

	err = definitionBuilder.SetInputDescriptors([]exchange.InputDescriptor{
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
			Format: &exchange.ClaimFormat{
				JWTVC: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
			},
		},
	})
	require.NoError(t, err)

	// build the presentation definition
	d, err := definitionBuilder.Build()
	require.NoError(t, err)

	// sign the definition as a JWT
	didDoc, err := issuerDID.Expand()
	require.NoError(t, err)

	signer, err := jwx.NewJWXSigner(did, didDoc.VerificationMethod[0].ID, privKey)
	require.NoError(t, err)

	presentationRequestBytes, err := exchange.BuildPresentationRequest(*signer, exchange.JWTRequest, *d)
	require.NoError(t, err)

	return presentationRequestBytes
}
