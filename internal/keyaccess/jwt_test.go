package keyaccess

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestCreateJWKKeyAccess(t *testing.T) {
	t.Run("Create a Key Access object - Happy Path", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		kid := "test-kid"
		assert.NoError(tt, err)
		ka, err := NewJWKKeyAccess(kid, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, ka)
	})

	t.Run("Create a Key Access object - Bad Key", func(tt *testing.T) {
		kid := "test-kid"
		ka, err := NewJWKKeyAccess(kid, nil)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "key cannot be nil")
		assert.Empty(tt, ka)
	})

	t.Run("Create a Key Access object - No KID", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		assert.NoError(tt, err)
		ka, err := NewJWKKeyAccess("", privKey)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "kid cannot be empty")
		assert.Empty(tt, ka)
	})
}

func TestJWKKeyAccessSignVerify(t *testing.T) {
	t.Run("Sign and Verify - Happy Path", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		kid := "test-kid"
		assert.NoError(tt, err)
		ka, err := NewJWKKeyAccess(kid, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, ka)

		data := map[string]interface{}{
			"test": "test",
		}
		token, err := ka.Sign(data)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, token)

		err = ka.Verify(*token)
		assert.NoError(tt, err)

		// Create just a verifier and check that it can verify the token
		verifier, err := NewJWKKeyAccessVerifier(kid, privKey.Public())
		assert.NoError(tt, err)
		assert.NotEmpty(tt, verifier)

		err = verifier.Verify(*token)
		assert.NoError(tt, err)

		// Make sure the verifier can't sign
		_, err = verifier.Sign(data)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "cannot sign with nil signer")
	})

	t.Run("Sign and Verify - Bad Data", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		kid := "test-kid"
		assert.NoError(tt, err)
		ka, err := NewJWKKeyAccess(kid, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, ka)

		_, err = ka.Sign(nil)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "payload cannot be nil")
	})

	t.Run("Sign and Verify - Bad Signature", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		kid := "test-kid"
		assert.NoError(tt, err)
		ka, err := NewJWKKeyAccess(kid, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, ka)

		err = ka.Verify(JWKToken{})
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "token cannot be empty")
	})
}

func TestJWKKeyAccessSignVerifyCredentials(t *testing.T) {
	t.Run("Sign and Verify Credentials - Happy Path", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		kid := "test-kid"
		assert.NoError(tt, err)
		ka, err := NewJWKKeyAccess(kid, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, ka)

		// sign
		testCred := getTestCredential()
		signedCred, err := ka.SignVerifiableCredential(testCred)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, signedCred)

		// verify
		verifiedCred, err := ka.VerifyVerifiableCredential(*signedCred)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, verifiedCred)

		// check equality
		testJSON, err := json.Marshal(testCred)
		assert.NoError(tt, err)
		verifiedJSON, err := json.Marshal(verifiedCred)
		assert.NoError(tt, err)
		assert.JSONEq(tt, string(testJSON), string(verifiedJSON))
	})

	t.Run("Sign and Verify Credentials - Bad Data", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		kid := "test-kid"
		assert.NoError(tt, err)
		ka, err := NewJWKKeyAccess(kid, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, ka)

		// sign
		_, err = ka.SignVerifiableCredential(credential.VerifiableCredential{})
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "cannot sign invalid credential")
	})

	t.Run("Sign and Verify Credentials - Bad Signature", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		kid := "test-kid"
		assert.NoError(tt, err)
		ka, err := NewJWKKeyAccess(kid, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, ka)

		// verify
		_, err = ka.VerifyVerifiableCredential(JWKToken{"bad"})
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not verify JWT and its signature")
	})
}

func TestJWKKeyAccessSignVerifyPresentations(t *testing.T) {
	t.Run("Sign and Verify Presentations - Happy Path", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		kid := "test-kid"
		assert.NoError(tt, err)
		ka, err := NewJWKKeyAccess(kid, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, ka)

		// sign
		testPres := getTestPresentation()
		signedPres, err := ka.SignVerifiablePresentation(testPres)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, signedPres)

		// verify
		verifiedPres, err := ka.VerifyVerifiablePresentation(*signedPres)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, verifiedPres)

		// check equality
		testJSON, err := json.Marshal(testPres)
		assert.NoError(tt, err)
		verifiedJSON, err := json.Marshal(verifiedPres)
		assert.NoError(tt, err)
		assert.JSONEq(tt, string(testJSON), string(verifiedJSON))
	})

	t.Run("Sign and Verify Presentations - Bad Data", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		kid := "test-kid"
		assert.NoError(tt, err)
		ka, err := NewJWKKeyAccess(kid, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, ka)

		// sign
		_, err = ka.SignVerifiablePresentation(credential.VerifiablePresentation{})
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "cannot sign invalid presentation")
	})

	t.Run("Sign and Verify Presentations - Bad Signature", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		kid := "test-kid"
		assert.NoError(tt, err)
		ka, err := NewJWKKeyAccess(kid, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, ka)

		// verify
		_, err = ka.VerifyVerifiablePresentation(JWKToken{"bad"})
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not verify JWT and its signature")
	})
}

func getTestCredential() credential.VerifiableCredential {
	knownContext := []string{"https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"}
	knownID := uuid.NewString()
	knownType := []string{"VerifiableCredential", "HappyCredential"}
	knownIssuer := "https://example.com/issuers/565049"
	knownIssuanceDate := "2010-01-01T19:23:24Z"
	knownSubject := map[string]interface{}{
		"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
		"happiness": map[string]interface{}{
			"howHappy": "really happy",
		},
	}
	return credential.VerifiableCredential{
		Context:           knownContext,
		ID:                knownID,
		Type:              knownType,
		Issuer:            knownIssuer,
		IssuanceDate:      knownIssuanceDate,
		CredentialSubject: knownSubject,
	}
}

func getTestPresentation() credential.VerifiablePresentation {
	knownContext := []string{"https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"}
	knownID := uuid.NewString()
	knownType := []string{"VerifiablePresentation", "HappyPresentation"}
	knownHolder := "did:example:ebfeb1f712ebc6f1c276e12ec21"
	return credential.VerifiablePresentation{
		Context:              knownContext,
		ID:                   knownID,
		Type:                 knownType,
		Holder:               knownHolder,
		VerifiableCredential: []interface{}{getTestCredential()},
	}
}
