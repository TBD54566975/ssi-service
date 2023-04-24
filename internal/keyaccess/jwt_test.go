package keyaccess

import (
	"context"
	"testing"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWKKeyAccessForEachKeyType(t *testing.T) {
	testID := "test-id"
	testKID := "test-kid"
	testData := map[string]any{
		"test": "data",
	}

	tests := []struct {
		kt crypto.KeyType
	}{
		{
			kt: crypto.Ed25519,
		},
		{
			kt: crypto.SECP256k1,
		},
		{
			kt: crypto.P256,
		},
		{
			kt: crypto.P384,
		},
		{
			kt: crypto.P521,
		},
		{
			kt: crypto.RSA,
		},
	}
	for _, test := range tests {
		t.Run(string(test.kt), func(t *testing.T) {
			// generate a new key based on the given key type
			_, privKey, err := crypto.GenerateKeyByKeyType(test.kt)
			assert.NoError(t, err)
			assert.NotEmpty(t, privKey)

			// create key access with the key
			ka, err := NewJWKKeyAccess(testID, testKID, privKey)
			assert.NoError(t, err)
			assert.NotEmpty(t, ka)

			// sign
			token, err := ka.Sign(testData)
			assert.NoError(t, err)
			assert.NotEmpty(t, token)

			// verify
			err = ka.Verify(*token)
			assert.NoError(t, err)
		})
	}
}

func TestCreateJWKKeyAccess(t *testing.T) {
	t.Run("Create a Key Access object - Happy Path", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		testID := "test-id"
		kid := "test-kid"
		assert.NoError(tt, err)
		ka, err := NewJWKKeyAccess(testID, kid, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, ka)
	})

	t.Run("Create a Key Access object - Bad Key", func(tt *testing.T) {
		testID := "test-id"
		kid := "test-kid"
		ka, err := NewJWKKeyAccess(testID, kid, nil)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "key cannot be nil")
		assert.Empty(tt, ka)
	})

	t.Run("Create a Key Access object - No KID", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		assert.NoError(tt, err)
		ka, err := NewJWKKeyAccess("test-id", "", privKey)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "kid cannot be empty")
		assert.Empty(tt, ka)
	})
}

func TestJWKKeyAccessSignVerify(t *testing.T) {
	t.Run("Sign and Verify - Happy Path", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		testID := "test-id"
		kid := "test-kid"
		assert.NoError(tt, err)
		ka, err := NewJWKKeyAccess(testID, kid, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, ka)

		data := map[string]any{
			"test": "test",
		}
		token, err := ka.Sign(data)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, token)

		err = ka.Verify(*token)
		assert.NoError(tt, err)

		// Create just a verifier and check that it can verify the token
		verifier, err := NewJWKKeyAccessVerifier(testID, kid, privKey.Public())
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
		testID := "test-id"
		kid := "test-kid"
		assert.NoError(tt, err)
		ka, err := NewJWKKeyAccess(testID, kid, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, ka)

		_, err = ka.Sign(nil)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "payload cannot be nil")
	})

	t.Run("Sign and Verify - Bad Signature", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		testID := "test-id"
		kid := "test-kid"
		assert.NoError(tt, err)
		ka, err := NewJWKKeyAccess(testID, kid, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, ka)

		err = ka.Verify(JWT(""))
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "token cannot be empty")
	})
}

func TestJWKKeyAccessSignVerifyCredentials(t *testing.T) {
	t.Run("Sign and Verify Credentials - Happy Path", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		testID := "test-id"
		kid := "test-kid"
		assert.NoError(tt, err)
		ka, err := NewJWKKeyAccess(testID, kid, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, ka)

		// sign
		testCred := getTestCredential(testID)
		testCredCopy := copyCred(t, testCred)
		signedCred, err := ka.SignVerifiableCredential(testCredCopy)
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
		testID := "test-id"
		kid := "test-kid"
		assert.NoError(tt, err)
		ka, err := NewJWKKeyAccess(testID, kid, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, ka)

		// sign
		_, err = ka.SignVerifiableCredential(credential.VerifiableCredential{})
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "cannot sign invalid credential")
	})

	t.Run("Sign and Verify Credentials - Bad Signature", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		testID := "test-id"
		kid := "test-kid"
		assert.NoError(tt, err)
		ka, err := NewJWKKeyAccess(testID, kid, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, ka)

		// verify
		_, err = ka.VerifyVerifiableCredential("bad")
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid JWT")
	})
}

func TestJWKKeyAccessSignVerifyPresentations(t *testing.T) {
	t.Run("Sign and Verify Presentations - Happy Path", func(tt *testing.T) {
		privKey, didKey, err := did.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, privKey)
		expanded, err := didKey.Expand()
		assert.NoError(tt, err)
		kid := expanded.VerificationMethod[0].ID
		ka, err := NewJWKKeyAccess(didKey.String(), kid, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, ka)

		// sign
		testPres := getJWTTestPresentation(*ka)
		signedPres, err := ka.SignVerifiablePresentation(didKey.String(), testPres)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, signedPres)

		// verify
		resolver, err := did.NewResolver([]did.Resolver{did.KeyResolver{}}...)
		assert.NoError(tt, err)
		verifiedPres, err := ka.VerifyVerifiablePresentation(context.Background(), resolver, *signedPres)
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
		testID := "test-id"
		kid := "test-kid"
		assert.NoError(tt, err)
		ka, err := NewJWKKeyAccess(testID, kid, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, ka)

		// sign
		_, err = ka.SignVerifiablePresentation("test-audience", credential.VerifiablePresentation{})
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "cannot sign invalid presentation")
	})

	t.Run("Sign and Verify Presentations - Bad Signature", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		testID := "test-id"
		kid := "test-kid"
		assert.NoError(tt, err)
		ka, err := NewJWKKeyAccess(testID, kid, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, ka)

		// verify
		resolver, err := did.NewResolver([]did.Resolver{did.KeyResolver{}}...)
		assert.NoError(tt, err)
		_, err = ka.VerifyVerifiablePresentation(context.Background(), resolver, "bad")
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid JWT")
	})
}

func getTestCredential(issuerDID string) credential.VerifiableCredential {
	knownContext := []string{"https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"}
	knownID := uuid.NewString()
	knownType := []string{"VerifiableCredential", "HappyCredential"}
	knownIssuanceDate := "2010-01-01T19:23:24Z"
	knownSubject := map[string]any{
		"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
		"happiness": map[string]any{
			"howHappy": "really happy",
		},
	}
	return credential.VerifiableCredential{
		Context:           knownContext,
		ID:                knownID,
		Type:              knownType,
		Issuer:            issuerDID,
		IssuanceDate:      knownIssuanceDate,
		CredentialSubject: knownSubject,
	}
}

func getDataIntegrityTestPresentation(ka DataIntegrityKeyAccess) credential.VerifiablePresentation {
	knownContext := []string{"https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"}
	knownID := uuid.NewString()
	knownType := []string{"VerifiablePresentation", "HappyPresentation"}
	knownHolder := "did:example:ebfeb1f712ebc6f1c276e12ec21"
	testCredential := getTestCredential(ka.JWTSigner.ID)
	signedCred, _ := ka.Sign(&testCredential)
	return credential.VerifiablePresentation{
		Context:              knownContext,
		ID:                   knownID,
		Type:                 knownType,
		Holder:               knownHolder,
		VerifiableCredential: []any{signedCred},
	}
}

func getJWTTestPresentation(ka JWKKeyAccess) credential.VerifiablePresentation {
	knownContext := []string{"https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"}
	knownID := uuid.NewString()
	knownType := []string{"VerifiablePresentation", "HappyPresentation"}
	knownHolder := "did:example:ebfeb1f712ebc6f1c276e12ec21"
	testCredential := getTestCredential(ka.JWTSigner.ID)
	signedJWT, _ := ka.SignVerifiableCredential(testCredential)
	return credential.VerifiablePresentation{
		Context:              knownContext,
		ID:                   knownID,
		Type:                 knownType,
		Holder:               knownHolder,
		VerifiableCredential: []any{signedJWT},
	}
}

func copyCred(t *testing.T, cred credential.VerifiableCredential) credential.VerifiableCredential {
	credBytes, err := json.Marshal(cred)
	require.NoError(t, err)
	var newCred credential.VerifiableCredential
	err = json.Unmarshal(credBytes, &newCred)
	require.NoError(t, err)
	return newCred
}
