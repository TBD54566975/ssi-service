package keyaccess

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
)

func TestCreateDataIntegrityKeyAccess(t *testing.T) {
	t.Run("Create a Key Access object - Happy Path", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		kid := "test-kid"
		assert.NoError(tt, err)
		ka, err := NewDataIntegrityKeyAccess(kid, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, ka)
	})

	t.Run("Create a Key Access object - Bad Key", func(tt *testing.T) {
		kid := "test-kid"
		ka, err := NewDataIntegrityKeyAccess(kid, nil)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "key cannot be nil")
		assert.Empty(tt, ka)
	})

	t.Run("Create a Key Access object - No KID", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		assert.NoError(tt, err)
		ka, err := NewDataIntegrityKeyAccess("", privKey)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "kid cannot be empty")
		assert.Empty(tt, ka)
	})
}

func TestDataIntegrityKeyAccessSignVerify(t *testing.T) {
	t.Run("Sign and Verify Credential - Happy Path", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		kid := "test-kid"
		assert.NoError(tt, err)
		ka, err := NewDataIntegrityKeyAccess(kid, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, ka)

		// sign
		testCred := getTestCredential()
		signedCred, err := ka.Sign(&testCred)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, signedCred)

		var cred credential.VerifiableCredential
		err = json.Unmarshal(signedCred, &cred)
		assert.NoError(tt, err)

		// verify
		err = ka.Verify(&cred)
		assert.NoError(tt, err)
	})

	t.Run("Sign and Verify Credential - Bad Data", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		kid := "test-kid"
		assert.NoError(tt, err)
		ka, err := NewDataIntegrityKeyAccess(kid, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, ka)

		// sign
		_, err = ka.Sign(nil)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "payload cannot be nil")
	})

	t.Run("Sign and Verify Credential - Bad Signature", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		kid := "test-kid"
		assert.NoError(tt, err)
		ka, err := NewDataIntegrityKeyAccess(kid, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, ka)

		// verify
		err = ka.Verify(nil)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "payload cannot be nil")
	})

	t.Run("Sign and Verify Presentation", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		kid := "test-kid"
		assert.NoError(tt, err)
		ka, err := NewDataIntegrityKeyAccess(kid, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, ka)

		// sign
		testPres := getTestPresentation()
		signedPres, err := ka.Sign(&testPres)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, signedPres)

		var pres credential.VerifiablePresentation
		err = json.Unmarshal(signedPres, &pres)
		assert.NoError(tt, err)

		// verify
		err = ka.Verify(&pres)
		assert.NoError(tt, err)
	})
}