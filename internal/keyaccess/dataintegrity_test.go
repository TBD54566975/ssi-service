package keyaccess

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
)

func TestCreateDataIntegrityKeyAccess(t *testing.T) {
	t.Run("Create a Key Access object - Happy Path", func(t *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		id := "test-id"
		kid := "test-kid"
		assert.NoError(t, err)
		ka, err := NewDataIntegrityKeyAccess(id, kid, privKey)
		assert.NoError(t, err)
		assert.NotEmpty(t, ka)
	})

	t.Run("Create a Key Access object - Bad Key", func(t *testing.T) {
		id := "test-id"
		kid := "test-kid"
		ka, err := NewDataIntegrityKeyAccess(id, kid, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key cannot be nil")
		assert.Empty(t, ka)
	})

	t.Run("Create a Key Access object - No KID", func(t *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		assert.NoError(t, err)
		ka, err := NewDataIntegrityKeyAccess("test-id", "", privKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "kid cannot be empty")
		assert.Empty(t, ka)
	})
}

func TestDataIntegrityKeyAccessSignVerify(t *testing.T) {
	t.Run("Sign and Verify Credential - Happy Path", func(t *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		id := "test-id"
		kid := "test-kid"
		assert.NoError(t, err)
		ka, err := NewDataIntegrityKeyAccess(id, kid, privKey)
		assert.NoError(t, err)
		assert.NotEmpty(t, ka)

		// sign
		testCred := getTestCredential(id)
		signedCred, err := ka.Sign(&testCred)
		assert.NoError(t, err)
		assert.NotEmpty(t, signedCred)

		var cred credential.VerifiableCredential
		err = json.Unmarshal(signedCred.Data, &cred)
		assert.NoError(t, err)

		// verify
		err = ka.Verify(&cred)
		assert.NoError(t, err)
	})

	t.Run("Sign and Verify Credential - Bad Data", func(t *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		id := "test-id"
		kid := "test-kid"
		assert.NoError(t, err)
		ka, err := NewDataIntegrityKeyAccess(id, kid, privKey)
		assert.NoError(t, err)
		assert.NotEmpty(t, ka)

		// sign
		_, err = ka.Sign(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "payload cannot be nil")
	})

	t.Run("Sign and Verify Credential - Bad Signature", func(t *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		id := "test-id"
		kid := "test-kid"
		assert.NoError(t, err)
		ka, err := NewDataIntegrityKeyAccess(id, kid, privKey)
		assert.NoError(t, err)
		assert.NotEmpty(t, ka)

		// verify
		err = ka.Verify(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "payload cannot be nil")
	})

	t.Run("Sign and Verify Presentation", func(t *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		id := "test-id"
		kid := "test-kid"
		assert.NoError(t, err)
		ka, err := NewDataIntegrityKeyAccess(id, kid, privKey)
		assert.NoError(t, err)
		assert.NotEmpty(t, ka)

		// sign
		testPres := getDataIntegrityTestPresentation(*ka)
		signedPres, err := ka.Sign(&testPres)
		assert.NoError(t, err)
		assert.NotEmpty(t, signedPres)

		var pres credential.VerifiablePresentation
		err = json.Unmarshal(signedPres.Data, &pres)
		assert.NoError(t, err)

		// verify
		err = ka.Verify(&pres)
		assert.NoError(t, err)

		// TODO(gabe) enable with https://github.com/TBD54566975/ssi-sdk/issues/352, https://github.com/TBD54566975/ssi-service/issues/105
		err = ka.VerifyVerifiablePresentation(&pres)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not implemented")
	})
}
