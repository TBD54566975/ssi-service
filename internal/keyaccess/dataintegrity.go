package keyaccess

import (
	gocrypto "crypto"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/cryptosuite"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
)

// TODO(gabe) handle signing for Data Integrity as well

// DataIntegrityKeyAccess TODO to be handled in https://github.com/TBD54566975/ssi-service/issues/105
type DataIntegrityKeyAccess struct {
	cryptosuite.JSONWebKeySigner
	cryptosuite.JSONWebKeyVerifier
	cryptosuite.CryptoSuite
}

// NewDataIntegrityKeyAccess creates a new DataIntegrityKeyAccess object from a key id and private key, generating both
// JSON Web Key Signer and Verifier objects.
func NewDataIntegrityKeyAccess(kid string, key gocrypto.PrivateKey) (*DataIntegrityKeyAccess, error) {
	publicKeyJWK, privateKeyJWK, err := crypto.PrivateKeyToPrivateKeyJWK(key)
	if err != nil {
		return nil, errors.Wrapf(err, "could not convert private key to JWK: %s", kid)
	}
	signer, err := cryptosuite.NewJSONWebKeySigner(kid, *privateKeyJWK, cryptosuite.AssertionMethod)
	if err != nil {
		return nil, errors.Wrapf(err, "could not create JWK signer: %s", kid)
	}
	verifier, err := cryptosuite.NewJSONWebKeyVerifier(kid, *publicKeyJWK)
	if err != nil {
		return nil, errors.Wrapf(err, "could not create JWK verifier: %s", kid)
	}
	return &DataIntegrityKeyAccess{
		JSONWebKeySigner:   *signer,
		JSONWebKeyVerifier: *verifier,
		CryptoSuite:        cryptosuite.GetJSONWebSignature2020Suite(),
	}, nil
}

func (ka *DataIntegrityKeyAccess) Sign(payload cryptosuite.Provable) ([]byte, error) {
	if err := ka.CryptoSuite.Sign(&ka.JSONWebKeySigner, payload); err != nil {
		return nil, errors.Wrap(err, "could not sign payload")
	}
	signedJSONBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal signed payload")
	}
	return signedJSONBytes, nil
}

func (ka *DataIntegrityKeyAccess) Verify(payload cryptosuite.Provable) error {
	if err := ka.CryptoSuite.Verify(&ka.JSONWebKeyVerifier, payload); err != nil {
		return errors.Wrap(err, "could not verify payload")
	}
	return nil
}
