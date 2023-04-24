package keyaccess

import (
	gocrypto "crypto"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/cryptosuite"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
)

// TODO(gabe) integrate signing for Data Integrity as well in https://github.com/TBD54566975/ssi-service/issues/105

// DataIntegrityKeyAccess represents a key access object for data integrity using the JsonWebSignature2020 suite:
// https://w3c.github.io/vc-jws-2020/
type DataIntegrityKeyAccess struct {
	cryptosuite.JSONWebKeySigner
	cryptosuite.JSONWebKeyVerifier
	cryptosuite.CryptoSuite
}

// NewDataIntegrityKeyAccess creates a new DataIntegrityKeyAccess object from an id, key id, and private key, generating both
// JSON Web Key Signer and Verifier objects.
func NewDataIntegrityKeyAccess(id, kid string, key gocrypto.PrivateKey) (*DataIntegrityKeyAccess, error) {
	if kid == "" {
		return nil, errors.New("kid cannot be empty")
	}
	if key == nil {
		return nil, errors.New("key cannot be nil")
	}
	publicKeyJWK, privateKeyJWK, err := crypto.PrivateKeyToPrivateKeyJWK(key)
	if err != nil {
		return nil, errors.Wrapf(err, "could not convert private key to JWK: %s", kid)
	}
	signer, err := cryptosuite.NewJSONWebKeySigner(id, kid, *privateKeyJWK, cryptosuite.AssertionMethod)
	if err != nil {
		return nil, errors.Wrapf(err, "could not create JWK signer: %s", kid)
	}
	verifier, err := cryptosuite.NewJSONWebKeyVerifier(id, *publicKeyJWK)
	if err != nil {
		return nil, errors.Wrapf(err, "could not create JWK verifier: %s", kid)
	}
	return &DataIntegrityKeyAccess{
		JSONWebKeySigner:   *signer,
		JSONWebKeyVerifier: *verifier,
		CryptoSuite:        cryptosuite.GetJSONWebSignature2020Suite(),
	}, nil
}

// DataIntegrityJSON represents a response from a DataIntegrityKeyAccess.Sign() call represented
// as a serialized JSON object
type DataIntegrityJSON struct {
	Data []byte `json:"data" validate:"required"`
}

func (ka DataIntegrityKeyAccess) Sign(payload cryptosuite.Provable) (*DataIntegrityJSON, error) {
	if payload == nil {
		return nil, errors.New("payload cannot be nil")
	}
	if err := ka.CryptoSuite.Sign(&ka.JSONWebKeySigner, payload); err != nil {
		return nil, errors.Wrap(err, "could not sign payload")
	}
	signedJSONBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal signed payload")
	}
	return &DataIntegrityJSON{Data: signedJSONBytes}, nil
}

func (ka DataIntegrityKeyAccess) Verify(payload cryptosuite.Provable) error {
	if payload == nil {
		return errors.New("payload cannot be nil")
	}
	if err := ka.CryptoSuite.Verify(&ka.JSONWebKeyVerifier, payload); err != nil {
		return errors.Wrap(err, "could not verify payload")
	}
	return nil
}

func (ka DataIntegrityKeyAccess) SignVerifiablePresentation(audience string, presentation credential.VerifiablePresentation) (*DataIntegrityJSON, error) {
	return nil, errors.New("not implemented")
}

func (ka DataIntegrityKeyAccess) VerifyVerifiablePresentation(presentation cryptosuite.Provable) error {
	return errors.New("not implemented")
}
