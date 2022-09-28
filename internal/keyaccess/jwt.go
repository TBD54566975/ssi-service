package keyaccess

import (
	gocrypto "crypto"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/signing"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
)

type JWKKeyAccess struct {
	crypto.JWTSigner
	crypto.JWTVerifier
}

// NewJWKKeyAccess creates a new JWKKeyAccess object from a key id and private key, generating both
// JWT Signer and Verifier objects.
func NewJWKKeyAccess(kid string, key gocrypto.PrivateKey) (*JWKKeyAccess, error) {
	if kid == "" {
		return nil, errors.New("kid cannot be empty")
	}
	if key == nil {
		return nil, errors.New("key cannot be nil")
	}
	gotJWK, err := jwk.New(key)
	if err != nil {
		return nil, errors.Wrap(err, "could not create jwk from private key")
	}
	signer, err := crypto.NewJWTSigner(kid, gotJWK)
	if err != nil {
		return nil, errors.Wrapf(err, "could not create JWK Key Access object for kid: %s, error creating signer", kid)
	}
	verifier, err := signer.ToVerifier()
	if err != nil {
		return nil, errors.Wrapf(err, "could not create JWK Key Access object for kid: %s, error creating verifier", kid)
	}
	return &JWKKeyAccess{
		JWTSigner:   *signer,
		JWTVerifier: *verifier,
	}, nil
}

// A JWKToken is a utility that wraps a string representation of a JSON Web Token.
type JWKToken struct {
	Token string `json:"token" validate:"required"`
}

func (ka JWKKeyAccess) Sign(payload map[string]interface{}) (*JWKToken, error) {
	if payload == nil {
		return nil, errors.New("payload cannot be nil")
	}
	tokenBytes, err := ka.SignJWT(payload)
	if err != nil {
		return nil, errors.Wrap(err, "could not sign payload")
	}
	return &JWKToken{Token: string(tokenBytes)}, nil
}

func (ka JWKKeyAccess) Verify(token JWKToken) error {
	if token.Token == "" {
		return errors.New("token cannot be empty")
	}
	return ka.VerifyJWT(token.Token)
}

func (ka JWKKeyAccess) SignVerifiableCredential(credential credential.VerifiableCredential) (*JWKToken, error) {
	if err := credential.IsValid(); err != nil {
		return nil, errors.New("cannot sign invalid credential")
	}
	tokenBytes, err := signing.SignVerifiableCredentialJWT(ka.JWTSigner, credential)
	if err != nil {
		return nil, errors.Wrap(err, "could not sign credential")
	}
	return &JWKToken{Token: string(tokenBytes)}, nil
}

func (ka JWKKeyAccess) VerifyVerifiableCredential(token JWKToken) (*credential.VerifiableCredential, error) {
	if token.Token == "" {
		return nil, errors.New("token cannot be empty")
	}
	return signing.VerifyVerifiableCredentialJWT(ka.JWTVerifier, token.Token)
}

func (ka JWKKeyAccess) SignVerifiablePresentation(presentation credential.VerifiablePresentation) (*JWKToken, error) {
	if err := presentation.IsValid(); err != nil {
		return nil, errors.New("cannot sign invalid presentation")
	}
	tokenBytes, err := signing.SignVerifiablePresentationJWT(ka.JWTSigner, presentation)
	if err != nil {
		return nil, errors.Wrap(err, "could not sign presentation")
	}
	return &JWKToken{Token: string(tokenBytes)}, nil
}

func (ka JWKKeyAccess) VerifyVerifiablePresentation(token JWKToken) (*credential.VerifiablePresentation, error) {
	if token.Token == "" {
		return nil, errors.New("token cannot be empty")
	}
	return signing.VerifyVerifiablePresentationJWT(ka.JWTVerifier, token.Token)
}
