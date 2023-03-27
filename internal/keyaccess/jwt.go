package keyaccess

import (
	gocrypto "crypto"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/signing"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
)

type JWKKeyAccess struct {
	*crypto.JWTSigner
	*crypto.JWTVerifier
}

// NewJWKKeyAccess creates a JWKKeyAccess object from a key id and private key, generating both
// JWT Signer and Verifier objects.
func NewJWKKeyAccess(kid string, key gocrypto.PrivateKey) (*JWKKeyAccess, error) {
	if kid == "" {
		return nil, errors.New("kid cannot be empty")
	}
	if key == nil {
		return nil, errors.New("key cannot be nil")
	}
	signer, err := crypto.NewJWTSigner(kid, key)
	if err != nil {
		return nil, errors.Wrapf(err, "could not create JWK Key Access object for kid: %s, error creating signer", kid)
	}
	verifier, err := signer.ToVerifier()
	if err != nil {
		return nil, errors.Wrapf(err, "could not create JWK Key Access object for kid: %s, error creating verifier", kid)
	}
	return &JWKKeyAccess{
		JWTSigner:   signer,
		JWTVerifier: verifier,
	}, nil
}

// NewJWKKeyAccessVerifier creates JWKKeyAccess object from a key id and public key, generating a JWT Verifier object.
func NewJWKKeyAccessVerifier(kid string, key gocrypto.PublicKey) (*JWKKeyAccess, error) {
	if kid == "" {
		return nil, errors.New("kid cannot be empty")
	}
	if key == nil {
		return nil, errors.New("key cannot be nil")
	}
	verifier, err := crypto.NewJWTVerifier(kid, key)
	if err != nil {
		return nil, errors.Wrapf(err, "could not create JWK Key Access object for kid: %s, error creating verifier", kid)
	}
	return &JWKKeyAccess{
		JWTVerifier: verifier,
	}, nil
}

type JWT string

func (j JWT) String() string {
	return string(j)
}

func (j JWT) Ptr() *JWT {
	return &j
}

func JWTPtr(j string) *JWT {
	jwt := JWT(j)
	return &jwt
}

// SignJSON takes an object that is either itself json or json-serializable and signs it.
func (ka JWKKeyAccess) SignJSON(data any) (*JWT, error) {
	if ka.JWTSigner == nil {
		return nil, errors.New("cannot sign with nil signer")
	}
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	payload := make(map[string]any)
	if err = json.Unmarshal(jsonBytes, &payload); err != nil {
		return nil, err
	}
	return ka.Sign(payload)
}

func (ka JWKKeyAccess) Sign(payload map[string]any) (*JWT, error) {
	if ka.JWTSigner == nil {
		return nil, errors.New("cannot sign with nil signer")
	}
	if payload == nil {
		return nil, errors.New("payload cannot be nil")
	}
	tokenBytes, err := ka.SignWithDefaults(payload)
	if err != nil {
		return nil, errors.Wrap(err, "could not sign payload")
	}
	return JWT(tokenBytes).Ptr(), nil
}

func (ka JWKKeyAccess) Verify(token JWT) error {
	if token == "" {
		return errors.New("token cannot be empty")
	}
	return ka.VerifyJWS(string(token))
}

func (ka JWKKeyAccess) SignVerifiableCredential(credential credential.VerifiableCredential) (*JWT, error) {
	if ka.JWTSigner == nil {
		return nil, errors.New("cannot sign with nil signer")
	}
	if err := credential.IsValid(); err != nil {
		return nil, errors.New("cannot sign invalid credential")
	}
	tokenBytes, err := signing.SignVerifiableCredentialJWT(*ka.JWTSigner, credential)
	if err != nil {
		return nil, errors.Wrap(err, "could not sign credential")
	}
	return JWT(tokenBytes).Ptr(), nil
}

func (ka JWKKeyAccess) VerifyVerifiableCredential(token JWT) (*credential.VerifiableCredential, error) {
	if token == "" {
		return nil, errors.New("token cannot be empty")
	}
	return signing.VerifyVerifiableCredentialJWT(*ka.JWTVerifier, token.String())
}

func (ka JWKKeyAccess) SignVerifiablePresentation(presentation credential.VerifiablePresentation) (*JWT, error) {
	if ka.JWTSigner == nil {
		return nil, errors.New("cannot sign with nil signer")
	}
	if err := presentation.IsValid(); err != nil {
		return nil, errors.New("cannot sign invalid presentation")
	}
	tokenBytes, err := signing.SignVerifiablePresentationJWT(*ka.JWTSigner, presentation)
	if err != nil {
		return nil, errors.Wrap(err, "could not sign presentation")
	}
	return JWT(tokenBytes).Ptr(), nil
}

func (ka JWKKeyAccess) VerifyVerifiablePresentation(token JWT) (*credential.VerifiablePresentation, error) {
	if token == "" {
		return nil, errors.New("token cannot be empty")
	}
	return signing.VerifyVerifiablePresentationJWT(*ka.JWTVerifier, token.String())
}
