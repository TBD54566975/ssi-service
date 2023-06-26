package keyaccess

import (
	"context"
	gocrypto "crypto"
	"fmt"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/integrity"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/did/resolution"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/pkg/errors"
)

type JWKKeyAccess struct {
	*jwx.Signer
	*jwx.Verifier
}

// NewJWKKeyAccess creates a JWKKeyAccess object from an id, key id, and private key, generating both
// JWT Signer and Verifier objects.
func NewJWKKeyAccess(id, kid string, key gocrypto.PrivateKey) (*JWKKeyAccess, error) {
	if id == "" {
		return nil, errors.New("id cannot be empty")
	}
	if kid == "" {
		return nil, errors.New("kid cannot be empty")
	}
	if key == nil {
		return nil, errors.New("key cannot be nil")
	}
	signer, err := jwx.NewJWXSigner(id, kid, key)
	if err != nil {
		return nil, errors.Wrapf(err, "could not create JWK Key Access object for kid: %s, error creating signer", kid)
	}
	verifier, err := signer.ToVerifier(id)
	if err != nil {
		return nil, errors.Wrapf(err, "could not create JWK Key Access object for kid: %s, error creating verifier", kid)
	}
	return &JWKKeyAccess{
		Signer:   signer,
		Verifier: verifier,
	}, nil
}

// NewJWKKeyAccessVerifier creates JWKKeyAccess object from an id, key id, and public key, generating a JWT Verifier object.
func NewJWKKeyAccessVerifier(id, kid string, key gocrypto.PublicKey) (*JWKKeyAccess, error) {
	if id == "" {
		return nil, errors.New("id cannot be empty")
	}
	if kid == "" {
		return nil, errors.New("kid cannot be empty")
	}
	if key == nil {
		return nil, errors.New("key cannot be nil")
	}
	verifier, err := jwx.NewJWXVerifier(id, kid, key)
	if err != nil {
		return nil, errors.Wrapf(err, "could not create JWK Key Access object for kid: %s, error creating verifier", kid)
	}
	return &JWKKeyAccess{Verifier: verifier}, nil
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
	if ka.Signer == nil {
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
	if ka.Signer == nil {
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

func (ka JWKKeyAccess) SignVerifiableCredential(cred credential.VerifiableCredential) (*JWT, error) {
	if ka.Signer == nil {
		return nil, errors.New("cannot sign with nil signer")
	}
	if err := cred.IsValid(); err != nil {
		return nil, errors.New("cannot sign invalid credential")
	}

	tokenBytes, err := integrity.SignVerifiableCredentialJWT(*ka.Signer, cred)
	if err != nil {
		return nil, errors.Wrap(err, "could not sign cred")
	}
	return JWT(tokenBytes).Ptr(), nil
}

func (ka JWKKeyAccess) VerifyVerifiableCredential(token JWT) (*credential.VerifiableCredential, error) {
	if token == "" {
		return nil, errors.New("token cannot be empty")
	}
	_, _, verifiableCredential, err := integrity.VerifyVerifiableCredentialJWT(*ka.Verifier, token.String())
	return verifiableCredential, err
}

func (ka JWKKeyAccess) SignVerifiablePresentation(audience string, presentation credential.VerifiablePresentation) (*JWT, error) {
	if ka.Signer == nil {
		return nil, errors.New("cannot sign with nil signer")
	}
	if err := presentation.IsValid(); err != nil {
		return nil, errors.New("cannot sign invalid presentation")
	}
	tokenBytes, err := integrity.SignVerifiablePresentationJWT(*ka.Signer, integrity.JWTVVPParameters{Audience: []string{audience}}, presentation)
	if err != nil {
		return nil, errors.Wrap(err, "could not sign presentation")
	}
	return JWT(tokenBytes).Ptr(), nil
}

func (ka JWKKeyAccess) VerifyVerifiablePresentation(ctx context.Context, resolver resolution.Resolver, token JWT) (*credential.VerifiablePresentation, error) {
	if token == "" {
		return nil, errors.New("token cannot be empty")
	}
	_, _, presentation, err := integrity.VerifyVerifiablePresentationJWT(ctx, *ka.Verifier, resolver, token.String())
	return presentation, err
}

// GetJWTHeaders returns the headers of a JWT token, assuming there is only one signature.
func GetJWTHeaders(token []byte) (jws.Headers, error) {
	msg, err := jws.Parse(token)
	if err != nil {
		return nil, err
	}
	if len(msg.Signatures()) != 1 {
		return nil, fmt.Errorf("expected 1 signature, got %d", len(msg.Signatures()))
	}
	return msg.Signatures()[0].ProtectedHeaders(), nil
}
