package keyaccess

type SigningConfig struct {
	// e.g. did:example:abcd#key-1
	SigningKey string `json:"signingKey" validate:"required"`
	// Where the value is either "JWT" or an LD Signature Suite such as "JsonWebSignature2020"
	SignatureType string `json:"signatureType" validate:"required"`
}

type VerificationConfig struct {
	// e.g. did:example:abcd#key-1
	VerificationKey string `json:"verificationKey" validate:"required"`
}

type KeyAccess interface {
	Sign(config SigningConfig, payload []byte) ([]byte, error)
	Verify(config VerificationConfig, payload []byte, signature []byte) error
}

type JWKKeyAccess struct{}

func (jwk *JWKKeyAccess) Sign(config SigningConfig, payload []byte) ([]byte, error) {
	return nil, nil
}

func (jwk *JWKKeyAccess) Verify(config VerificationConfig, payload []byte, signature []byte) error {
	return nil
}

type LDKeyAccess struct{}

func (ld *LDKeyAccess) Sign(config SigningConfig, payload []byte) ([]byte, error) {
	return nil, nil
}

func (ld *LDKeyAccess) Verify(config VerificationConfig, payload []byte, signature []byte) error {
	return nil
}
