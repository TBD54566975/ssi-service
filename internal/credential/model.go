package credential

import (
	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/signing"
	"github.com/pkg/errors"
)

// CredentialContainer acts as an abstraction over both possible credential representations
// JWT representations are parsed upon container creation, while the original JWT is maintained
type CredentialContainer struct {
	// Credential ID
	ID            string
	Credential    *credential.VerifiableCredential
	CredentialJWT *string
}

func NewCredentialContainerFromJWT(credentialJWT string) (*CredentialContainer, error) {
	cred, err := signing.ParseVerifiableCredentialFromJWT(credentialJWT)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse credential from JWT")
	}
	return &CredentialContainer{
		ID:            cred.ID,
		Credential:    cred,
		CredentialJWT: &credentialJWT,
	}, nil
}

func (cc CredentialContainer) IsValid() bool {
	return cc.ID != "" && (cc.HasDataIntegrityCredential() || cc.HasJWTCredential())
}

func (cc CredentialContainer) HasDataIntegrityCredential() bool {
	return cc.Credential != nil && cc.Credential.Proof != nil
}

func (cc CredentialContainer) HasJWTCredential() bool {
	return cc.CredentialJWT != nil
}
