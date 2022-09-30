package credential

import (
	"github.com/TBD54566975/ssi-sdk/credential"
)

// CredentialContainer acts as a mutually exclusive abstraction over both possible credential representations
type CredentialContainer struct {
	// Credential ID
	ID            string
	Credential    *credential.VerifiableCredential
	CredentialJWT *string
}

func (cc CredentialContainer) IsValid() bool {
	return (cc.Credential != nil && cc.CredentialJWT == nil) ||
		(cc.Credential == nil && cc.CredentialJWT != nil)
}

func (cc CredentialContainer) HasDataIntegrityCredential() bool {
	return cc.Credential != nil
}

func (cc CredentialContainer) HasJWTCredential() bool {
	return cc.CredentialJWT != nil
}

type CredentialsContainer struct {
	Credentials    []credential.VerifiableCredential
	CredentialJWTs []string
}

func (ccs CredentialsContainer) IsValid() bool {
	return (len(ccs.Credentials) != 0 && len(ccs.CredentialJWTs) == 0) ||
		(len(ccs.Credentials) == 0 && len(ccs.CredentialJWTs) != 0)
}

func (ccs CredentialsContainer) HasDataIntegrityCredential() bool {
	return len(ccs.Credentials) != 0
}

func (ccs CredentialsContainer) HasJWTCredential() bool {
	return len(ccs.CredentialJWTs) != 0
}
