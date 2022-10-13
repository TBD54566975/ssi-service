package credential

import (
	"fmt"
	"reflect"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/signing"
	"github.com/goccy/go-json"
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

// NewCredentialContainerFromJWT attempts to parse a VC-JWT credential from a string into a CredentialContainer
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

// NewCredentialContainerFromMap attempts to parse a data integrity credential from a piece of JSON,
// which is represented as a map in go, into a CredentialContainer
func NewCredentialContainerFromMap(credMap map[string]interface{}) (*CredentialContainer, error) {
	var cred credential.VerifiableCredential
	credMapBytes, err := json.Marshal(credMap)
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal credential map")
	}
	if err = json.Unmarshal(credMapBytes, &cred); err != nil {
		return nil, errors.Wrap(err, "could not unmarshal credential map")
	}
	container := CredentialContainer{
		ID:         cred.ID,
		Credential: &cred,
	}
	if container.HasDataIntegrityCredential() {
		return &container, nil
	}
	return nil, errors.New("credential does not have a data integrity proof")
}

func (cc CredentialContainer) IsValid() bool {
	return cc.ID != "" && (cc.HasDataIntegrityCredential() || cc.HasJWTCredential())
}

func (cc CredentialContainer) HasSignedCredential() bool {
	return cc.HasDataIntegrityCredential() || cc.HasJWTCredential()
}

func (cc CredentialContainer) HasDataIntegrityCredential() bool {
	return cc.Credential != nil && cc.Credential.Proof != nil
}

func (cc CredentialContainer) HasJWTCredential() bool {
	return cc.CredentialJWT != nil
}

// NewCredentialContainerFromArray attempts to parse arrays of credentials of any type (either data integrity or JWT)
// into an array of CredentialContainers. The method will return an error if any of the credentials are invalid.
func NewCredentialContainerFromArray(creds []interface{}) ([]CredentialContainer, error) {
	var containers []CredentialContainer
	for _, c := range creds {
		switch c.(type) {
		case string:
			// JWT
			container, err := NewCredentialContainerFromJWT(c.(string))
			if err != nil {
				return nil, errors.Wrap(err, "could not parse credential from JWT")
			}
			containers = append(containers, *container)
		case map[string]interface{}:
			// JSON
			container, err := NewCredentialContainerFromMap(c.(map[string]interface{}))
			if err != nil {
				return nil, errors.Wrap(err, "could not parse credential from JSON")
			}
			containers = append(containers, *container)
		default:
			return nil, fmt.Errorf("invalid credential type: %s", reflect.TypeOf(c).Name())
		}
	}
	return containers, nil
}
