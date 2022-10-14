package credential

import (
	"fmt"
	"reflect"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/signing"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"

	"github.com/tbd54566975/ssi-service/internal/keyaccess"
)

// Container acts as an abstraction over both possible credential representations
// JWT representations are parsed upon container creation, while the original JWT is maintained
type Container struct {
	// Credential ID
	ID            string
	Credential    *credential.VerifiableCredential
	CredentialJWT *keyaccess.JWT
}

func (c Container) JWTString() string {
	return string(*c.CredentialJWT)
}

// NewCredentialContainerFromJWT attempts to parse a VC-JWT credential from a string into a Container
func NewCredentialContainerFromJWT(credentialJWT string) (*Container, error) {
	cred, err := signing.ParseVerifiableCredentialFromJWT(credentialJWT)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse credential from JWT")
	}
	return &Container{
		ID:            cred.ID,
		CredentialJWT: keyaccess.JWTPtr(credentialJWT),
	}, nil
}

// NewCredentialContainerFromMap attempts to parse a data integrity credential from a piece of JSON,
// which is represented as a map in go, into a Container
func NewCredentialContainerFromMap(credMap map[string]interface{}) (*Container, error) {
	var cred credential.VerifiableCredential
	credMapBytes, err := json.Marshal(credMap)
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal credential map")
	}
	if err = json.Unmarshal(credMapBytes, &cred); err != nil {
		return nil, errors.Wrap(err, "could not unmarshal credential map")
	}
	container := Container{
		ID:         cred.ID,
		Credential: &cred,
	}
	if container.HasDataIntegrityCredential() {
		return &container, nil
	}
	return nil, errors.New("credential does not have a data integrity proof")
}

func (cc Container) IsValid() bool {
	return cc.ID != "" && (cc.HasDataIntegrityCredential() || cc.HasJWTCredential())
}

func (cc Container) HasSignedCredential() bool {
	return cc.HasDataIntegrityCredential() || cc.HasJWTCredential()
}

func (cc Container) HasDataIntegrityCredential() bool {
	return cc.Credential != nil && cc.Credential.Proof != nil
}

func (cc Container) HasJWTCredential() bool {
	return cc.CredentialJWT != nil
}

// NewCredentialContainerFromArray attempts to parse arrays of credentials of any type (either data integrity or JWT)
// into an array of CredentialContainers. The method will return an error if any of the credentials are invalid.
func NewCredentialContainerFromArray(creds []interface{}) ([]Container, error) {
	var containers []Container
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
