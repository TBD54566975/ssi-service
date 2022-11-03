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

func (c Container) IsValid() bool {
	return c.ID != "" && (c.HasDataIntegrityCredential() || c.HasJWTCredential())
}

func (c Container) HasSignedCredential() bool {
	return c.HasDataIntegrityCredential() || c.HasJWTCredential()
}

func (c Container) HasDataIntegrityCredential() bool {
	return c.Credential != nil && c.Credential.Proof != nil
}

func (c Container) HasJWTCredential() bool {
	return c.CredentialJWT != nil
}

// NewCredentialContainerFromJWT attempts to parse a VC-JWT credential from a string into a Container
func NewCredentialContainerFromJWT(credentialJWT string) (*Container, error) {
	cred, err := signing.ParseVerifiableCredentialFromJWT(credentialJWT)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse credential from JWT")
	}
	return &Container{
		ID:            cred.ID,
		Credential:    cred,
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

func ContainersToInterface(cs []Container) []interface{} {
	var credentials []interface{}
	for _, container := range cs {
		if container.HasDataIntegrityCredential() {
			credentials = append(credentials, *container.Credential)
		} else if container.HasJWTCredential() {
			credentials = append(credentials, *container.CredentialJWT)
		}
	}
	return credentials
}

// NewCredentialContainerFromArray attempts to parse arrays of credentials of any type (either data integrity or JWT)
// into an array of CredentialContainers. The method will return an error if any of the credentials are invalid.
func NewCredentialContainerFromArray(creds []interface{}) ([]Container, error) {
	var containers []Container
	for _, c := range creds {
		switch v := c.(type) {
		case string:
			// JWT
			container, err := NewCredentialContainerFromJWT(v)
			if err != nil {
				return nil, errors.Wrap(err, "could not parse credential from JWT")
			}
			containers = append(containers, *container)
		case map[string]interface{}:
			// JSON
			container, err := NewCredentialContainerFromMap(v)
			if err != nil {
				return nil, errors.Wrap(err, "could not parse credential from JSON")
			}
			containers = append(containers, *container)
		default:
			return nil, fmt.Errorf("invalid credential type: %s", reflect.TypeOf(c).Kind().String())
		}
	}
	return containers, nil
}
