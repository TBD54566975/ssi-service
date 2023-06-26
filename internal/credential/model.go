package credential

import (
	"fmt"
	"reflect"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/parsing"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"

	"github.com/tbd54566975/ssi-service/internal/keyaccess"
)

// Container acts as an abstraction over both possible credential representations
// JWT representations are parsed upon container creation, while the original JWT is maintained
type Container struct {
	// UUID assigned by the ssi-service. For example, 48958871-6a6d-4a25-889f-88c9c6835780. The `credential.id`
	// value will be a URL that can be dereferenced, which includes this ID.
	ID string `json:"id,omitempty"`

	// The KID of the private key used to sign `credentialJwt`.
	IssuerKID string `json:"issuerKid,omitempty"`

	// Verifiable Credential in the `application/vc+ld+json` format. The credential is secured with an external proof
	// using JWS. In other words, the `proof` field is not present. See `credentialJwt` for the secured Verifiable
	// Credential.
	Credential *credential.VerifiableCredential `json:"credential,omitempty"`

	// JWT representation of `credential`, secured with an external proof signed by `issuerKid`.
	CredentialJWT *keyaccess.JWT `json:"credentialJwt,omitempty"`

	// Whether this credential is currently revoked.
	Revoked bool `json:"revoked,omitempty"`

	// Whether this credential is currently suspended.
	Suspended bool `json:"suspended,omitempty"`
}

func (c Container) JWTString() string {
	return string(*c.CredentialJWT)
}

func (c Container) IsValid() bool {
	return c.Credential != nil && c.Credential.ID != "" && (c.HasDataIntegrityCredential() || c.HasJWTCredential())
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
	_, _, cred, err := parsing.ToCredential(credentialJWT)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse credential from JWT")
	}
	return &Container{
		Credential:    cred,
		CredentialJWT: keyaccess.JWTPtr(credentialJWT),
	}, nil
}

// NewCredentialContainerFromMap attempts to parse a data integrity credential from a piece of JSON,
// which is represented as a map in go, into a Container
func NewCredentialContainerFromMap(credMap map[string]any) (*Container, error) {
	_, _, cred, err := parsing.ToCredential(credMap)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse credential from map")
	}
	container := Container{
		Credential: cred,
	}
	if container.HasDataIntegrityCredential() {
		return &container, nil
	}
	return nil, errors.New("credential does not have a data integrity proof")
}

func ContainersToInterface(cs []Container) []any {
	var credentials []any
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
func NewCredentialContainerFromArray(creds []any) ([]Container, error) {
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
		case map[string]any:
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

// CopyCredential copies a credential into a new credential
func CopyCredential(c credential.VerifiableCredential) (*credential.VerifiableCredential, error) {
	var cred credential.VerifiableCredential
	credBytes, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(credBytes, &cred)
	return &cred, err
}
