package storage

import (
	"fmt"

	"github.com/TBD54566975/ssi-sdk/credential/manifest"

	cred "github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type StoredManifest struct {
	ID          string                      `json:"id"`
	Issuer      string                      `json:"issuer"`
	Manifest    manifest.CredentialManifest `json:"manifest"`
	ManifestJWT keyaccess.JWT               `json:"manifestJwt"`
}

type StoredApplication struct {
	ID             string                         `json:"id"`
	ManifestID     string                         `json:"manifestId"`
	ApplicantDID   string                         `json:"applicantDid"`
	Application    manifest.CredentialApplication `json:"application"`
	Credentials    []cred.Container               `json:"credentials"`
	ApplicationJWT keyaccess.JWT                  `json:"applicationJwt"`
}

type StoredResponse struct {
	ID           string                      `json:"id"`
	ManifestID   string                      `json:"manifestId"`
	ApplicantDID string                      `json:"applicantId"`
	Response     manifest.CredentialResponse `json:"response"`
	Credentials  []cred.Container            `json:"credentials"`
	ResponseJWT  keyaccess.JWT               `json:"responseJwt"`
}

type Storage interface {
	CredentialManifestStorage
	CredentialApplicationStorage
	CredentialResponseStorage
}

type CredentialManifestStorage interface {
	StoreManifest(manifest StoredManifest) error
	GetManifest(id string) (*StoredManifest, error)
	GetManifests() ([]StoredManifest, error)
	DeleteManifest(id string) error
}

type CredentialApplicationStorage interface {
	StoreApplication(application StoredApplication) error
	GetApplication(id string) (*StoredApplication, error)
	GetApplications() ([]StoredApplication, error)
	DeleteApplication(id string) error
}

type CredentialResponseStorage interface {
	StoreResponse(response StoredResponse) error
	GetResponse(id string) (*StoredResponse, error)
	GetResponses() ([]StoredResponse, error)
	DeleteResponse(id string) error
}

// NewManifestStorage finds the manifest storage impl for a given ServiceStorage value
func NewManifestStorage(s storage.ServiceStorage) (Storage, error) {
	switch s.Type() {
	case storage.Bolt:
		gotBolt, ok := s.(*storage.BoltDB)
		if !ok {
			errMsg := fmt.Sprintf("trouble instantiating : %s", s.Type())
			return nil, util.LoggingNewError(errMsg)
		}
		boltStorage, err := NewBoltManifestStorage(gotBolt)
		if err != nil {
			return nil, util.LoggingErrorMsg(err, "could not instantiate manifest bolt storage")
		}
		return boltStorage, err
	default:
		errMsg := fmt.Errorf("unsupported storage type: %s", s.Type())
		return nil, util.LoggingError(errMsg)
	}
}
