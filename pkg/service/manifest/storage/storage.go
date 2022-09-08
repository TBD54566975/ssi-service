package storage

import (
	"fmt"
	"github.com/TBD54566975/ssi-sdk/credential/manifest"

	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type StoredManifest struct {
	ID       string                      `json:"id"`
	Manifest manifest.CredentialManifest `json:"manifest"`
	Issuer   string                      `json:"issuer"`
}

type Storage interface {
	StoreManifest(manifest StoredManifest) error
	GetManifest(id string) (*StoredManifest, error)
	GetManifests() ([]StoredManifest, error)
	DeleteManifest(id string) error
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
