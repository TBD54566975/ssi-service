package router

import (
	"os"
	"testing"

	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/stretchr/testify/require"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

// generic test config to be used by all tests in this package

type testService struct{}

func (s *testService) Type() framework.Type {
	return "test"
}

func (s *testService) Status() framework.Status {
	return framework.Status{Status: "ready"}
}

func (s *testService) Config() config.ServicesConfig {
	return config.ServicesConfig{
		StorageProvider:  "bolt",
		KeyStoreConfig:   config.KeyStoreServiceConfig{MasterKeyPassword: "test-password"},
		DIDConfig:        config.DIDServiceConfig{Methods: []string{string(didsdk.KeyMethod)}},
		SchemaConfig:     config.SchemaServiceConfig{},
		CredentialConfig: config.CredentialServiceConfig{},
		ManifestConfig:   config.ManifestServiceConfig{},
	}
}

func setupTestDB(t *testing.T) storage.ServiceStorage {
	file, err := os.CreateTemp("", "bolt")
	require.NoError(t, err)
	name := file.Name()
	err = file.Close()
	require.NoError(t, err)
	s, err := storage.NewStorage(storage.Bolt, storage.Option{
		ID:     storage.BoltDBFilePathOption,
		Option: name,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = s.Close()
		_ = os.Remove(s.URI())
	})
	return s
}
