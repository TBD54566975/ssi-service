package router

import (
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
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
