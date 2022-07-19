package router

import (
	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
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
		DIDConfig:        config.DIDServiceConfig{Methods: []string{string(did.KeyMethod)}},
		SchemaConfig:     config.SchemaServiceConfig{},
		CredentialConfig: config.CredentialServiceConfig{},
		KeyStoreConfig:   config.KeyStoreServiceConfig{},
	}
}
