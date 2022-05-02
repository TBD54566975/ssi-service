package service

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"log"
)

// SSIService represents all services and their dependencies independent of transport
type SSIService struct {
	*log.Logger
	services []framework.Service
	config   config.ServicesConfig
}

// InstantiateSSIService creates a new instance of the SSIS which instantiates all services and their
// dependencies independent of transport.
func InstantiateSSIService(logger *log.Logger, config config.ServicesConfig) (*SSIService, error) {
	if logger == nil {
		return nil, errors.New("logger not initialized")
	}
	services, err := instantiateServices(logger, config)
	if err != nil {
		errMsg := "could not instantiate the verifiable credentials service"
		log.Printf(errMsg)
		return nil, errors.Wrap(err, errMsg)
	}
	return &SSIService{services: services}, nil
}

func validateServiceConfig(config config.ServicesConfig) error {
	for svc, svcConfig := range config.Config {
		if !IsServiceAvailable(svc) {
			return fmt.Errorf("configured service<%s> not available", svc)
		}
		if !storage.IsStorageAvailable(svcConfig.Storage) {
			return fmt.Errorf("configured storage<%s> not available", svc)
		}
	}

	// create an index of enabled services to cross-check for dependent services
	seen := make(map[string]bool)
	for _, s := range config.EnabledServices {
		seen[s] = true
	}

	// static configuration analysis to determine whether selected services and storage can be instantiated
	for svc, svcConfig := range config.Config {
		for _, dependent := range svcConfig.DependentServices {
			if ok := seen[dependent]; !ok {
				return fmt.Errorf("dependent service<%s> of <%s> not available", dependent, svc)
			}
		}
	}

	return nil
}

// GetServices returns the instantiated service providers
func (ssi *SSIService) GetServices() []framework.Service {
	return ssi.services
}

// instantiateServices begins all instantiates and their dependencies
func instantiateServices(logger *log.Logger, config config.ServicesConfig) ([]framework.Service, error) {
	enabledIndex := make(map[string]bool)
	for _, svc := range config.EnabledServices {
		enabledIndex[svc] = true
	}

	// some services may have config but not be enabled, this is ok
	//for svc, svcConfig := range config.Config {
	//	if ok := enabledIndex[svc]; ok {
	//
	//	}
	//}

	bolt, err := storage.NewBoltDB(logger)
	if err != nil {
		return nil, errors.Wrap(err, "could not instantiate BoltDB")
	}
	didService, err := did.NewDIDService(logger, []did.Method{did.KeyMethod}, bolt)
	if err != nil {
		return nil, errors.Wrap(err, "could not instantiate the DID service")
	}
	schemaService, err := schema.NewSchemaService(logger, bolt)
	if err != nil {
		return nil, errors.Wrap(err, "could not instantiate the schema service")
	}
	return []framework.Service{didService, schemaService}, nil
}

// AvailableServices returns the supported service providers
func AvailableServices() []framework.Service {
	return []framework.Service{framework.DID, framework.Schema}
}

// IsServiceAvailable determines whether a given service provider is available for instantiation
func IsServiceAvailable(service string) bool {
	all := AvailableServices()
	for _, s := range all {
		if service == s.Type() {
			return true
		}
	}
	return false
}
