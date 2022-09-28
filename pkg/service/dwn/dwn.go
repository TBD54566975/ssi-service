package dwn

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	manifeststorage "github.com/tbd54566975/ssi-service/pkg/service/manifest/storage"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type Service struct {
	config          config.DWNServiceConfig
	manifestStorage manifeststorage.Storage

	// external dependencies
	keyStore *keystore.Service
}

func (s Service) Type() framework.Type {
	return framework.DWN
}

func (s Service) Status() framework.Status {
	if s.manifestStorage == nil {
		return framework.Status{
			Status:  framework.StatusNotReady,
			Message: "no manifestStorage",
		}
	}

	return framework.Status{Status: framework.StatusReady}
}

func (s Service) Config() config.DWNServiceConfig {
	return s.config
}

func NewDWNService(config config.DWNServiceConfig, s storage.ServiceStorage, keyStore *keystore.Service) (*Service, error) {
	manifestStorage, err := manifeststorage.NewManifestStorage(s)
	if err != nil {
		errMsg := "could not instantiate manifestStorage for the dwn service"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	return &Service{
		config:          config,
		manifestStorage: manifestStorage,
		keyStore:        keyStore,
	}, nil
}

func (s Service) GetManifest(request DWNPublishManifestRequest) (*DWNPublishManifestResponse, error) {
	logrus.Debugf("getting manifest: %s", request.ManifestID)

	gotManifest, err := s.manifestStorage.GetManifest(request.ManifestID)
	if err != nil {
		errMsg := fmt.Sprintf("could not get manifest: %s", request.ManifestID)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	response := DWNPublishManifestResponse{Manifest: gotManifest.Manifest}
	return &response, nil
}
