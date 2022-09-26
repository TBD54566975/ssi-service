package dwn

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	manifeststorage "github.com/tbd54566975/ssi-service/pkg/service/manifest/storage"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type Service struct {
	config          config.DWNServiceConfig
	manifestStorage manifeststorage.Storage
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

func NewDWNService(config config.DWNServiceConfig, s storage.ServiceStorage) (*Service, error) {
	manifestStorage, err := manifeststorage.NewManifestStorage(s)
	if err != nil {
		errMsg := "could not instantiate manifestStorage for the dwn service"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	return &Service{
		config:          config,
		manifestStorage: manifestStorage,
	}, nil
}

func (s Service) PublishManifest(request DWNPublishManifestRequest) (*DWNPublishManifestResponse, error) {
	logrus.Debugf("publishing manifest to dwn: %+v", request)

	gotManifest, err := s.manifestStorage.GetManifest(request.ManifestID)

	if err != nil {
		return nil, util.LoggingErrorMsg(err, fmt.Sprintf("problem retrieving manifest with id %v", request.ManifestID))
	}

	if gotManifest == nil {
		return nil, util.LoggingErrorMsg(err, fmt.Sprintf("manifest with id %v not found", request.ManifestID))
	}

	response := DWNPublishManifestResponse{Manifest: gotManifest.Manifest}
	return &response, nil
}
