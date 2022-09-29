package dwn

import (
	"fmt"

	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	"github.com/tbd54566975/ssi-service/pkg/service/manifest"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type Service struct {
	config config.DWNServiceConfig

	// external dependencies
	keyStore *keystore.Service
	manifest *manifest.Service
}

func (s Service) Type() framework.Type {
	return framework.DWN
}

func (s Service) Status() framework.Status {
	err := sdkutil.NewAppendError()
	if s.keyStore == nil {
		err.AppendString("keystore not set")
	}
	if s.manifest == nil {
		err.AppendString("manifest not set")
	}
	if gotErr := err.Error(); gotErr != nil {
		return framework.Status{
			Status:  framework.StatusNotReady,
			Message: gotErr.Error(),
		}
	}
	return framework.Status{Status: framework.StatusReady}
}

func (s Service) Config() config.DWNServiceConfig {
	return s.config
}

func NewDWNService(config config.DWNServiceConfig, s storage.ServiceStorage, keyStore *keystore.Service, manifest *manifest.Service) (*Service, error) {
	if keyStore == nil {
		return nil, fmt.Errorf("keystore not set")
	}
	if manifest == nil {
		return nil, fmt.Errorf("manifest not set")
	}
	return &Service{
		config:   config,
		keyStore: keyStore,
		manifest: manifest,
	}, nil
}

func (s Service) GetManifest(request DWNPublishManifestRequest) (*DWNPublishManifestResponse, error) {

	logrus.Debugf("getting manifest: %s", request.ManifestID)

	gotManifest, err := s.manifest.GetManifest(manifest.GetManifestRequest{ID: request.ManifestID})
	if err != nil {
		errMsg := fmt.Sprintf("could not get manifest: %s", request.ManifestID)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	response := DWNPublishManifestResponse{Manifest: gotManifest.Manifest}
	return &response, nil
}
