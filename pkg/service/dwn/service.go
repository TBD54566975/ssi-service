package dwn

import (
	"fmt"

	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/pkg/errors"
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
	ae := sdkutil.NewAppendError()
	if s.keyStore == nil {
		ae.AppendString("no key store service configured")
	}
	if s.manifest == nil {
		ae.AppendString("no manifest service configured")
	}
	if !ae.IsEmpty() {
		return framework.Status{
			Status:  framework.StatusNotReady,
			Message: fmt.Sprintf("dwn service is not ready: %s", ae.Error().Error()),
		}
	}
	return framework.Status{Status: framework.StatusReady}
}

func (s Service) Config() config.DWNServiceConfig {
	return s.config
}

func NewDWNService(config config.DWNServiceConfig, s storage.ServiceStorage, keyStore *keystore.Service, manifest *manifest.Service) (*Service, error) {
	service := Service{
		config:   config,
		keyStore: keyStore,
		manifest: manifest,
	}
	if !service.Status().IsReady() {
		return nil, errors.New(service.Status().Message)
	}
	return &service, nil
}

func (s Service) GetManifest(request PublishManifestRequest) (*PublishManifestResponse, error) {

	logrus.Debugf("getting manifest: %s", request.ManifestID)

	gotManifest, err := s.manifest.GetManifest(manifest.GetManifestRequest{ID: request.ManifestID})
	if err != nil {
		errMsg := fmt.Sprintf("could not get manifest: %s", request.ManifestID)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	response := PublishManifestResponse{Manifest: &gotManifest.Manifest}
	return &response, nil
}
