package manifest

import (
	"encoding/json"
	"fmt"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/credential/manifest"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/sirupsen/logrus"
	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	manifeststorage "github.com/tbd54566975/ssi-service/pkg/service/manifest/storage"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type Service struct {
	storage manifeststorage.Storage
	config  config.ManifestServiceConfig
}

func (s Service) Type() framework.Type {
	return framework.Manifest
}

func (s Service) Status() framework.Status {
	if s.storage == nil {
		return framework.Status{
			Status:  framework.StatusNotReady,
			Message: "no storage",
		}
	}
	return framework.Status{Status: framework.StatusReady}
}

func (s Service) Config() config.ManifestServiceConfig {
	return s.config
}

func NewManifestService(config config.ManifestServiceConfig, s storage.ServiceStorage) (*Service, error) {
	manifestStorage, err := manifeststorage.NewManifestStorage(s)
	if err != nil {
		errMsg := "could not instantiate storage for the manifest service"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	return &Service{
		storage: manifestStorage,
		config:  config,
	}, nil
}

func (s Service) CreateManifest(request CreateManifestRequest) (*CreateManifestResponse, error) {
	logrus.Debugf("creating manifest: %+v", request)

	builder := manifest.NewCredentialManifestBuilder()
	issuer := manifest.Issuer{ID: request.Issuer, Name: request.Issuer}

	if err := builder.SetIssuer(issuer); err != nil {
		errMsg := fmt.Sprintf("could not build manifest when setting issuer: %s", request.Issuer)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	// TODO: (Neal) Add dynamic claim formats
	if err := builder.SetClaimFormat(exchange.ClaimFormat{
		JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
	}); err != nil {
		errMsg := fmt.Sprintf("could not build manifest when setting claim format")
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	// parse OutputDescriptors
	odJsonString, err := json.Marshal(request.OutputDescriptors)
	if err != nil {
		errMsg := "could not marshal request output descriptors"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	od := []manifest.OutputDescriptor{}
	err = json.Unmarshal(odJsonString, &od)
	if err != nil {
		errMsg := "could not unmarshal output descriptors"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	builder.SetOutputDescriptors(od)

	// parse PresentationDefinition
	pdJsonString, err := json.Marshal(request.PresentationDefinition)
	if err != nil {
		errMsg := "could not marshal request presentation definition"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	pd := exchange.PresentationDefinition{}
	err = json.Unmarshal(pdJsonString, &pd)
	if err != nil {
		errMsg := "could not unmarshal presentation definition"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	builder.SetPresentationDefinition(pd)

	mfst, err := builder.Build()
	if err != nil {
		errMsg := "could not build manifest"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	// store the manifest
	storageRequest := manifeststorage.StoredManifest{
		ID:       mfst.ID,
		Manifest: *mfst,
		Issuer:   request.Issuer,
	}

	if err := s.storage.StoreManifest(storageRequest); err != nil {
		errMsg := "could not store manifest"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	// return the result
	response := CreateManifestResponse{Manifest: *mfst}
	return &response, nil
}

func (s Service) GetManifest(request GetManifestRequest) (*GetManifestResponse, error) {

	logrus.Debugf("getting manifest: %s", request.ID)

	gotManifest, err := s.storage.GetManifest(request.ID)
	if err != nil {
		errMsg := fmt.Sprintf("could not get manifest: %s", request.ID)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	response := GetManifestResponse{Manifest: gotManifest.Manifest}
	return &response, nil
}

func (s Service) GetManifests() (*GetManifestsResponse, error) {
	gotManifests, err := s.storage.GetManifests()

	if err != nil {
		errMsg := fmt.Sprintf("could not get manifests(s)")
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	var manifests []manifest.CredentialManifest
	for _, manifest := range gotManifests {
		manifests = append(manifests, manifest.Manifest)
	}
	response := GetManifestsResponse{Manifests: manifests}
	return &response, nil
}

func (s Service) DeleteManifest(request DeleteManifestRequest) error {

	logrus.Debugf("deleting manifest: %s", request.ID)

	if err := s.storage.DeleteManifest(request.ID); err != nil {
		errMsg := fmt.Sprintf("could not delete manifest with id: %s", request.ID)
		return util.LoggingErrorMsg(err, errMsg)
	}

	return nil
}
