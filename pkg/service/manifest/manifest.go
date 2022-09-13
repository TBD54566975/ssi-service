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

// Manifests
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

// TODO: (Neal) Add entire validation framework in place of these validation checks
func isValidApplication(s Service, request CreateApplicationRequest, ps exchange.PresentationSubmission) error {

	gotManifest, err := s.storage.GetManifest(request.ManifestID)

	if err != nil {
		return util.LoggingErrorMsg(err, "problem with retrieving manifest during application validation")
	}

	if gotManifest == nil {
		return util.LoggingNewError(fmt.Sprintf("application is not valid. A manifest does not exist with id: %s", request.ManifestID))
	}

	inputDescriptors := gotManifest.Manifest.PresentationDefinition.InputDescriptors
	inputDescriptorIds := map[string]bool{}

	for _, inputDescriptor := range inputDescriptors {
		inputDescriptorIds[inputDescriptor.ID] = true
	}

	for _, submissionDescriptor := range ps.DescriptorMap {
		if inputDescriptorIds[submissionDescriptor.ID] != true {
			return util.LoggingNewError("application is not valid. The submission descriptor ids do not match the input descriptor ids")
		}
	}

	return nil
}

// Applications
func (s Service) CreateApplication(request CreateApplicationRequest) (*CreateApplicationResponse, error) {

	// parse OutputDescriptors
	psJsonString, err := json.Marshal(request.PresentationSubmission)
	if err != nil {
		errMsg := "could not marshal request presentation submission"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	ps := exchange.PresentationSubmission{}
	err = json.Unmarshal(psJsonString, &ps)
	if err != nil {
		errMsg := "could not unmarshal presentation submission"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	// validate
	if err := isValidApplication(s, request, ps); err != nil {
		errMsg := fmt.Sprintf("could not validate application")
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	// build credential application
	builder := manifest.NewCredentialApplicationBuilder(request.ManifestID)

	// TODO: (Neal) Add dynamic claim formats
	if err := builder.SetApplicationClaimFormat(exchange.ClaimFormat{
		JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
	}); err != nil {
		errMsg := fmt.Sprintf("could not build application when setting claim format")
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	builder.SetPresentationSubmission(ps)

	credApp, err := builder.Build()
	if err != nil {
		errMsg := "could not build application"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	// store the application
	storageRequest := manifeststorage.StoredApplication{
		ID:          credApp.Application.ID,
		Application: *credApp,
		ManifestID:  request.ManifestID,
	}

	if err := s.storage.StoreApplication(storageRequest); err != nil {
		errMsg := "could not store application"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	// return the result
	response := CreateApplicationResponse{Application: *credApp}
	return &response, nil
}

func (s Service) GetApplication(request GetApplicationRequest) (*GetApplicationResponse, error) {

	logrus.Debugf("getting application: %s", request.ID)

	gotCred, err := s.storage.GetApplication(request.ID)
	if err != nil {
		errMsg := fmt.Sprintf("could not get application: %s", request.ID)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	response := GetApplicationResponse{Application: gotCred.Application}
	return &response, nil
}

func (s Service) GetApplications() (*GetApplicationsResponse, error) {

	logrus.Debugf("getting application(s)")

	gotCreds, err := s.storage.GetApplications()
	if err != nil {
		errMsg := fmt.Sprintf("could not get application(s)")
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	var apps []manifest.CredentialApplication
	for _, cred := range gotCreds {
		apps = append(apps, cred.Application)
	}

	response := GetApplicationsResponse{Applications: apps}
	return &response, nil
}

func (s Service) DeleteApplication(request DeleteApplicationRequest) error {

	logrus.Debugf("deleting application: %s", request.ID)

	if err := s.storage.DeleteApplication(request.ID); err != nil {
		errMsg := fmt.Sprintf("could not delete application with id: %s", request.ID)
		return util.LoggingErrorMsg(err, errMsg)
	}

	return nil
}
