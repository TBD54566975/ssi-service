package manifest

import (
	"fmt"
	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/manifest"
	"github.com/sirupsen/logrus"
	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/internal/util"
	credentialstorage "github.com/tbd54566975/ssi-service/pkg/service/credential/storage"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	manifeststorage "github.com/tbd54566975/ssi-service/pkg/service/manifest/storage"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"time"
)

type Service struct {
	manifestStorage   manifeststorage.Storage
	credentialStorage credentialstorage.Storage
	config            config.ManifestServiceConfig
}

func (s Service) Type() framework.Type {
	return framework.Manifest
}

func (s Service) Status() framework.Status {
	if s.manifestStorage == nil {
		return framework.Status{
			Status:  framework.StatusNotReady,
			Message: "no manifestStorage",
		}
	}

	if s.credentialStorage == nil {
		return framework.Status{
			Status:  framework.StatusNotReady,
			Message: "no credentialStorage",
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
		errMsg := "could not instantiate manifestStorage for the manifest service"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	credentialStorage, err := credentialstorage.NewCredentialStorage(s)
	if err != nil {
		errMsg := "could not instantiate credentialStorage for the manifest service"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	return &Service{
		manifestStorage:   manifestStorage,
		credentialStorage: credentialStorage,
		config:            config,
	}, nil
}

func (s Service) CreateManifest(request CreateManifestRequest) (*CreateManifestResponse, error) {
	logrus.Debugf("creating manifest: %+v", request)

	mfst := request.Manifest
	if err := mfst.IsValid(); err != nil {
		errMsg := "manifest is not valid"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	// store the manifest
	storageRequest := manifeststorage.StoredManifest{
		ID:       mfst.ID,
		Manifest: mfst,
		Issuer:   mfst.Issuer.ID,
	}

	if err := s.manifestStorage.StoreManifest(storageRequest); err != nil {
		errMsg := "could not store manifest"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	// return the result
	response := CreateManifestResponse{Manifest: mfst}
	return &response, nil
}

func (s Service) GetManifest(request GetManifestRequest) (*GetManifestResponse, error) {

	logrus.Debugf("getting manifest: %s", request.ID)

	gotManifest, err := s.manifestStorage.GetManifest(request.ID)
	if err != nil {
		errMsg := fmt.Sprintf("could not get manifest: %s", request.ID)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	response := GetManifestResponse{Manifest: gotManifest.Manifest}
	return &response, nil
}

func (s Service) GetManifests() (*GetManifestsResponse, error) {
	gotManifests, err := s.manifestStorage.GetManifests()

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

	if err := s.manifestStorage.DeleteManifest(request.ID); err != nil {
		errMsg := fmt.Sprintf("could not delete manifest with id: %s", request.ID)
		return util.LoggingErrorMsg(err, errMsg)
	}

	return nil
}

// TODO: (Neal) Add entire validation framework in place of these validation checks - https://github.com/TBD54566975/ssi-service/issues/95
func isValidApplication(gotManifest *manifeststorage.StoredManifest, application manifest.CredentialApplication) error {
	if gotManifest == nil {
		return util.LoggingNewError(fmt.Sprintf("application is not valid. A manifest does not exist with id: %s", application.ManifestID))
	}

	inputDescriptors := gotManifest.Manifest.PresentationDefinition.InputDescriptors
	inputDescriptorIDs := make(map[string]bool)
	for _, inputDescriptor := range inputDescriptors {
		inputDescriptorIDs[inputDescriptor.ID] = true
	}

	for _, submissionDescriptor := range application.PresentationSubmission.DescriptorMap {
		if inputDescriptorIDs[submissionDescriptor.ID] != true {
			return util.LoggingNewError("application is not valid. The submission descriptor ids do not match the input descriptor ids")
		}
	}

	return nil
}

func (s Service) SubmitApplication(request SubmitApplicationRequest) (*SubmitApplicationResponse, error) {
	credApp := request.Application

	if err := credApp.IsValid(); err != nil {
		errMsg := "application is not valid"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	gotManifest, err := s.manifestStorage.GetManifest(credApp.ManifestID)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "problem with retrieving manifest during application validation")
	}

	// validate
	if err := isValidApplication(gotManifest, credApp); err != nil {
		errMsg := fmt.Sprintf("could not validate application")
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	// store the application
	storageRequest := manifeststorage.StoredApplication{
		ID:          credApp.ID,
		Application: credApp,
		ManifestID:  request.Application.ManifestID,
	}

	if err := s.manifestStorage.StoreApplication(storageRequest); err != nil {
		errMsg := "could not store application"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	// build the credential response
	responseBuilder := manifest.NewCredentialResponseBuilder(request.Application.ManifestID)
	responseBuilder.SetApplicationID(credApp.ID)
	responseBuilder.SetFulfillment(credApp.PresentationSubmission.DescriptorMap)

	credRes, err := responseBuilder.Build()
	if err != nil {
		errMsg := "could not build response"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	// store the response
	responseStorageRequest := manifeststorage.StoredResponse{
		ID:         credRes.ID,
		Response:   *credRes,
		ManifestID: request.Application.ManifestID,
	}

	var creds []credential.VerifiableCredential
	for _, od := range gotManifest.Manifest.OutputDescriptors {

		if err := s.manifestStorage.StoreResponse(responseStorageRequest); err != nil {
			errMsg := "could not store response"
			return nil, util.LoggingErrorMsg(err, errMsg)
		}

		credentialBuilder := credential.NewVerifiableCredentialBuilder()
		credentialBuilder.SetIssuer(gotManifest.Manifest.Issuer.ID)
		credentialBuilder.SetCredentialSubject(map[string]interface{}{
			"id": request.RequesterDID,
		})
		credentialBuilder.SetIssuanceDate(time.Now().Format(time.RFC3339))

		cred, err := credentialBuilder.Build()
		if err != nil {
			errMsg := "could not build credential"
			return nil, util.LoggingErrorMsg(err, errMsg)
		}

		credentialStorageRequest := credentialstorage.StoredCredential{
			ID:           cred.ID,
			Credential:   *cred,
			Issuer:       gotManifest.Manifest.Issuer.ID,
			Subject:      request.RequesterDID,
			Schema:       od.Schema,
			IssuanceDate: time.Now().Format(time.RFC3339),
		}

		if err := s.credentialStorage.StoreCredential(credentialStorageRequest); err != nil {
			errMsg := "could not store credential"
			return nil, util.LoggingErrorMsg(err, errMsg)
		}

		creds = append(creds, *cred)
	}

	response := SubmitApplicationResponse{Response: *credRes, Credential: creds}
	return &response, nil
}

func (s Service) GetApplication(request GetApplicationRequest) (*GetApplicationResponse, error) {

	logrus.Debugf("getting application: %s", request.ID)

	gotApp, err := s.manifestStorage.GetApplication(request.ID)
	if err != nil {
		errMsg := fmt.Sprintf("could not get application: %s", request.ID)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	response := GetApplicationResponse{Application: gotApp.Application}
	return &response, nil
}

func (s Service) GetApplications() (*GetApplicationsResponse, error) {

	logrus.Debugf("getting application(s)")

	gotApps, err := s.manifestStorage.GetApplications()
	if err != nil {
		errMsg := fmt.Sprintf("could not get application(s)")
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	var apps []manifest.CredentialApplication
	for _, cred := range gotApps {
		apps = append(apps, cred.Application)
	}

	response := GetApplicationsResponse{Applications: apps}
	return &response, nil
}

func (s Service) DeleteApplication(request DeleteApplicationRequest) error {

	logrus.Debugf("deleting application: %s", request.ID)

	if err := s.manifestStorage.DeleteApplication(request.ID); err != nil {
		errMsg := fmt.Sprintf("could not delete application with id: %s", request.ID)
		return util.LoggingErrorMsg(err, errMsg)
	}

	return nil
}

func (s Service) GetResponse(request GetResponseRequest) (*GetResponseResponse, error) {

	logrus.Debugf("getting response: %s", request.ID)

	gotResponse, err := s.manifestStorage.GetResponse(request.ID)
	if err != nil {
		errMsg := fmt.Sprintf("could not get response: %s", request.ID)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	response := GetResponseResponse{Response: gotResponse.Response}
	return &response, nil
}

func (s Service) GetResponses() (*GetResponsesResponse, error) {

	logrus.Debugf("getting response(s)")

	gotResponses, err := s.manifestStorage.GetResponses()
	if err != nil {
		errMsg := fmt.Sprintf("could not get response(s)")
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	var responses []manifest.CredentialResponse
	for _, res := range gotResponses {
		responses = append(responses, res.Response)
	}

	response := GetResponsesResponse{Responses: responses}
	return &response, nil
}

func (s Service) DeleteResponse(request DeleteResponseRequest) error {

	logrus.Debugf("deleting response: %s", request.ID)

	if err := s.manifestStorage.DeleteResponse(request.ID); err != nil {
		errMsg := fmt.Sprintf("could not delete response with id: %s", request.ID)
		return util.LoggingErrorMsg(err, errMsg)
	}

	return nil
}
