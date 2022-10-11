package manifest

import (
	"fmt"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/credential/manifest"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/config"
	cred "github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/service/credential"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	manifeststorage "github.com/tbd54566975/ssi-service/pkg/service/manifest/storage"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type Service struct {
	storage manifeststorage.Storage
	config  config.ManifestServiceConfig

	// external dependencies
	credential *credential.Service
	keyStore   *keystore.Service
}

func (s Service) Type() framework.Type {
	return framework.Manifest
}

func (s Service) Status() framework.Status {
	ae := sdkutil.NewAppendError()
	if s.storage == nil {
		ae.AppendString("no storage configured")
	}
	if s.credential == nil {
		ae.AppendString("no credential service configured")
	}
	if s.keyStore == nil {
		ae.AppendString("no keystore service configured")
	}
	if !ae.IsEmpty() {
		return framework.Status{
			Status:  framework.StatusNotReady,
			Message: fmt.Sprintf("manifest service is not ready: %s", ae.Error().Error()),
		}
	}
	return framework.Status{Status: framework.StatusReady}
}

func (s Service) Config() config.ManifestServiceConfig {
	return s.config
}

func NewManifestService(config config.ManifestServiceConfig, s storage.ServiceStorage, keyStore *keystore.Service, credential *credential.Service) (*Service, error) {
	manifestStorage, err := manifeststorage.NewManifestStorage(s)
	if err != nil {
		errMsg := "could not instantiate storage for the manifest service"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	return &Service{
		storage:    manifestStorage,
		config:     config,
		keyStore:   keyStore,
		credential: credential,
	}, nil
}

func (s Service) CreateManifest(request CreateManifestRequest) (*CreateManifestResponse, error) {
	logrus.Debugf("creating manifest: %+v", request)

	m := request.Manifest
	if err := m.IsValid(); err != nil {
		return nil, util.LoggingErrorMsg(err, "manifest is not valid")
	}

	// store the manifest
	storageRequest := manifeststorage.StoredManifest{
		ID:       m.ID,
		Manifest: m,
		Issuer:   m.Issuer.ID,
	}

	if err := s.storage.StoreManifest(storageRequest); err != nil {
		return nil, util.LoggingErrorMsg(err, "could not store manifest")
	}

	// return the result
	response := CreateManifestResponse{Manifest: m}
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
		return nil, util.LoggingErrorMsg(err, "could not get manifests(s)")
	}

	var manifests []manifest.CredentialManifest
	for _, m := range gotManifests {
		manifests = append(manifests, m.Manifest)
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

func (s Service) ProcessApplicationSubmission(request SubmitApplicationRequest) (*SubmitApplicationResponse, error) {
	credApp := request.Application

	if err := credApp.IsValid(); err != nil {
		return nil, util.LoggingErrorMsg(err, "application is not valid")
	}

	gotManifest, err := s.storage.GetManifest(credApp.ManifestID)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "problem with retrieving manifest during application validation")
	}

	// validate
	if err := isValidApplication(gotManifest, credApp); err != nil {
		return nil, util.LoggingErrorMsg(err, "could not validate application")
	}

	// store the application
	storageRequest := manifeststorage.StoredApplication{
		ID:          credApp.ID,
		Application: credApp,
		ManifestID:  request.Application.ManifestID,
	}

	if err := s.storage.StoreApplication(storageRequest); err != nil {
		errMsg := "could not store application"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	// build the credential response
	// TODO(gabe) need to check if this can be fulfilled and conditionally return success/denial
	responseBuilder := manifest.NewCredentialResponseBuilder(request.Application.ManifestID)
	if err := responseBuilder.SetApplicationID(credApp.ID); err != nil {
		return nil, util.LoggingErrorMsg(err, "could not fulfill credential application: could not set application id")
	}

	var creds []cred.CredentialContainer
	for _, od := range gotManifest.Manifest.OutputDescriptors {
		credentialRequest := credential.CreateCredentialRequest{
			Issuer:     gotManifest.Manifest.Issuer.ID,
			Subject:    request.ApplicantDID,
			JSONSchema: od.Schema,
			// TODO(gabe) need to add in data here to match the request + schema
			Data: map[string]interface{}{},
		}

		credentialResponse, err := s.credential.CreateCredential(credentialRequest)
		if err != nil {
			return nil, util.LoggingErrorMsg(err, "could not create credential")
		}

		creds = append(creds, credentialResponse.CredentialContainer)
	}

	// build descriptor map based on credential type
	var descriptors []exchange.SubmissionDescriptor
	for i, c := range creds {
		var format string
		if c.HasDataIntegrityCredential() {
			format = string(exchange.LDPVC)
		}
		if c.HasJWTCredential() {
			format = string(exchange.JWTVC)
		}
		descriptors = append(descriptors, exchange.SubmissionDescriptor{
			ID:     c.ID,
			Format: format,
			Path:   fmt.Sprintf("$.verifiableCredential[%d]", i),
		})
	}

	// set the information for the fulfilled credentials in the response
	if err := responseBuilder.SetFulfillment(descriptors); err != nil {
		return nil, util.LoggingErrorMsg(err, "could not fulfill credential application: could not set fulfillment")
	}
	credRes, err := responseBuilder.Build()
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not build response")
	}

	// store the response we've generated
	storeResponseRequest := manifeststorage.StoredResponse{
		ID:         credRes.ID,
		Response:   *credRes,
		ManifestID: request.Application.ManifestID,
	}
	if err := s.storage.StoreResponse(storeResponseRequest); err != nil {
		return nil, util.LoggingErrorMsg(err, "could not store manifest response")
	}

	response := SubmitApplicationResponse{Response: *credRes, Credential: creds}
	return &response, nil
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

func (s Service) GetApplication(request GetApplicationRequest) (*GetApplicationResponse, error) {

	logrus.Debugf("getting application: %s", request.ID)

	gotApp, err := s.storage.GetApplication(request.ID)
	if err != nil {
		errMsg := fmt.Sprintf("could not get application: %s", request.ID)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	response := GetApplicationResponse{Application: gotApp.Application}
	return &response, nil
}

func (s Service) GetApplications() (*GetApplicationsResponse, error) {

	logrus.Debugf("getting application(s)")

	gotApps, err := s.storage.GetApplications()
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not get application(s)")
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

	if err := s.storage.DeleteApplication(request.ID); err != nil {
		errMsg := fmt.Sprintf("could not delete application with id: %s", request.ID)
		return util.LoggingErrorMsg(err, errMsg)
	}

	return nil
}

func (s Service) GetResponse(request GetResponseRequest) (*GetResponseResponse, error) {

	logrus.Debugf("getting response: %s", request.ID)

	gotResponse, err := s.storage.GetResponse(request.ID)
	if err != nil {
		errMsg := fmt.Sprintf("could not get response: %s", request.ID)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	response := GetResponseResponse{Response: gotResponse.Response}
	return &response, nil
}

func (s Service) GetResponses() (*GetResponsesResponse, error) {

	logrus.Debugf("getting response(s)")

	gotResponses, err := s.storage.GetResponses()
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not get response(s)")
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

	if err := s.storage.DeleteResponse(request.ID); err != nil {
		errMsg := fmt.Sprintf("could not delete response with id: %s", request.ID)
		return util.LoggingErrorMsg(err, errMsg)
	}

	return nil
}
