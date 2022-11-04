package manifest

import (
	"fmt"

	"github.com/TBD54566975/ssi-sdk/credential/manifest"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	errresp "github.com/TBD54566975/ssi-sdk/error"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/config"
	credint "github.com/tbd54566975/ssi-service/internal/credential"
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
	keyStore    *keystore.Service
	didResolver *didsdk.Resolver
	credential  *credential.Service
}

func (s Service) Type() framework.Type {
	return framework.Manifest
}

func (s Service) Status() framework.Status {
	ae := sdkutil.NewAppendError()
	if s.storage == nil {
		ae.AppendString("no storage configured")
	}
	if s.keyStore == nil {
		ae.AppendString("no keystore service configured")
	}
	if s.didResolver == nil {
		ae.AppendString("no did resolver configured")
	}
	if s.credential == nil {
		ae.AppendString("no credential service configured")
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

func NewManifestService(config config.ManifestServiceConfig, s storage.ServiceStorage, keyStore *keystore.Service, didResolver *didsdk.Resolver, credential *credential.Service) (*Service, error) {
	manifestStorage, err := manifeststorage.NewManifestStorage(s)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not instantiate storage for the manifest service")
	}
	return &Service{
		storage:     manifestStorage,
		config:      config,
		keyStore:    keyStore,
		didResolver: didResolver,
		credential:  credential,
	}, nil
}

// CredentialManifestContainer represents what is signed over and return for a credential manifest
type CredentialManifestContainer struct {
	Manifest manifest.CredentialManifest `json:"credential_manifest"`
}

func (s Service) CreateManifest(request CreateManifestRequest) (*CreateManifestResponse, error) {

	logrus.Debugf("creating manifest: %+v", request)

	// validate the request
	if err := sdkutil.IsValidStruct(request); err != nil {
		return nil, util.LoggingErrorMsgf(err, "invalid create manifest request: %s", err.Error())
	}

	// compose a valid manifest
	builder := manifest.NewCredentialManifestBuilder()

	// set the manifest's name and description
	if request.Name != nil {
		if err := builder.SetName(*request.Name); err != nil {
			return nil, util.LoggingErrorMsg(err, "invalid manifest name")
		}
	}
	if request.Description != nil {
		if err := builder.SetDescription(*request.Description); err != nil {
			return nil, util.LoggingErrorMsg(err, "invalid manifest description")
		}
	}

	// set the issuer
	var issuerName string
	if request.IssuerName != nil {
		issuerName = *request.IssuerName
	}
	if err := builder.SetIssuer(manifest.Issuer{
		ID:   request.IssuerDID,
		Name: issuerName,
	}); err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not set issuer<%s> for manifest", request.IssuerDID)
	}
	if err := builder.SetClaimFormat(*request.ClaimFormat); err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not set claim format<%+v> for manifest", request.ClaimFormat)
	}
	if err := builder.SetOutputDescriptors(request.OutputDescriptors); err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not set output descriptors<%+v> for manifest", request.OutputDescriptors)
	}
	if request.PresentationDefinition != nil {
		if err := builder.SetPresentationDefinition(*request.PresentationDefinition); err != nil {
			return nil, util.LoggingErrorMsgf(err, "could not set presentation definition<%+v> for manifest", request.PresentationDefinition)
		}
	}

	// build the manifest
	m, err := builder.Build()
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not build manifest")
	}

	// sign the manifest
	manifestJWT, err := s.signManifestJWT(CredentialManifestContainer{Manifest: *m})
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not sign manifest")
	}

	// store the manifest
	storageRequest := manifeststorage.StoredManifest{
		ID:          m.ID,
		Issuer:      m.Issuer.ID,
		Manifest:    *m,
		ManifestJWT: *manifestJWT,
	}

	if err = s.storage.StoreManifest(storageRequest); err != nil {
		return nil, util.LoggingErrorMsg(err, "could not store manifest")
	}

	// return the result
	response := CreateManifestResponse{Manifest: *m, ManifestJWT: *manifestJWT}
	return &response, nil
}

// VerifyManifest verifies a manifest's signature and makes sure the manifest is compliant with the specification
func (s Service) VerifyManifest(request VerifyManifestRequest) (*VerifyManifestResponse, error) {
	m, err := s.verifyManifestJWT(request.ManifestJWT)
	if err != nil {
		return &VerifyManifestResponse{Verified: false, Reason: "could not verify manifest's signature: " + err.Error()}, nil
	}

	// check the manifest is valid against its specification
	if err := m.IsValid(); err != nil {
		return &VerifyManifestResponse{Verified: false, Reason: "manifest is not valid: " + err.Error()}, nil
	}
	return &VerifyManifestResponse{Verified: true}, nil
}

func (s Service) GetManifest(request GetManifestRequest) (*GetManifestResponse, error) {

	logrus.Debugf("getting manifest: %s", request.ID)

	gotManifest, err := s.storage.GetManifest(request.ID)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get manifest: %s", request.ID)
	}

	response := GetManifestResponse{Manifest: gotManifest.Manifest, ManifestJWT: gotManifest.ManifestJWT}
	return &response, nil
}

func (s Service) GetManifests() (*GetManifestsResponse, error) {
	gotManifests, err := s.storage.GetManifests()

	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not get manifests(s)")
	}

	manifests := make([]GetManifestResponse, 0, len(gotManifests))
	for _, m := range gotManifests {
		response := GetManifestResponse{Manifest: m.Manifest, ManifestJWT: m.ManifestJWT}
		manifests = append(manifests, response)
	}
	response := GetManifestsResponse{Manifests: manifests}
	return &response, nil
}

func (s Service) DeleteManifest(request DeleteManifestRequest) error {

	logrus.Debugf("deleting manifest: %s", request.ID)

	if err := s.storage.DeleteManifest(request.ID); err != nil {
		return util.LoggingErrorMsgf(err, "could not delete manifest with id: %s", request.ID)
	}

	return nil
}

// CredentialResponseContainer represents what is signed over and return for a credential response
type CredentialResponseContainer struct {
	Response    manifest.CredentialResponse `json:"credential_response"`
	Credentials []interface{}               `json:"verifiableCredentials,omitempty"`
}

func (s Service) ProcessApplicationSubmission(request SubmitApplicationRequest) (*SubmitApplicationResponse, error) {
	// get the manifest associated with the application
	manifestID := request.Application.ManifestID
	gotManifest, err := s.storage.GetManifest(manifestID)
	applicationID := request.Application.ID
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "problem with retrieving manifest<%s> during application<%s>'s validation", manifestID, applicationID)
	}
	if gotManifest == nil {
		return nil, util.LoggingNewErrorf("application<%s> is not valid; a manifest does not exist with id: %s", applicationID, manifestID)
	}
	credManifest := gotManifest.Manifest

	// validate the application
	if unfulfilledInputDescriptorIDs, validationErr := s.validateCredentialApplication(gotManifest.Manifest, request); validationErr != nil {
		resp := errresp.GetErrorResponse(validationErr)
		if resp.ErrorType == DenialResponse {
			denialResp, err := buildDenialCredentialResponse(manifestID, applicationID, resp.Err.Error(), unfulfilledInputDescriptorIDs...)
			if err != nil {
				return nil, util.LoggingErrorMsg(err, "could not build denial credential response")
			}
			return &SubmitApplicationResponse{Response: *denialResp}, nil
		}
		return nil, util.LoggingErrorMsg(validationErr, "could not validate application")
	}

	// store the application
	applicantDID := request.ApplicantDID
	storageRequest := manifeststorage.StoredApplication{
		ID:             applicationID,
		ManifestID:     manifestID,
		ApplicantDID:   applicantDID,
		Application:    request.Application,
		Credentials:    request.Credentials,
		ApplicationJWT: request.ApplicationJWT,
	}
	if err = s.storage.StoreApplication(storageRequest); err != nil {
		return nil, util.LoggingErrorMsg(err, "could not store application")
	}

	// build the credential response
	credResp, creds, err := s.buildCredentialResponse(applicantDID, manifestID, applicationID, credManifest)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not build credential response")
	}

	// prepare credentials for the response
	credentials := credint.ContainersToInterface(creds)

	// sign the response before returning
	responseJWT, err := s.signCredentialResponseJWT(gotManifest.Issuer, CredentialResponseContainer{
		Response:    *credResp,
		Credentials: credentials,
	})
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not sign credential response")
	}

	// store the response we've generated
	storeResponseRequest := manifeststorage.StoredResponse{
		ID:           credResp.ID,
		ManifestID:   manifestID,
		ApplicantDID: applicantDID,
		Response:     *credResp,
		Credentials:  creds,
		ResponseJWT:  *responseJWT,
	}
	if err = s.storage.StoreResponse(storeResponseRequest); err != nil {
		return nil, util.LoggingErrorMsg(err, "could not store manifest response")
	}

	response := SubmitApplicationResponse{Response: *credResp, Credentials: credentials, ResponseJWT: *responseJWT}
	return &response, nil
}

func (s Service) GetApplication(request GetApplicationRequest) (*GetApplicationResponse, error) {

	logrus.Debugf("getting application: %s", request.ID)

	gotApp, err := s.storage.GetApplication(request.ID)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get application: %s", request.ID)
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

	apps := make([]manifest.CredentialApplication, 0, len(gotApps))
	for _, cred := range gotApps {
		apps = append(apps, cred.Application)
	}

	response := GetApplicationsResponse{Applications: apps}
	return &response, nil
}

func (s Service) DeleteApplication(request DeleteApplicationRequest) error {

	logrus.Debugf("deleting application: %s", request.ID)

	if err := s.storage.DeleteApplication(request.ID); err != nil {
		return util.LoggingErrorMsgf(err, "could not delete application with id: %s", request.ID)
	}

	return nil
}

func (s Service) GetResponse(request GetResponseRequest) (*GetResponseResponse, error) {

	logrus.Debugf("getting response: %s", request.ID)

	gotResponse, err := s.storage.GetResponse(request.ID)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get response: %s", request.ID)
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

	responses := make([]manifest.CredentialResponse, 0, len(gotResponses))
	for _, res := range gotResponses {
		responses = append(responses, res.Response)
	}

	response := GetResponsesResponse{Responses: responses}
	return &response, nil
}

func (s Service) DeleteResponse(request DeleteResponseRequest) error {

	logrus.Debugf("deleting response: %s", request.ID)

	if err := s.storage.DeleteResponse(request.ID); err != nil {
		return util.LoggingErrorMsgf(err, "could not delete response with id: %s", request.ID)
	}

	return nil
}
