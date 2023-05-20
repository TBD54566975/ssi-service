package manifest

import (
	"context"
	"fmt"

	"github.com/TBD54566975/ssi-sdk/credential/manifest"
	"github.com/TBD54566975/ssi-sdk/did/resolution"
	errresp "github.com/TBD54566975/ssi-sdk/error"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/benbjohnson/clock"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/config"
	credint "github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/pkg/service/credential"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/issuance"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	"github.com/tbd54566975/ssi-service/pkg/service/manifest/model"
	manifeststg "github.com/tbd54566975/ssi-service/pkg/service/manifest/storage"
	"github.com/tbd54566975/ssi-service/pkg/service/operation"
	opcredential "github.com/tbd54566975/ssi-service/pkg/service/operation/credential"
	opstorage "github.com/tbd54566975/ssi-service/pkg/service/operation/storage"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type Service struct {
	storage                 *manifeststg.Storage
	opsStorage              *operation.Storage
	issuanceTemplateStorage *issuance.Storage
	config                  config.ManifestServiceConfig

	// external dependencies
	keyStore    *keystore.Service
	didResolver resolution.Resolver
	credential  *credential.Service

	Clock clock.Clock
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

func NewManifestService(config config.ManifestServiceConfig, s storage.ServiceStorage, keyStore *keystore.Service,
	didResolver resolution.Resolver, credential *credential.Service) (*Service, error) {
	manifestStorage, err := manifeststg.NewManifestStorage(s)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not instantiate storage for the manifest service")
	}
	opsStorage, err := operation.NewOperationStorage(s)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not instantiate storage for the operations")
	}
	issuingStorage, err := issuance.NewIssuanceStorage(s)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not instantiate storage for issuance templates")
	}
	return &Service{
		storage:                 manifestStorage,
		opsStorage:              opsStorage,
		issuanceTemplateStorage: issuingStorage,
		config:                  config,
		keyStore:                keyStore,
		didResolver:             didResolver,
		credential:              credential,
		Clock:                   clock.New(),
	}, nil
}

// CredentialManifestContainer represents what is signed over and return for a credential manifest
type CredentialManifestContainer struct {
	Manifest manifest.CredentialManifest `json:"credential_manifest"`
}

func (s Service) CreateManifest(ctx context.Context, request model.CreateManifestRequest) (*model.CreateManifestResponse, error) {
	logrus.Debugf("creating manifest: %+v", request)

	// validate the request
	if err := sdkutil.IsValidStruct(request); err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "invalid create manifest request: %s", err.Error())
	}

	// compose a valid manifest
	builder := manifest.NewCredentialManifestBuilder()

	// set the manifest's name and description
	if request.Name != nil {
		if err := builder.SetName(*request.Name); err != nil {
			return nil, sdkutil.LoggingErrorMsg(err, "invalid manifest name")
		}
	}
	if request.Description != nil {
		if err := builder.SetDescription(*request.Description); err != nil {
			return nil, sdkutil.LoggingErrorMsg(err, "invalid manifest description")
		}
	}

	// set the issuer
	var issuerName string
	if request.IssuerName != nil {
		issuerName = *request.IssuerName
	}
	if err := builder.SetIssuer(
		manifest.Issuer{
			ID:   request.IssuerDID,
			Name: issuerName,
		},
	); err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "could not set issuer<%s> for manifest", request.IssuerDID)
	}
	if err := builder.SetClaimFormat(*request.ClaimFormat); err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "could not set claim format<%+v> for manifest", request.ClaimFormat)
	}
	if err := builder.SetOutputDescriptors(request.OutputDescriptors); err != nil {
		return nil, sdkutil.LoggingErrorMsgf(
			err,
			"could not set output descriptors<%+v> for manifest",
			request.OutputDescriptors,
		)
	}
	if request.PresentationDefinition != nil {
		if err := builder.SetPresentationDefinition(*request.PresentationDefinition); err != nil {
			return nil, sdkutil.LoggingErrorMsgf(
				err,
				"could not set presentation definition<%+v> for manifest",
				request.PresentationDefinition,
			)
		}
	}

	// build the manifest
	m, err := builder.Build()
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not build manifest")
	}

	// sign the manifest
	manifestJWT, err := s.signManifestJWT(ctx, request.IssuerKID, CredentialManifestContainer{Manifest: *m})
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not sign manifest")
	}

	// store the manifest
	storageRequest := manifeststg.StoredManifest{
		ID:          m.ID,
		IssuerDID:   m.Issuer.ID,
		IssuerKID:   request.IssuerKID,
		Manifest:    *m,
		ManifestJWT: *manifestJWT,
	}

	if err = s.storage.StoreManifest(ctx, storageRequest); err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not store manifest")
	}

	// return the result
	response := model.CreateManifestResponse{Manifest: *m, ManifestJWT: *manifestJWT}
	return &response, nil
}

// VerifyManifest verifies a manifest's signature and makes sure the manifest is compliant with the specification
func (s Service) VerifyManifest(ctx context.Context, request model.VerifyManifestRequest) (*model.VerifyManifestResponse, error) {
	m, err := s.verifyManifestJWT(ctx, request.ManifestJWT)
	if err != nil {
		return &model.VerifyManifestResponse{
			Verified: false,
			Reason:   "could not verify manifest's signature: " + err.Error(),
		}, nil
	}

	// check the manifest is valid against its specification
	if err = m.IsValid(); err != nil {
		return &model.VerifyManifestResponse{Verified: false, Reason: "manifest is not valid: " + err.Error()}, nil
	}
	return &model.VerifyManifestResponse{Verified: true}, nil
}

func (s Service) GetManifest(ctx context.Context, request model.GetManifestRequest) (*model.GetManifestResponse, error) {
	logrus.Debugf("getting manifest: %s", request.ID)

	gotManifest, err := s.storage.GetManifest(ctx, request.ID)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "could not get manifest: %s", request.ID)
	}

	response := model.GetManifestResponse{Manifest: gotManifest.Manifest, ManifestJWT: gotManifest.ManifestJWT}
	return &response, nil
}

func (s Service) GetManifests(ctx context.Context) (*model.GetManifestsResponse, error) {
	gotManifests, err := s.storage.GetManifests(ctx)

	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not get manifests(s)")
	}

	manifests := make([]model.GetManifestResponse, 0, len(gotManifests))
	for _, m := range gotManifests {
		response := model.GetManifestResponse{Manifest: m.Manifest, ManifestJWT: m.ManifestJWT}
		manifests = append(manifests, response)
	}
	response := model.GetManifestsResponse{Manifests: manifests}
	return &response, nil
}

func (s Service) DeleteManifest(ctx context.Context, request model.DeleteManifestRequest) error {
	logrus.Debugf("deleting manifest: %s", request.ID)

	if err := s.storage.DeleteManifest(ctx, request.ID); err != nil {
		return sdkutil.LoggingErrorMsgf(err, "could not delete manifest with id: %s", request.ID)
	}

	return nil
}

// CredentialResponseContainer represents what is signed over and return for a credential response
type CredentialResponseContainer struct {
	Response    manifest.CredentialResponse `json:"credential_response"`
	Credentials []any                       `json:"verifiableCredentials,omitempty"`
}

// ProcessApplicationSubmission stores the application in a pending state, along with an operation.
// When there is an issuance template related to this manifest, the operation is done immediately.
// Once the operation is done, the Operation.Response field will be of type model.SubmitApplicationResponse.
// Invalid applications return an operation marked as done, with Response that represents denial.
// The state of the application can be updated by calling CancelOperation, or by calling ReviewApplicationSubmission.
// When the state is updated, the operation is marked as done.
func (s Service) ProcessApplicationSubmission(ctx context.Context, request model.SubmitApplicationRequest) (*operation.Operation, error) {
	// get the manifest associated with the application
	manifestID := request.Application.ManifestID
	gotManifest, err := s.storage.GetManifest(ctx, manifestID)
	applicationID := request.Application.ID
	if err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err,
			"problem with retrieving manifest<%s> during application<%s>'s validation", manifestID, applicationID)
	}
	if gotManifest == nil {
		return nil, sdkutil.LoggingNewErrorf(
			"application<%s> is not valid; a manifest does not exist with id: %s", applicationID, manifestID)
	}

	opID := opcredential.IDFromResponseID(applicationID)

	// validate the application
	unfulfilledInputDescriptorIDs, validationErr := s.validateCredentialApplication(ctx, gotManifest.Manifest, request)
	if validationErr != nil {
		resp := errresp.GetErrorResponse(validationErr)
		if resp.ErrorType == DenialResponse {
			denialResp, err := buildDenialCredentialResponse(manifestID, request.ApplicantDID, applicationID, resp.Err.Error(), unfulfilledInputDescriptorIDs...)
			if err != nil {
				return nil, sdkutil.LoggingErrorMsg(err, "could not build denial credential response")
			}
			sarData, err := json.Marshal(manifeststg.StoredResponse{Response: *denialResp})
			if err != nil {
				return nil, sdkutil.LoggingErrorMsg(err, "marshalling response")
			}
			storedOp := opstorage.StoredOperation{
				ID:       opID,
				Done:     true,
				Response: sarData,
			}
			if err = s.opsStorage.StoreOperation(ctx, storedOp); err != nil {
				return nil, sdkutil.LoggingErrorMsg(err, "storing operation")
			}

			return operation.ServiceModel(storedOp)
		}
		return nil, sdkutil.LoggingErrorMsg(validationErr, "could not validate application")
	}

	// store the application
	applicantDID := request.ApplicantDID
	storageRequest := manifeststg.StoredApplication{
		ID:             applicationID,
		Status:         opcredential.StatusPending,
		ManifestID:     manifestID,
		ApplicantDID:   applicantDID,
		Application:    request.Application,
		Credentials:    request.Credentials,
		ApplicationJWT: request.ApplicationJWT,
	}
	if err = s.storage.StoreApplication(ctx, storageRequest); err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not store application")
	}

	storedOp := &opstorage.StoredOperation{ID: opID}
	if err = s.opsStorage.StoreOperation(ctx, *storedOp); err != nil {
		return nil, errors.Wrap(err, "storing operation")
	}

	autoStoredOp, err := s.attemptAutomaticIssuance(ctx, request, manifestID, applicantDID, applicationID, *gotManifest)
	if err != nil {
		return nil, err
	}

	if autoStoredOp != nil {
		storedOp = autoStoredOp
	}
	return operation.ServiceModel(*storedOp)
}

// attemptAutomaticIssuance checks if there is an issuance template for the manifest, and if so,
// attempts to issue a credential against it
func (s Service) attemptAutomaticIssuance(ctx context.Context, request model.SubmitApplicationRequest, manifestID,
	applicantDID, applicationID string, gotManifest manifeststg.StoredManifest) (*opstorage.StoredOperation, error) {
	issuanceTemplates, err := s.issuanceTemplateStorage.GetIssuanceTemplatesByManifestID(ctx, manifestID)
	if err != nil {
		return nil, errors.Wrap(err, "fetching issuance templates by manifest ID")
	}
	if len(issuanceTemplates) == 0 {
		logrus.Warnf("no issuance templates found for manifest<%s>, processing application<%s>", manifestID, applicationID)
		return nil, nil
	}

	issuanceTemplate := issuanceTemplates[0].IssuanceTemplate
	if len(issuanceTemplates) > 1 {
		logrus.Warnf("found multiple issuance templates for manifest<%s>, using first entry only", manifestID)
	}

	credResp, creds, err := s.buildFulfillmentCredentialResponseFromTemplate(ctx, applicantDID, manifestID, gotManifest.IssuerKID,
		gotManifest.Manifest, issuanceTemplate, request.Application, request.ApplicationJSON)
	if err != nil {
		return nil, err
	}

	responseJWT, err := s.signCredentialResponse(ctx, gotManifest.IssuerKID, CredentialResponseContainer{
		Response:    *credResp,
		Credentials: credint.ContainersToInterface(creds),
	})
	if err != nil {
		return nil, errors.Wrap(err, "signing credential response")
	}

	storedResponse := manifeststg.StoredResponse{
		ID:           credResp.ID,
		ManifestID:   manifestID,
		ApplicantDID: applicantDID,
		Response:     *credResp,
		Credentials:  creds,
		ResponseJWT:  *responseJWT,
	}
	_, storedOp, err := s.storage.StoreReviewApplication(ctx, applicationID, true,
		"automatic from issuance template", opcredential.IDFromResponseID(applicationID), storedResponse)
	if err != nil {
		return nil, errors.Wrap(err, "reviewing application")
	}
	return storedOp, nil
}

// ReviewApplication moves an application state and marks the operation associated with it as done. A credential
// response is stored.
func (s Service) ReviewApplication(ctx context.Context, request model.ReviewApplicationRequest) (*model.SubmitApplicationResponse, error) {
	application, err := s.storage.GetApplication(ctx, request.ID)
	if err != nil {
		return nil, errors.Wrap(err, "fetching application")
	}

	manifestID := application.ManifestID
	gotManifest, err := s.storage.GetManifest(ctx, manifestID)
	if err != nil {
		return nil, errors.Wrap(err, "fetching manifest")
	}
	applicationID := application.ID
	if gotManifest == nil {
		return nil, sdkutil.LoggingNewErrorf("application<%s> is not valid; a manifest does not exist with id: %s", applicationID, manifestID)
	}
	credManifest := gotManifest.Manifest
	applicantDID := application.ApplicantDID

	var responseContainer CredentialResponseContainer
	var credentials []credint.Container
	if request.Approved {
		// build the credential response
		approvalResponse, creds, err := s.buildFulfillmentCredentialResponse(ctx, applicantDID, applicationID, manifestID, gotManifest.IssuerKID, credManifest, request.CredentialOverrides)
		if err != nil {
			return nil, sdkutil.LoggingErrorMsg(err, "building credential response")
		}
		credentials = creds

		// prepare credentials for the response
		genericCredentials := credint.ContainersToInterface(creds)
		responseContainer = CredentialResponseContainer{
			Response:    *approvalResponse,
			Credentials: genericCredentials,
		}
	} else {
		denialResponse, err := buildDenialCredentialResponse(manifestID, applicantDID, applicationID, request.Reason)
		if err != nil {
			return nil, sdkutil.LoggingErrorMsg(err, "building denial credential response")
		}
		responseContainer = CredentialResponseContainer{Response: *denialResponse}
	}

	// sign the response before returning
	responseJWT, err := s.signCredentialResponse(ctx, gotManifest.IssuerKID, responseContainer)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not sign credential response")
	}

	// store the response we've generated
	storeResponseRequest := manifeststg.StoredResponse{
		ID:           responseContainer.Response.ID,
		ManifestID:   manifestID,
		ApplicantDID: applicantDID,
		Response:     responseContainer.Response,
		Credentials:  credentials,
		ResponseJWT:  *responseJWT,
	}
	storedResponse, _, err := s.storage.StoreReviewApplication(ctx, request.ID, request.Approved, request.Reason,
		opcredential.IDFromResponseID(request.ID), storeResponseRequest)
	if err != nil {
		return nil, errors.Wrap(err, "updating submission")
	}

	m := model.ServiceModel(storedResponse)
	return &m, nil
}

func (s Service) GetApplication(ctx context.Context, request model.GetApplicationRequest) (*model.GetApplicationResponse, error) {
	logrus.Debugf("getting application: %s", request.ID)

	gotApp, err := s.storage.GetApplication(ctx, request.ID)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "could not get application: %s", request.ID)
	}

	response := model.GetApplicationResponse{Application: gotApp.Application}
	return &response, nil
}

func (s Service) GetApplications(ctx context.Context) (*model.GetApplicationsResponse, error) {
	logrus.Debugf("getting application(s)")

	gotApps, err := s.storage.GetApplications(ctx)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not get application(s)")
	}

	apps := make([]manifest.CredentialApplication, 0, len(gotApps))
	for _, cred := range gotApps {
		apps = append(apps, cred.Application)
	}

	response := model.GetApplicationsResponse{Applications: apps}
	return &response, nil
}

func (s Service) DeleteApplication(ctx context.Context, request model.DeleteApplicationRequest) error {
	logrus.Debugf("deleting application: %s", request.ID)

	if err := s.storage.DeleteApplication(ctx, request.ID); err != nil {
		return sdkutil.LoggingErrorMsgf(err, "could not delete application with id: %s", request.ID)
	}

	return nil
}

func (s Service) GetResponse(ctx context.Context, request model.GetResponseRequest) (*model.GetResponseResponse, error) {
	logrus.Debugf("getting response: %s", request.ID)

	gotResponse, err := s.storage.GetResponse(ctx, request.ID)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "could not get response: %s", request.ID)
	}

	response := model.GetResponseResponse{
		Response:    gotResponse.Response,
		Credentials: credint.ContainersToInterface(gotResponse.Credentials),
		ResponseJWT: gotResponse.ResponseJWT,
	}
	return &response, nil
}

func (s Service) GetResponses(ctx context.Context) (*model.GetResponsesResponse, error) {
	logrus.Debugf("getting response(s)")

	gotResponses, err := s.storage.GetResponses(ctx)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not get response(s)")
	}

	responses := make([]manifest.CredentialResponse, 0, len(gotResponses))
	for _, res := range gotResponses {
		responses = append(responses, res.Response)
	}

	response := model.GetResponsesResponse{Responses: responses}
	return &response, nil
}

func (s Service) DeleteResponse(ctx context.Context, request model.DeleteResponseRequest) error {
	logrus.Debugf("deleting response: %s", request.ID)

	if err := s.storage.DeleteResponse(ctx, request.ID); err != nil {
		return sdkutil.LoggingErrorMsgf(err, "could not delete response with id: %s", request.ID)
	}

	return nil
}
