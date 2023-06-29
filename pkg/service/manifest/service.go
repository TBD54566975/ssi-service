package manifest

import (
	"context"
	"fmt"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/credential/manifest"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/resolution"
	errresp "github.com/TBD54566975/ssi-sdk/error"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/benbjohnson/clock"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tbd54566975/ssi-service/config"
	credint "github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/pkg/service/common"
	"github.com/tbd54566975/ssi-service/pkg/service/credential"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/issuance"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	"github.com/tbd54566975/ssi-service/pkg/service/manifest/model"
	manifeststg "github.com/tbd54566975/ssi-service/pkg/service/manifest/storage"
	"github.com/tbd54566975/ssi-service/pkg/service/operation"
	opcredential "github.com/tbd54566975/ssi-service/pkg/service/operation/credential"
	opstorage "github.com/tbd54566975/ssi-service/pkg/service/operation/storage"
	"github.com/tbd54566975/ssi-service/pkg/service/presentation"
	presmodel "github.com/tbd54566975/ssi-service/pkg/service/presentation/model"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

const requestNamespace = "manifest_request"

type Service struct {
	storage                 *manifeststg.Storage
	opsStorage              *operation.Storage
	issuanceTemplateStorage *issuance.Storage
	config                  config.ManifestServiceConfig

	// external dependencies
	keyStore        *keystore.Service
	presentationSvc *presentation.Service
	didResolver     resolution.Resolver
	credential      *credential.Service

	Clock      clock.Clock
	reqStorage common.RequestStorage
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

func NewManifestService(config config.ManifestServiceConfig, s storage.ServiceStorage, keyStore *keystore.Service, didResolver resolution.Resolver, credential *credential.Service, presentationSvc *presentation.Service) (*Service, error) {
	manifestStorage, err := manifeststg.NewManifestStorage(s)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not instantiate storage for the manifest service")
	}
	opsStorage, err := operation.NewOperationStorage(s)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not instantiate storage for the operations")
	}
	issuanceStorage, err := issuance.NewIssuanceStorage(s)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not instantiate storage for issuance templates")
	}
	requestStorage := common.NewRequestStorage(s, requestNamespace)
	return &Service{
		storage:                 manifestStorage,
		opsStorage:              opsStorage,
		issuanceTemplateStorage: issuanceStorage,
		config:                  config,
		keyStore:                keyStore,
		didResolver:             didResolver,
		credential:              credential,
		Clock:                   clock.New(),
		reqStorage:              requestStorage,
		presentationSvc:         presentationSvc,
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
	if request.PresentationDefinitionRef != nil {
		var pd *exchange.PresentationDefinition
		if request.PresentationDefinitionRef.ID != nil && request.PresentationDefinitionRef.PresentationDefinition != nil {
			return nil, errors.New(`only one of "id" and "value" can be provided`)
		}

		if request.PresentationDefinitionRef.ID != nil {
			resp, err := s.presentationSvc.GetPresentationDefinition(ctx, presmodel.GetPresentationDefinitionRequest{ID: *request.PresentationDefinitionRef.ID})
			if err != nil {
				return nil, errors.Wrap(err, "getting presentation definition")
			}
			pd = &resp.PresentationDefinition
		}

		if request.PresentationDefinitionRef.PresentationDefinition != nil {
			pd = request.PresentationDefinitionRef.PresentationDefinition
		}

		if err := builder.SetPresentationDefinition(*pd); err != nil {
			return nil, sdkutil.LoggingErrorMsgf(
				err,
				"could not set presentation definition<%+v> for manifest",
				request.PresentationDefinitionRef,
			)
		}
	}

	// build the manifest
	m, err := builder.Build()
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not build manifest")
	}

	// store the manifest
	storageRequest := manifeststg.StoredManifest{
		ID:        m.ID,
		IssuerDID: m.Issuer.ID,
		IssuerKID: request.FullyQualifiedVerificationMethodID,
		Manifest:  *m,
	}

	if err = s.storage.StoreManifest(ctx, storageRequest); err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not store manifest")
	}

	// return the result
	response := model.CreateManifestResponse{Manifest: *m}
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

	response := model.GetManifestResponse{Manifest: gotManifest.Manifest}
	return &response, nil
}

func (s Service) ListManifests(ctx context.Context) (*model.ListManifestsResponse, error) {
	gotManifests, err := s.storage.ListManifests(ctx)

	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not list manifests(s)")
	}

	manifests := make([]model.GetManifestResponse, 0, len(gotManifests))
	for _, m := range gotManifests {
		response := model.GetManifestResponse{Manifest: m.Manifest}
		manifests = append(manifests, response)
	}
	response := model.ListManifestsResponse{Manifests: manifests}
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
		return nil, sdkutil.LoggingErrorMsgf(err, "problem with retrieving manifest<%s> during application<%s>'s validation", manifestID, applicationID)
	}
	if gotManifest == nil {
		return nil, sdkutil.LoggingNewErrorf("application<%s> is not valid; a manifest does not exist with id: %s", applicationID, manifestID)
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
		logrus.Warnf("found issuance issuance templates for manifest<%s>, using first entry only", manifestID)
	}

	credResp, creds, err := s.buildFulfillmentCredentialResponseFromTemplate(ctx, applicantDID, manifestID, gotManifest.IssuerKID,
		gotManifest.Manifest, issuanceTemplate, request.Application, request.ApplicationJSON)
	if err != nil {
		return nil, err
	}

	keyStoreID := did.FullyQualifiedVerificationMethodID(gotManifest.IssuerDID, gotManifest.IssuerKID)
	responseJWT, err := s.signCredentialResponse(ctx, keyStoreID, CredentialResponseContainer{
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
	keyStoreID := did.FullyQualifiedVerificationMethodID(gotManifest.IssuerDID, gotManifest.IssuerKID)
	responseJWT, err := s.signCredentialResponse(ctx, keyStoreID, responseContainer)
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

func (s Service) ListApplications(ctx context.Context) (*model.ListApplicationsResponse, error) {
	logrus.Debugf("listing application(s)")

	gotApps, err := s.storage.ListApplications(ctx)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not list application(s)")
	}

	apps := make([]manifest.CredentialApplication, 0, len(gotApps))
	for _, cred := range gotApps {
		apps = append(apps, cred.Application)
	}

	response := model.ListApplicationsResponse{Applications: apps}
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

func (s Service) ListResponses(ctx context.Context) (*model.ListResponsesResponse, error) {
	logrus.Debugf("listing responses")

	gotResponses, err := s.storage.ListResponses(ctx)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not list responses")
	}

	responses := make([]manifest.CredentialResponse, 0, len(gotResponses))
	for _, res := range gotResponses {
		responses = append(responses, res.Response)
	}

	response := model.ListResponsesResponse{Responses: responses}
	return &response, nil
}

func (s Service) DeleteResponse(ctx context.Context, request model.DeleteResponseRequest) error {
	logrus.Debugf("deleting response: %s", request.ID)

	if err := s.storage.DeleteResponse(ctx, request.ID); err != nil {
		return sdkutil.LoggingErrorMsgf(err, "could not delete response with id: %s", request.ID)
	}

	return nil
}

func (s Service) CreateRequest(ctx context.Context, req model.CreateRequestRequest) (*model.Request, error) {
	if err := sdkutil.IsValidStruct(req); err != nil {
		return nil, err
	}

	request := req.ManifestRequest
	storedManifest, err := s.storage.GetManifest(ctx, request.ManifestID)
	if err != nil {
		return nil, errors.Wrap(err, "getting credential manifest")
	}
	if storedManifest == nil {
		return nil, errors.Errorf("credential manifest %q is nil", request.ManifestID)
	}

	claimName := "credential_manifest"
	claimValue := storedManifest.Manifest

	stored, err := common.CreateStoredRequest(ctx, s.keyStore, claimName, claimValue, request.Request, request.ManifestID)
	if err != nil {
		return nil, errors.Wrap(err, "creating stored request")
	}
	if err := s.reqStorage.StoreRequest(ctx, *stored); err != nil {
		return nil, errors.Wrap(err, "storing request")
	}
	return serviceModel(stored)
}

func (s Service) ListRequests(ctx context.Context) (*model.ListRequestsResponse, error) {
	requests, err := s.reqStorage.ListRequests(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "listing from storage")
	}
	reqs := make([]model.Request, 0, len(requests))
	for _, storedReq := range requests {
		storedReq := storedReq
		r, err := serviceModel(&storedReq)
		if err != nil {
			return nil, err
		}
		reqs = append(reqs, *r)
	}
	return &model.ListRequestsResponse{ManifestRequests: reqs}, nil
}

func (s Service) GetRequest(ctx context.Context, request *model.GetRequestRequest) (*model.Request, error) {
	logrus.Debugf("getting manifest request: %s", request.ID)

	storedRequest, err := s.reqStorage.GetRequest(ctx, request.ID)
	if err != nil {
		return nil, errors.Wrapf(err, "getting signed document with id: %s", request.ID)
	}
	if storedRequest == nil {
		return nil, sdkutil.LoggingNewErrorf("manifest request with id<%s> could not be found", request.ID)
	}

	return serviceModel(storedRequest)
}

func (s Service) DeleteRequest(ctx context.Context, request model.DeleteRequestRequest) error {
	logrus.Debugf("deleting manifest request: %s", request.ID)

	if err := s.reqStorage.DeleteRequest(ctx, request.ID); err != nil {
		return sdkutil.LoggingNewErrorf("could not delete manifest request with id: %s", request.ID)
	}

	return nil
}

func serviceModel(stored *common.StoredRequest) (*model.Request, error) {
	req, err := common.ToServiceModel(stored)
	if err != nil {
		return nil, err
	}
	return &model.Request{
		Request:               *req,
		ManifestID:            stored.ReferenceID,
		CredentialManifestJWT: keyaccess.JWT(stored.JWT),
	}, nil
}
