package presentation

import (
	"context"
	"fmt"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/credential/integrity"
	"github.com/TBD54566975/ssi-sdk/did/resolution"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	didint "github.com/tbd54566975/ssi-service/internal/did"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/internal/verification"
	"github.com/tbd54566975/ssi-service/pkg/service/common"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	"github.com/tbd54566975/ssi-service/pkg/service/operation"
	opstorage "github.com/tbd54566975/ssi-service/pkg/service/operation/storage"
	"github.com/tbd54566975/ssi-service/pkg/service/operation/submission"
	"github.com/tbd54566975/ssi-service/pkg/service/presentation/model"
	presentationstorage "github.com/tbd54566975/ssi-service/pkg/service/presentation/storage"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

const presentationRequestNamespace = "presentation_request"

type Service struct {
	storage    presentationstorage.Storage
	keystore   *keystore.Service
	opsStorage *operation.Storage
	resolver   resolution.Resolver
	schema     *schema.Service
	verifier   *verification.Verifier
	reqStorage common.RequestStorage
}

func (s Service) Type() framework.Type {
	return framework.Presentation
}

func (s Service) Status() framework.Status {
	ae := sdkutil.NewAppendError()
	if s.storage == nil {
		ae.AppendString("no storage configured")
	}
	if !ae.IsEmpty() {
		return framework.Status{
			Status:  framework.StatusNotReady,
			Message: fmt.Sprintf("presentation service is not ready: %s", ae.Error().Error()),
		}
	}
	return framework.Status{Status: framework.StatusReady}
}

func NewPresentationService(s storage.ServiceStorage,
	resolver resolution.Resolver, schema *schema.Service, keystore *keystore.Service) (*Service, error) {
	presentationStorage, err := NewPresentationStorage(s)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not instantiate definition storage for the presentation service")
	}
	opsStorage, err := operation.NewOperationStorage(s)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not instantiate storage for the operations")
	}
	verifier, err := verification.NewVerifiableDataVerifier(resolver, schema)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not instantiate verifier")
	}
	requestStorage := common.NewRequestStorage(s, presentationRequestNamespace)
	service := Service{
		storage:    presentationStorage,
		keystore:   keystore,
		opsStorage: opsStorage,
		resolver:   resolver,
		schema:     schema,
		verifier:   verifier,
		reqStorage: requestStorage,
	}
	if !service.Status().IsReady() {
		return nil, errors.New(service.Status().Message)
	}
	return &service, nil
}

type VerifyPresentationRequest struct {
	PresentationJWT *keyaccess.JWT `json:"presentationJwt,omitempty" validate:"required"`
}

type VerifyPresentationResponse struct {
	Verified bool   `json:"verified"`
	Reason   string `json:"reason,omitempty"`
}

// VerifyPresentation does a series of verification on a presentation:
//  1. Makes sure the presentation has a valid signature
//  2. Makes sure the presentation is not expired
//  3. Makes sure the presentation complies with the VC Data Model v1.1
//  4. For each verification in the presentation, makes sure:
//     a. Makes sure the verification has a valid signature
//     b. Makes sure the verification is not expired
//     c. Makes sure the verification complies with the VC Data Model
func (s Service) VerifyPresentation(ctx context.Context, request VerifyPresentationRequest) (*VerifyPresentationResponse, error) {
	logrus.Debugf("verifying presentation: %+v", request)

	if err := sdkutil.IsValidStruct(request); err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "invalid verify presentation request")
	}

	if err := s.verifier.VerifyJWTPresentation(ctx, *request.PresentationJWT); err != nil {
		return &VerifyPresentationResponse{Verified: false, Reason: err.Error()}, nil
	}

	return &VerifyPresentationResponse{Verified: true}, nil
}

// CreatePresentationDefinition houses the main service logic for presentation definition creation. It validates the input, and
// produces a presentation definition value that conforms with the PresentationDefinition specification.
func (s Service) CreatePresentationDefinition(ctx context.Context,
	request model.CreatePresentationDefinitionRequest) (*model.CreatePresentationDefinitionResponse, error) {
	logrus.Debugf("creating presentation definition: %+v", request)

	if err := request.IsValid(); err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "invalid create presentation definition request: %+v", request)
	}

	if err := exchange.IsValidPresentationDefinition(request.PresentationDefinition); err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "provided value is not a valid presentation definition")
	}

	storedPresentation := presentationstorage.StoredDefinition{
		ID:                     request.PresentationDefinition.ID,
		PresentationDefinition: request.PresentationDefinition,
	}

	if err := s.storage.StoreDefinition(ctx, storedPresentation); err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not store presentation")
	}

	var m model.CreatePresentationDefinitionResponse
	m.PresentationDefinition = storedPresentation.PresentationDefinition
	return &m, nil
}

func (s Service) GetPresentationDefinition(ctx context.Context,
	request model.GetPresentationDefinitionRequest) (*model.GetPresentationDefinitionResponse, error) {
	logrus.Debugf("getting presentation definition: %s", request.ID)

	storedDefinition, err := s.storage.GetDefinition(ctx, request.ID)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "error getting presentation definition: %s", request.ID)
	}
	if storedDefinition == nil {
		return nil, sdkutil.LoggingNewErrorf("presentation definition with id<%s> could not be found", request.ID)
	}
	return &model.GetPresentationDefinitionResponse{
		PresentationDefinition: storedDefinition.PresentationDefinition,
	}, nil
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
	return &model.ListRequestsResponse{PresentationRequests: reqs}, nil
}

func (s Service) DeletePresentationDefinition(ctx context.Context, request model.DeletePresentationDefinitionRequest) error {
	logrus.Debugf("deleting presentation definition: %s", request.ID)

	if err := s.storage.DeleteDefinition(ctx, request.ID); err != nil {
		return sdkutil.LoggingNewErrorf("could not delete presentation definition with id: %s", request.ID)
	}

	return nil
}

// CreateSubmission houses the main service logic for presentation submission creation. It validates the input, and
// produces a presentation submission value that conforms with the Submission specification.
func (s Service) CreateSubmission(ctx context.Context, request model.CreateSubmissionRequest) (*operation.Operation, error) {
	if !request.IsValid() {
		return nil, errors.Errorf("invalid create presentation submission request: %+v", request)
	}

	if err := exchange.IsValidPresentationSubmission(request.Submission); err != nil {
		return nil, errors.Wrap(err, "provided value is not a valid presentation submission")
	}

	headers, _, vp, err := integrity.ParseVerifiablePresentationFromJWT(request.SubmissionJWT.String())
	if err != nil {
		return nil, errors.Wrap(err, "parsing vp from jwt")
	}

	gotKID, ok := headers.Get(jws.KeyIDKey)
	if !ok {
		return nil, errors.New("kid not found in token headers")
	}
	kid, ok := gotKID.(string)
	if !ok {
		return nil, errors.New("kid not a string")
	}

	// verify the token with the did by first resolving the did and getting the public key and next verifying the token
	if err = didint.VerifyTokenFromDID(ctx, s.resolver, vp.Holder, kid, request.SubmissionJWT); err != nil {
		return nil, errors.Wrapf(err, "verifying token from did<%s> with kid<%s>", vp.Holder, kid)
	}

	if _, err = s.storage.GetSubmission(ctx, request.Submission.ID); !errors.Is(err, presentationstorage.ErrSubmissionNotFound) {
		return nil, errors.Errorf("submission with id %s already present", request.Submission.ID)
	}

	storedDefinition, err := s.storage.GetDefinition(ctx, request.Submission.DefinitionID)
	if err != nil {
		return nil, errors.Wrap(err, "getting presentation definition")
	}

	for _, cred := range request.Credentials {
		if !cred.IsValid() {
			return nil, errors.Errorf("invalid credential %+v", cred)
		}
		if cred.CredentialJWT != nil {
			if err = s.verifier.VerifyJWTCredential(ctx, *cred.CredentialJWT); err != nil {
				return nil, errors.Wrapf(err, "verifying jwt credential %s", cred.CredentialJWT)
			}
		} else {
			if cred.HasDataIntegrityCredential() {
				if err = s.verifier.VerifyDataIntegrityCredential(ctx, *cred.Credential); err != nil {
					return nil, errors.Wrapf(err, "verifying data integrity credential %+v", cred.Credential)
				}
			}
		}
	}

	// TODO(gabe) plug in additional credential verification logic here
	if _, err = exchange.VerifyPresentationSubmissionVP(storedDefinition.PresentationDefinition, request.Presentation); err != nil {
		return nil, errors.Wrap(err, "verifying presentation submission vp")
	}

	storedSubmission := presentationstorage.StoredSubmission{
		Status:                 submission.StatusPending,
		VerifiablePresentation: request.Presentation,
	}

	// TODO(andres): IO requests should be done in parallel, once we have context wired up.
	if err = s.storage.StoreSubmission(ctx, storedSubmission); err != nil {
		return nil, errors.Wrap(err, "could not store presentation")
	}

	sub, ok := storedSubmission.VerifiablePresentation.PresentationSubmission.(exchange.PresentationSubmission)
	if !ok {
		return nil, errors.New("interface is not exchange.PresentationSubmission")
	}
	opID := submission.IDFromSubmissionID(sub.ID)
	storedOp := opstorage.StoredOperation{
		ID:   opID,
		Done: false,
	}
	if err = s.opsStorage.StoreOperation(ctx, storedOp); err != nil {
		return nil, errors.Wrap(err, "could not store operation")
	}

	return &operation.Operation{
		ID:   storedOp.ID,
		Done: false,
	}, nil
}

func (s Service) GetSubmission(ctx context.Context, request model.GetSubmissionRequest) (*model.GetSubmissionResponse, error) {
	logrus.Debugf("getting presentation submission: %s", request.ID)

	storedSubmission, err := s.storage.GetSubmission(ctx, request.ID)
	if err != nil {
		return nil, errors.Wrap(err, "fetching from storage")
	}
	return &model.GetSubmissionResponse{
		Submission: model.ServiceModel(storedSubmission),
	}, nil
}

func (s Service) ListSubmissions(ctx context.Context, request model.ListSubmissionRequest) (*model.ListSubmissionResponse, error) {
	logrus.Debug("listing presentation submissions")

	subs, err := s.storage.ListSubmissions(ctx, request.Filter, *request.PageRequest.ToServicePage())
	if err != nil {
		return nil, errors.Wrap(err, "fetching submissions from storage")
	}

	resp := &model.ListSubmissionResponse{
		Submissions:   make([]model.Submission, 0, len(subs.Submissions)),
		NextPageToken: subs.NextPageToken,
	}
	for _, sub := range subs.Submissions {
		sub := sub // What's this?? see https://github.com/golang/go/wiki/CommonMistakes#using-reference-to-loop-iterator-variable
		resp.Submissions = append(resp.Submissions, model.ServiceModel(&sub))
	}

	return resp, nil
}

func (s Service) ReviewSubmission(ctx context.Context, request model.ReviewSubmissionRequest) (*model.Submission, error) {
	if err := request.Validate(); err != nil {
		return nil, errors.Wrap(err, "invalid request")
	}

	updatedSubmission, _, err := s.storage.UpdateSubmission(ctx, request.ID, request.Approved, request.Reason,
		submission.IDFromSubmissionID(request.ID))
	if err != nil {
		return nil, errors.Wrap(err, "updating submission")
	}

	m := model.ServiceModel(&updatedSubmission)
	return &m, nil
}

func (s Service) ListDefinitions(ctx context.Context) (*model.ListDefinitionsResponse, error) {
	logrus.Debug("listing presentation definitions")

	defs, err := s.storage.ListDefinitions(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "fetching definitions from storage")
	}

	resp := &model.ListDefinitionsResponse{Definitions: make([]*exchange.PresentationDefinition, 0, len(defs))}
	for _, def := range defs {
		// What's this?? see https://github.com/golang/go/wiki/CommonMistakes#using-reference-to-loop-iterator-variable
		def := def
		resp.Definitions = append(resp.Definitions, &def.PresentationDefinition)
	}

	return resp, nil
}

func (s Service) CreateRequest(ctx context.Context, req model.CreateRequestRequest) (*model.Request, error) {
	if err := sdkutil.IsValidStruct(req); err != nil {
		return nil, err
	}

	request := req.PresentationRequest
	pd, err := s.storage.GetDefinition(ctx, request.PresentationDefinitionID)
	if err != nil {
		return nil, errors.Wrap(err, "getting presentation definition")
	}
	if pd == nil {
		return nil, errors.Errorf("presentation definition %q is nil", request.PresentationDefinitionID)
	}

	stored, err := common.CreateStoredRequest(
		ctx,
		s.keystore,
		"presentation_definition",
		pd.PresentationDefinition,
		request.Request,
		request.PresentationDefinitionID,
	)
	if err != nil {
		return nil, errors.Wrap(err, "creating stored request")
	}
	if err := s.reqStorage.StoreRequest(ctx, *stored); err != nil {
		return nil, errors.Wrap(err, "storing signed document")
	}
	return serviceModel(stored)
}

func (s Service) GetRequest(ctx context.Context, request *model.GetRequestRequest) (*model.Request, error) {
	logrus.Debugf("getting presentation request: %s", request.ID)

	storedRequest, err := s.reqStorage.GetRequest(ctx, request.ID)
	if err != nil {
		return nil, errors.Wrapf(err, "getting signed document with id: %s", request.ID)
	}
	if storedRequest == nil {
		return nil, sdkutil.LoggingNewErrorf("presentation request with id<%s> could not be found", request.ID)
	}

	return serviceModel(storedRequest)
}

func (s Service) DeleteRequest(ctx context.Context, request model.DeleteRequestRequest) error {
	logrus.Debugf("deleting presentation request: %s", request.ID)

	if err := s.reqStorage.DeleteRequest(ctx, request.ID); err != nil {
		return sdkutil.LoggingNewErrorf("could not delete presentation request with id: %s", request.ID)
	}

	return nil
}

func serviceModel(storedRequest *common.StoredRequest) (*model.Request, error) {
	req, err := common.ToServiceModel(storedRequest)
	if err != nil {
		return nil, err
	}
	return &model.Request{
		Request:                   *req,
		PresentationDefinitionID:  storedRequest.ReferenceID,
		PresentationDefinitionJWT: keyaccess.JWT(storedRequest.JWT),
	}, nil
}
