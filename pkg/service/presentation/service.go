package presentation

import (
	"context"
	"fmt"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/credential/signing"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/internal/credential"
	didint "github.com/tbd54566975/ssi-service/internal/did"
	"github.com/tbd54566975/ssi-service/internal/util"
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

type Service struct {
	storage    *Storage
	keystore   *keystore.Service
	opsStorage *operation.Storage
	config     config.PresentationServiceConfig
	resolver   didsdk.Resolver
	schema     *schema.Service
	verifier   *credential.Verifier
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

func (s Service) Config() config.PresentationServiceConfig {
	return s.config
}

func NewPresentationService(config config.PresentationServiceConfig, s storage.ServiceStorage, resolver didsdk.Resolver, schema *schema.Service, keystore *keystore.Service) (*Service, error) {
	presentationStorage, err := NewPresentationStorage(s)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not instantiate definition storage for the presentation service")
	}
	opsStorage, err := operation.NewOperationStorage(s)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not instantiate storage for the operations")
	}
	verifier, err := credential.NewCredentialVerifier(resolver, schema)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not instantiate verifier")
	}
	service := Service{
		storage:    presentationStorage,
		keystore:   keystore,
		opsStorage: opsStorage,
		config:     config,
		resolver:   resolver,
		schema:     schema,
		verifier:   verifier,
	}
	if !service.Status().IsReady() {
		return nil, errors.New(service.Status().Message)
	}
	return &service, nil
}

// CreatePresentationDefinition houses the main service logic for presentation definition creation. It validates the input, and
// produces a presentation definition value that conforms with the PresentationDefinition specification.
func (s Service) CreatePresentationDefinition(ctx context.Context, request model.CreatePresentationDefinitionRequest) (*model.CreatePresentationDefinitionResponse, error) {
	logrus.Debugf("creating presentation definition: %+v", request)

	if err := request.IsValid(); err != nil {
		return nil, util.LoggingErrorMsgf(err, "invalid create presentation definition request: %+v", request)
	}

	if err := exchange.IsValidPresentationDefinition(request.PresentationDefinition); err != nil {
		return nil, util.LoggingErrorMsg(err, "provided value is not a valid presentation definition")
	}

	storedPresentation := StoredPresentation{
		ID:                     request.PresentationDefinition.ID,
		PresentationDefinition: request.PresentationDefinition,
		Author:                 request.Author,
	}

	if err := s.storage.StorePresentation(ctx, storedPresentation); err != nil {
		return nil, util.LoggingErrorMsg(err, "could not store presentation")
	}
	defJWT, err := s.keystore.Sign(context.Background(), storedPresentation.Author, exchange.PresentationDefinitionEnvelope{PresentationDefinition: storedPresentation.PresentationDefinition})
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "signing presentation definition enveloper with author<%s>", storedPresentation.Author)
	}

	var m model.CreatePresentationDefinitionResponse
	m.PresentationDefinition = storedPresentation.PresentationDefinition
	m.PresentationDefinitionJWT = *defJWT
	return &m, nil
}

func (s Service) GetPresentationDefinition(ctx context.Context, request model.GetPresentationDefinitionRequest) (*model.GetPresentationDefinitionResponse, error) {
	logrus.Debugf("getting presentation definition: %s", request.ID)

	storedPresentation, err := s.storage.GetPresentation(ctx, request.ID)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "error getting presentation definition: %s", request.ID)
	}
	if storedPresentation == nil {
		return nil, util.LoggingNewErrorf("presentation definition with id<%s> could not be found", request.ID)
	}
	defJWT, err := s.keystore.Sign(ctx, storedPresentation.Author, exchange.PresentationDefinitionEnvelope{PresentationDefinition: storedPresentation.PresentationDefinition})
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "signing presentation definition envelope by issuer<%s>", storedPresentation.Author)
	}
	return &model.GetPresentationDefinitionResponse{
		ID:                        storedPresentation.ID,
		PresentationDefinition:    storedPresentation.PresentationDefinition,
		PresentationDefinitionJWT: *defJWT,
	}, nil
}

func (s Service) DeletePresentationDefinition(ctx context.Context, request model.DeletePresentationDefinitionRequest) error {
	logrus.Debugf("deleting presentation definition: %s", request.ID)

	if err := s.storage.DeletePresentation(ctx, request.ID); err != nil {
		return util.LoggingNewErrorf("could not delete presentation definition with id: %s", request.ID)
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

	headers, _, vp, err := signing.ParseVerifiablePresentationFromJWT(request.SubmissionJWT.String())
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

	definition, err := s.storage.GetPresentation(ctx, request.Submission.DefinitionID)
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

	if err = exchange.VerifyPresentationSubmissionVP(definition.PresentationDefinition, request.Presentation); err != nil {
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

	subs, err := s.storage.ListSubmissions(ctx, request.Filter)
	if err != nil {
		return nil, errors.Wrap(err, "fetching submissions from storage")
	}

	resp := &model.ListSubmissionResponse{Submissions: make([]model.Submission, 0, len(subs))}
	for _, sub := range subs {
		sub := sub // What's this?? see https://github.com/golang/go/wiki/CommonMistakes#using-reference-to-loop-iterator-variable
		resp.Submissions = append(resp.Submissions, model.ServiceModel(&sub))
	}

	return resp, nil
}

func (s Service) ReviewSubmission(ctx context.Context, request model.ReviewSubmissionRequest) (*model.Submission, error) {
	if err := request.Validate(); err != nil {
		return nil, errors.Wrap(err, "invalid request")
	}

	updatedSubmission, _, err := s.storage.UpdateSubmission(ctx, request.ID, request.Approved, request.Reason, submission.IDFromSubmissionID(request.ID))
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
