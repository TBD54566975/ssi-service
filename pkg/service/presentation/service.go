package presentation

import (
	"fmt"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/credential/signing"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/jwt"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/operation"
	opstorage "github.com/tbd54566975/ssi-service/pkg/service/operation/storage"
	"github.com/tbd54566975/ssi-service/pkg/service/operation/submission"
	"github.com/tbd54566975/ssi-service/pkg/service/presentation/model"
	presentationstorage "github.com/tbd54566975/ssi-service/pkg/service/presentation/storage"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type Service struct {
	storage    *PresentationStorage
	opsStorage *operation.OperationStorage
	config     config.PresentationServiceConfig
	resolver   *didsdk.Resolver
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

func NewPresentationService(config config.PresentationServiceConfig, s storage.ServiceStorage, resolver *didsdk.Resolver, schema *schema.Service) (*Service, error) {
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
func (s Service) CreatePresentationDefinition(request CreatePresentationDefinitionRequest) (*CreatePresentationDefinitionResponse, error) {
	logrus.Debugf("creating presentation definition: %+v", request)

	if !request.IsValid() {
		return nil, util.LoggingNewErrorf("invalid create presentation definition request: %+v", request)
	}

	if err := exchange.IsValidPresentationDefinition(request.PresentationDefinition); err != nil {
		return nil, util.LoggingErrorMsg(err, "provided value is not a valid presentation definition")
	}

	storedPresentation := StoredPresentation{ID: request.PresentationDefinition.ID, PresentationDefinition: request.PresentationDefinition}

	if err := s.storage.StorePresentation(storedPresentation); err != nil {
		return nil, util.LoggingErrorMsg(err, "could not store presentation")
	}

	return &CreatePresentationDefinitionResponse{
		PresentationDefinition: storedPresentation.PresentationDefinition,
	}, nil
}

func (s Service) GetPresentationDefinition(request GetPresentationDefinitionRequest) (*GetPresentationDefinitionResponse, error) {
	logrus.Debugf("getting presentation definition: %s", request.ID)

	storedPresentation, err := s.storage.GetPresentation(request.ID)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "error getting presentation definition: %s", request.ID)
	}
	if storedPresentation == nil {
		return nil, util.LoggingNewErrorf("presentation definition with id<%s> could not be found", request.ID)
	}
	return &GetPresentationDefinitionResponse{ID: storedPresentation.ID, PresentationDefinition: storedPresentation.PresentationDefinition}, nil
}

func (s Service) DeletePresentationDefinition(request DeletePresentationDefinitionRequest) error {
	logrus.Debugf("deleting presentation definition: %s", request.ID)

	if err := s.storage.DeletePresentation(request.ID); err != nil {
		return util.LoggingNewErrorf("could not delete presentation definition with id: %s", request.ID)
	}

	return nil
}

// CreateSubmission houses the main service logic for presentation submission creation. It validates the input, and
// produces a presentation submission value that conforms with the Submission specification.
func (s Service) CreateSubmission(request submission.CreateSubmissionRequest) (*operation.Operation, error) {
	if !request.IsValid() {
		return nil, errors.Errorf("invalid create presentation submission request: %+v", request)
	}

	if err := exchange.IsValidPresentationSubmission(request.Submission); err != nil {
		return nil, errors.Wrap(err, "provided value is not a valid presentation submission")
	}

	sdkVP, err := signing.ParseVerifiablePresentationFromJWT(request.SubmissionJWT.String())
	if err != nil {
		return nil, errors.Wrap(err, "parsing vp from jwt")
	}
	if err := jwt.VerifyTokenFromDID(sdkVP.Holder, request.SubmissionJWT, s.resolver); err != nil {
		return nil, errors.Wrap(err, "verifying token from did")
	}

	if _, err := s.storage.GetSubmission(request.Submission.ID); !errors.Is(err, submission.ErrSubmissionNotFound) {
		return nil, errors.Errorf("submission with id %s already present", request.Submission.ID)
	}

	definition, err := s.storage.GetPresentation(request.Submission.DefinitionID)
	if err != nil {
		return nil, errors.Wrap(err, "getting presentation definition")
	}

	for _, cred := range request.Credentials {
		if !cred.IsValid() {
			return nil, errors.Errorf("invalid credential %+v", cred)
		}
		if cred.CredentialJWT != nil {
			if err := s.verifier.VerifyJWTCredential(*cred.CredentialJWT); err != nil {
				return nil, errors.Wrapf(err, "verifying jwt credential %s", cred.CredentialJWT)
			}
		} else {
			if cred.HasDataIntegrityCredential() {
				if err := s.verifier.VerifyDataIntegrityCredential(*cred.Credential); err != nil {
					return nil, errors.Wrapf(err, "verifying data integrity credential %+v", cred.Credential)
				}
			}
		}
	}

	if err := exchange.VerifyPresentationSubmissionVP(definition.PresentationDefinition, request.Presentation); err != nil {
		return nil, errors.Wrap(err, "verifying presentation submission vp")
	}

	storedSubmission := presentationstorage.StoredSubmission{
		Status:     submission.StatusPending,
		Submission: request.Submission,
	}

	// TODO(andres): IO requests should be done in parallel, once we have context wired up.
	if err := s.storage.StoreSubmission(storedSubmission); err != nil {
		return nil, errors.Wrap(err, "could not store presentation")
	}

	opID := submission.IDFromSubmissionID(storedSubmission.Submission.ID)
	storedOp := operation.StoredOperation{
		ID:   opID,
		Done: false,
	}
	if err := s.opsStorage.StoreOperation(storedOp); err != nil {
		return nil, errors.Wrap(err, "could not store operation")
	}

	return &operation.Operation{
		ID:   storedOp.ID,
		Done: false,
	}, nil
}

func (s Service) GetSubmission(request submission.GetSubmissionRequest) (*submission.GetSubmissionResponse, error) {
	logrus.Debugf("getting presentation submission: %s", request.ID)

	storedSubmission, err := s.storage.GetSubmission(request.ID)
	if err != nil {
		return nil, errors.Wrap(err, "fetching from storage")
	}
	return &submission.GetSubmissionResponse{
		Submission: submission.ServiceModel(storedSubmission),
	}, nil
}

func (s Service) ListSubmissions(request submission.ListSubmissionRequest) (*submission.ListSubmissionResponse, error) {
	logrus.Debug("listing presentation submissions")

	subs, err := s.storage.ListSubmissions(request.Filter)
	if err != nil {
		return nil, errors.Wrap(err, "fetching submissions from storage")
	}

	resp := &submission.ListSubmissionResponse{Submissions: make([]submission.Submission, 0, len(subs))}
	for _, sub := range subs {
		sub := sub // What's this?? see https://github.com/golang/go/wiki/CommonMistakes#using-reference-to-loop-iterator-variable
		resp.Submissions = append(resp.Submissions, submission.ServiceModel(&sub))
	}

	return resp, nil
}

func (s Service) ReviewSubmission(request submission.ReviewSubmissionRequest) (*submission.Submission, error) {
	if err := request.Validate(); err != nil {
		return nil, errors.Wrap(err, "invalid request")
	}

	updatedSubmission, _, err := s.storage.UpdateSubmission(request.ID, request.Approved, request.Reason, submission.IDFromSubmissionID(request.ID))
	if err != nil {
		return nil, errors.Wrap(err, "updating submission")
	}

	m := submission.ServiceModel(&updatedSubmission)
	return &m, nil
}
