package presentation

import (
	"fmt"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	presentationstorage "github.com/tbd54566975/ssi-service/pkg/service/presentation/storage"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type Service struct {
	storage presentationstorage.Storage
	config  config.PresentationServiceConfig
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

func NewPresentationService(config config.PresentationServiceConfig, s storage.ServiceStorage) (*Service, error) {
	presentationStorage, err := presentationstorage.NewPresentationStorage(s)
	if err != nil {
		errMsg := "could not instantiate storage for the presentation definition service"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	service := Service{
		storage: presentationStorage,
		config:  config,
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

	storedPresentation := presentationstorage.StoredPresentation{ID: request.PresentationDefinition.ID, PresentationDefinition: request.PresentationDefinition}

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
func (s Service) CreateSubmission(request CreateSubmissionRequest) (*CreateSubmissionResponse, error) {
	logrus.Debugf("creating presentation submission: %+v", request)

	if !request.IsValid() {
		errMsg := fmt.Sprintf("invalid create presentation submission request: %+v", request)
		return nil, util.LoggingNewError(errMsg)
	}

	if err := exchange.IsValidPresentationSubmission(request.Submission); err != nil {
		return nil, util.LoggingErrorMsg(err, "provided value is not a valid presentation submission")
	}

	storedSubmission := presentationstorage.StoredSubmission{Submission: request.Submission}

	if err := s.storage.StoreSubmission(storedSubmission); err != nil {
		return nil, util.LoggingErrorMsg(err, "could not store presentation")
	}

	return &CreateSubmissionResponse{
		Submission: storedSubmission.Submission,
	}, nil
}

func (s Service) GetSubmission(request GetSubmissionRequest) (*GetSubmissionResponse, error) {
	logrus.Debugf("getting presentation submission: %s", request.ID)

	storedSubmission, err := s.storage.GetSubmission(request.ID)
	if err != nil {
		err := errors.Wrapf(err, "error getting presentation submission: %s", request.ID)
		return nil, util.LoggingError(err)
	}
	if storedSubmission == nil {
		err := fmt.Errorf("presentation submission with id<%s> could not be found", request.ID)
		return nil, util.LoggingError(err)
	}
	return &GetSubmissionResponse{Submission: storedSubmission.Submission}, nil
}
