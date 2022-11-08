package submission

import (
	"fmt"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	presentationstorage "github.com/tbd54566975/ssi-service/pkg/service/submission/storage"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type Service struct {
	storage presentationstorage.Storage
	// TODO(andres) maybe change this
	config config.PresentationServiceConfig
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

func NewSubmissionService(config config.PresentationServiceConfig, s storage.ServiceStorage) (*Service, error) {
	presentationStorage, err := presentationstorage.NewSubmissionStorage(s)
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

// CreateSubmission houses the main service logic for presentation definition creation. It validates the input, and
// produces a presentation definition value that conforms with the Submission specification.
func (s Service) CreateSubmission(request CreateSubmissionRequest) (*CreateSubmissionResponse, error) {
	logrus.Debugf("creating presentation definition: %+v", request)

	if !request.IsValid() {
		errMsg := fmt.Sprintf("invalid create presentation definition request: %+v", request)
		return nil, util.LoggingNewError(errMsg)
	}

	if err := exchange.IsValidPresentationSubmission(request.Submission); err != nil {
		return nil, util.LoggingErrorMsg(err, "provided value is not a valid presentation definition")
	}

	storedSubmission := presentationstorage.StoredSubmission{ID: request.Submission.ID, Submission: request.Submission}

	if err := s.storage.StoreSubmission(storedSubmission); err != nil {
		return nil, util.LoggingErrorMsg(err, "could not store presentation")
	}

	return &CreateSubmissionResponse{
		Submission: storedSubmission.Submission,
	}, nil
}

func (s Service) GetSubmission(request GetSubmissionRequest) (*GetSubmissionResponse, error) {
	logrus.Debugf("getting presentation definition: %s", request.ID)

	storedSubmission, err := s.storage.GetSubmission(request.ID)
	if err != nil {
		err := errors.Wrapf(err, "error getting presentation definition: %s", request.ID)
		return nil, util.LoggingError(err)
	}
	if storedSubmission == nil {
		err := fmt.Errorf("presentation definition with id<%s> could not be found", request.ID)
		return nil, util.LoggingError(err)
	}
	return &GetSubmissionResponse{ID: storedSubmission.ID, Submission: storedSubmission.Submission}, nil
}

func (s Service) DeleteSubmission(request DeleteSubmissionRequest) error {
	logrus.Debugf("deleting presentation definition: %s", request.ID)

	if err := s.storage.DeleteSubmission(request.ID); err != nil {
		errMsg := fmt.Sprintf("could not delete presentation definition with id: %s", request.ID)
		return util.LoggingErrorMsg(err, errMsg)
	}

	return nil
}
