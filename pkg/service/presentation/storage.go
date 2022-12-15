package presentation

import (
	"fmt"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tbd54566975/ssi-service/internal/util"
	opstorage "github.com/tbd54566975/ssi-service/pkg/service/operation/storage"
	"github.com/tbd54566975/ssi-service/pkg/service/operation/storage/namespace"
	"github.com/tbd54566975/ssi-service/pkg/service/operation/submission"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"go.einride.tech/aip/filtering"
)

const (
	presentationDefinitionNamespace = "presentation_definition"
)

type StoredPresentation struct {
	ID                     string                          `json:"id"`
	PresentationDefinition exchange.PresentationDefinition `json:"presentationDefinition"`
}

type PresentationStorage struct {
	db storage.ServiceStorage
}

func (b PresentationStorage) UpdateSubmission(id string, approved bool, reason string, opID string) (StoredSubmission, opstorage.StoredOperation, error) {
	m := map[string]any{
		"status": submission.StatusDenied,
		"reason": reason,
	}
	if approved {
		m["status"] = submission.StatusApproved
	}
	submissionData, operationData, err := ps.db.UpdateValueAndOperation(
		submission.Namespace,
		id,
		storage.NewUpdater(m),
		namespace.FromID(opID),
		opID,
		submission.OperationUpdater{
			UpdaterWithMap: storage.NewUpdater(map[string]any{
				"done": true,
			}),
		})
	if err != nil {
		return submission.StoredSubmission{}, operation.StoredOperation{}, errors.Wrap(err, "updating value and operation")
	}

	var s submission.StoredSubmission
	if err = json.Unmarshal(submissionData, &s); err != nil {
		return submission.StoredSubmission{}, operation.StoredOperation{}, errors.Wrap(err, "unmarshalling written submission")
	}
	var op operation.StoredOperation
	if err = json.Unmarshal(operationData, &op); err != nil {
		return submission.StoredSubmission{}, operation.StoredOperation{}, errors.Wrap(err, "unmarshalling written operation")
	}
	return s, op, nil
}

func (ps *PresentationStorage) ListSubmissions(filter filtering.Filter) ([]submission.StoredSubmission, error) {
	allData, err := ps.db.ReadAll(submission.Namespace)
	if err != nil {
		return nil, errors.Wrap(err, "reading all data")
	}

	shouldInclude, err := storage.NewIncludeFunc(filter)
	if err != nil {
		return nil, err
	}
	storedSubmissions := make([]submission.StoredSubmission, 0, len(allData))
	for key, data := range allData {
		var ss submission.StoredSubmission
		if err = json.Unmarshal(data, &ss); err != nil {
			logrus.WithError(err).WithField("key", key).Error("unmarshalling submission")
		}
		include, err := shouldInclude(ss)
		// We explicitly ignore evaluation errors and simply include them in the result.
		if err != nil {
			storedSubmissions = append(storedSubmissions, ss)
			continue
		}
		if include {
			storedSubmissions = append(storedSubmissions, ss)
		}
	}
	return storedSubmissions, nil
}

func NewPresentationStorage(db storage.ServiceStorage) (*PresentationStorage, error) {
	if db == nil {
		return nil, errors.New("bolt db reference is nil")
	}
	return &PresentationStorage{db: db}, nil
}

func (ps *PresentationStorage) StorePresentation(presentation StoredPresentation) error {
	id := presentation.ID
	if id == "" {
		err := errors.New("could not store presentation definition without an ID")
		logrus.WithError(err).Error()
		return err
	}
	jsonBytes, err := json.Marshal(presentation)
	if err != nil {
		errMsg := fmt.Sprintf("could not store presentation definition: %s", id)
		logrus.WithError(err).Error(errMsg)
		return errors.Wrapf(err, errMsg)
	}
	return ps.db.Write(presentationDefinitionNamespace, id, jsonBytes)
}

func (ps *PresentationStorage) GetPresentation(id string) (*StoredPresentation, error) {
	jsonBytes, err := ps.db.Read(presentationDefinitionNamespace, id)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get presentation definition: %s", id)
	}
	if len(jsonBytes) == 0 {
		return nil, util.LoggingNewErrorf("presentation definition not found with id: %s", id)
	}
	var stored StoredPresentation
	if err := json.Unmarshal(jsonBytes, &stored); err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not unmarshal stored presentation definition: %s", id)
	}
	return &stored, nil
}

func (ps *PresentationStorage) DeletePresentation(id string) error {
	if err := ps.db.Delete(presentationDefinitionNamespace, id); err != nil {
		return util.LoggingNewErrorf("could not delete presentation definition: %s", id)
	}
	return nil
}

func (ps PresentationStorage) StoreSubmission(s StoredSubmission) error {
	id := s.Submission.ID
	if id == "" {
		err := errors.New("could not store submission definition without an ID")
		logrus.WithError(err).Error()
		return err
	}
	jsonBytes, err := json.Marshal(s)
	if err != nil {
		return util.LoggingNewErrorf("could not store submission definition: %s", id)
	}
	return ps.db.Write(submission.Namespace, id, jsonBytes)
}

func (ps *PresentationStorage) GetSubmission(id string) (*submission.StoredSubmission, error) {
	jsonBytes, err := ps.db.Read(submission.Namespace, id)
	if err != nil {
		return nil, util.LoggingNewErrorf("could not get submission definition: %s", id)
	}
	if len(jsonBytes) == 0 {
		return nil, util.LoggingErrorMsgf(submission.ErrSubmissionNotFound, "reading submission with id: %s", id)
	}
	var stored submission.StoredSubmission
	if err := json.Unmarshal(jsonBytes, &stored); err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not unmarshal stored submission definition: %s", id)
	}
	return &stored, nil
}
