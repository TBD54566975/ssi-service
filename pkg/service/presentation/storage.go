package presentation

import (
	"context"
	"fmt"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tbd54566975/ssi-service/internal/util"
	opstorage "github.com/tbd54566975/ssi-service/pkg/service/operation/storage"
	"github.com/tbd54566975/ssi-service/pkg/service/operation/storage/namespace"
	opsubmission "github.com/tbd54566975/ssi-service/pkg/service/operation/submission"
	prestorage "github.com/tbd54566975/ssi-service/pkg/service/presentation/storage"
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

type Storage struct {
	db storage.ServiceStorage
}

func (ps Storage) UpdateSubmission(id string, approved bool, reason string, opID string) (prestorage.StoredSubmission, opstorage.StoredOperation, error) {
	m := map[string]any{
		"status": opsubmission.StatusDenied,
		"reason": reason,
	}
	if approved {
		m["status"] = opsubmission.StatusApproved
	}
	submissionData, operationData, err := ps.db.UpdateValueAndOperation(
		opsubmission.Namespace,
		id,
		storage.NewUpdater(m),
		namespace.FromID(opID),
		opID,
		opsubmission.OperationUpdater{
			UpdaterWithMap: storage.NewUpdater(map[string]any{
				"done": true,
			}),
		})
	if err != nil {
		return prestorage.StoredSubmission{}, opstorage.StoredOperation{}, errors.Wrap(err, "updating value and operation")
	}

	var s prestorage.StoredSubmission
	if err = json.Unmarshal(submissionData, &s); err != nil {
		return prestorage.StoredSubmission{}, opstorage.StoredOperation{}, errors.Wrap(err, "unmarshalling written submission")
	}
	var op opstorage.StoredOperation
	if err = json.Unmarshal(operationData, &op); err != nil {
		return prestorage.StoredSubmission{}, opstorage.StoredOperation{}, errors.Wrap(err, "unmarshalling written operation")
	}
	return s, op, nil
}

func (ps *Storage) ListSubmissions(filter filtering.Filter) ([]prestorage.StoredSubmission, error) {
	allData, err := ps.db.ReadAll(opsubmission.Namespace)
	if err != nil {
		return nil, errors.Wrap(err, "reading all data")
	}

	shouldInclude, err := storage.NewIncludeFunc(filter)
	if err != nil {
		return nil, err
	}
	storedSubmissions := make([]prestorage.StoredSubmission, 0, len(allData))
	for key, data := range allData {
		var ss prestorage.StoredSubmission
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

func NewPresentationStorage(db storage.ServiceStorage) (*Storage, error) {
	if db == nil {
		return nil, errors.New("bolt db reference is nil")
	}
	return &Storage{db: db}, nil
}

func (ps *Storage) StorePresentation(ctx context.Context, presentation StoredPresentation) error {
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
	return ps.db.Write(ctx, presentationDefinitionNamespace, id, jsonBytes)
}

func (ps *Storage) GetPresentation(id string) (*StoredPresentation, error) {
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

func (ps *Storage) DeletePresentation(id string) error {
	if err := ps.db.Delete(presentationDefinitionNamespace, id); err != nil {
		return util.LoggingNewErrorf("could not delete presentation definition: %s", id)
	}
	return nil
}

func (ps Storage) StoreSubmission(ctx context.Context, s prestorage.StoredSubmission) error {
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
	return ps.db.Write(ctx, opsubmission.Namespace, id, jsonBytes)
}

func (ps *Storage) GetSubmission(id string) (*prestorage.StoredSubmission, error) {
	jsonBytes, err := ps.db.Read(opsubmission.Namespace, id)
	if err != nil {
		return nil, util.LoggingNewErrorf("could not get submission definition: %s", id)
	}
	if len(jsonBytes) == 0 {
		return nil, util.LoggingErrorMsgf(prestorage.ErrSubmissionNotFound, "reading submission with id: %s", id)
	}
	var stored prestorage.StoredSubmission
	if err := json.Unmarshal(jsonBytes, &stored); err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not unmarshal stored submission definition: %s", id)
	}
	return &stored, nil
}
