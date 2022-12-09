package storage

import (
	"fmt"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tbd54566975/ssi-service/internal/util"
	opstorage "github.com/tbd54566975/ssi-service/pkg/service/operation/storage"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"go.einride.tech/aip/filtering"
)

const (
	namespace           = "presentation_definition"
	submissionNamespace = "presentation_submission"
)

type BoltPresentationStorage struct {
	db *storage.BoltDB
}

type opUpdater struct {
	storage.UpdaterWithMap
}

func (u opUpdater) SetUpdatedResponse(response []byte) {
	u.UpdaterWithMap.Values["response"] = response
}

func (u opUpdater) Validate(v []byte) error {
	var op opstorage.StoredOperation
	if err := json.Unmarshal(v, &op); err != nil {
		return errors.Wrap(err, "unmarshalling operation")
	}

	if op.Done {
		return errors.New("operation already marked as done")
	}

	return nil
}

var _ storage.ResponseSettingUpdater = (*opUpdater)(nil)

func (b BoltPresentationStorage) UpdateSubmission(id string, approved bool, reason string, opID string) (StoredSubmission, opstorage.StoredOperation, error) {
	m := map[string]any{
		"status": StatusDenied,
		"reason": reason,
	}
	if approved {
		m["status"] = StatusApproved
	}
	submissionData, operationData, err := b.db.UpdateValueAndOperation(
		submissionNamespace,
		id,
		storage.NewUpdater(m),
		opstorage.NamespaceFromID(opID),
		opID,
		opUpdater{
			storage.NewUpdater(map[string]any{
				"done": true,
			}),
		})
	if err != nil {
		return StoredSubmission{}, opstorage.StoredOperation{}, errors.Wrap(err, "updating value and operation")
	}

	var s StoredSubmission
	if err = json.Unmarshal(submissionData, &s); err != nil {
		return StoredSubmission{}, opstorage.StoredOperation{}, errors.Wrap(err, "unmarshalling written submission")
	}
	var op opstorage.StoredOperation
	if err = json.Unmarshal(operationData, &op); err != nil {
		return StoredSubmission{}, opstorage.StoredOperation{}, errors.Wrap(err, "unmarshalling written operation")
	}
	return s, op, nil
}

func (b BoltPresentationStorage) ListSubmissions(filter filtering.Filter) ([]StoredSubmission, error) {
	allData, err := b.db.ReadAll(submissionNamespace)
	if err != nil {
		return nil, errors.Wrap(err, "reading all data")
	}

	shouldInclude, err := storage.NewIncludeFunc(filter)
	if err != nil {
		return nil, err
	}
	storedSubmissions := make([]StoredSubmission, 0, len(allData))
	for key, data := range allData {
		var ss StoredSubmission
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

func NewBoltPresentationStorage(db *storage.BoltDB) (*BoltPresentationStorage, error) {
	if db == nil {
		return nil, errors.New("bolt db reference is nil")
	}
	return &BoltPresentationStorage{db: db}, nil
}

func (b BoltPresentationStorage) StorePresentation(presentation StoredPresentation) error {
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
	return b.db.Write(namespace, id, jsonBytes)
}

func (b BoltPresentationStorage) GetPresentation(id string) (*StoredPresentation, error) {
	jsonBytes, err := b.db.Read(namespace, id)
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

func (b BoltPresentationStorage) DeletePresentation(id string) error {
	if err := b.db.Delete(namespace, id); err != nil {
		return util.LoggingNewErrorf("could not delete presentation definition: %s", id)
	}
	return nil
}

func (b BoltPresentationStorage) StoreSubmission(submission StoredSubmission) error {
	id := submission.Submission.ID
	if id == "" {
		err := errors.New("could not store submission definition without an ID")
		logrus.WithError(err).Error()
		return err
	}
	jsonBytes, err := json.Marshal(submission)
	if err != nil {
		return util.LoggingNewErrorf("could not store submission definition: %s", id)
	}
	return b.db.Write(submissionNamespace, id, jsonBytes)
}

func (b BoltPresentationStorage) GetSubmission(id string) (*StoredSubmission, error) {
	jsonBytes, err := b.db.Read(submissionNamespace, id)
	if err != nil {
		return nil, util.LoggingNewErrorf("could not get submission definition: %s", id)
	}
	if len(jsonBytes) == 0 {
		return nil, util.LoggingErrorMsgf(ErrSubmissionNotFound, "reading submission with id: %s", id)
	}
	var stored StoredSubmission
	if err := json.Unmarshal(jsonBytes, &stored); err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not unmarshal stored submission definition: %s", id)
	}
	return &stored, nil
}
