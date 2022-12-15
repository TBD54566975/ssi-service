package presentation

import (
	"fmt"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/service/common"
	"github.com/tbd54566975/ssi-service/pkg/service/operation"

	"github.com/tbd54566975/ssi-service/pkg/storage"
	"go.einride.tech/aip/filtering"
)

const (
	namespace           = "presentation_definition"
	submissionNamespace = "presentation_submission"
)

type StoredPresentation struct {
	ID                     string                          `json:"id"`
	PresentationDefinition exchange.PresentationDefinition `json:"presentationDefinition"`
}

type PresentationStorage struct {
	db storage.ServiceStorage
}

type opUpdater struct {
	storage.UpdaterWithMap
}

func (u opUpdater) SetUpdatedResponse(response []byte) {
	u.UpdaterWithMap.Values["response"] = response
}

func (u opUpdater) Validate(v []byte) error {
	var op operation.StoredOperation
	if err := json.Unmarshal(v, &op); err != nil {
		return errors.Wrap(err, "unmarshalling operation")
	}

	if op.Done {
		return errors.New("operation already marked as done")
	}

	return nil
}

var _ storage.ResponseSettingUpdater = (*opUpdater)(nil)

func (ps *PresentationStorage) UpdateSubmission(id string, approved bool, reason string, opID string) (common.StoredSubmission, operation.StoredOperation, error) {
	m := map[string]any{
		"status": common.StatusDenied,
		"reason": reason,
	}
	if approved {
		m["status"] = common.StatusApproved
	}
	submissionData, operationData, err := ps.db.UpdateValueAndOperation(
		submissionNamespace,
		id,
		storage.NewUpdater(m),
		operation.NamespaceFromID(opID),
		opID,
		opUpdater{
			storage.NewUpdater(map[string]any{
				"done": true,
			}),
		})
	if err != nil {
		return common.StoredSubmission{}, operation.StoredOperation{}, errors.Wrap(err, "updating value and operation")
	}

	var s common.StoredSubmission
	if err = json.Unmarshal(submissionData, &s); err != nil {
		return common.StoredSubmission{}, operation.StoredOperation{}, errors.Wrap(err, "unmarshalling written submission")
	}
	var op operation.StoredOperation
	if err = json.Unmarshal(operationData, &op); err != nil {
		return common.StoredSubmission{}, operation.StoredOperation{}, errors.Wrap(err, "unmarshalling written operation")
	}
	return s, op, nil
}

func (ps *PresentationStorage) ListSubmissions(filter filtering.Filter) ([]common.StoredSubmission, error) {
	allData, err := ps.db.ReadAll(submissionNamespace)
	if err != nil {
		return nil, errors.Wrap(err, "reading all data")
	}

	shouldInclude, err := storage.NewIncludeFunc(filter)
	if err != nil {
		return nil, err
	}
	storedSubmissions := make([]common.StoredSubmission, 0, len(allData))
	for key, data := range allData {
		var ss common.StoredSubmission
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
	return ps.db.Write(namespace, id, jsonBytes)
}

func (ps *PresentationStorage) GetPresentation(id string) (*StoredPresentation, error) {
	jsonBytes, err := ps.db.Read(namespace, id)
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
	if err := ps.db.Delete(namespace, id); err != nil {
		return util.LoggingNewErrorf("could not delete presentation definition: %s", id)
	}
	return nil
}

func (ps *PresentationStorage) StoreSubmission(submission common.StoredSubmission) error {
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
	return ps.db.Write(submissionNamespace, id, jsonBytes)
}

func (ps *PresentationStorage) GetSubmission(id string) (*common.StoredSubmission, error) {
	jsonBytes, err := ps.db.Read(submissionNamespace, id)
	if err != nil {
		return nil, util.LoggingNewErrorf("could not get submission definition: %s", id)
	}
	if len(jsonBytes) == 0 {
		return nil, util.LoggingErrorMsgf(common.ErrSubmissionNotFound, "reading submission with id: %s", id)
	}
	var stored common.StoredSubmission
	if err := json.Unmarshal(jsonBytes, &stored); err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not unmarshal stored submission definition: %s", id)
	}
	return &stored, nil
}
