package storage

import (
	"fmt"
	"github.com/tbd54566975/ssi-service/internal/util"

	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/pkg/storage"
)

const (
	namespace           = "presentation_definition"
	submissionNamespace = "presentation_submission"
)

type BoltPresentationStorage struct {
	db *storage.BoltDB
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
		return nil, util.LoggingNewErrorf("submission definition not found with id: %s", id)
	}
	var stored StoredSubmission
	if err := json.Unmarshal(jsonBytes, &stored); err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not unmarshal stored submission definition: %s", id)
	}
	return &stored, nil
}
