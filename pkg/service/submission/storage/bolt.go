package storage

import (
	"fmt"

	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/pkg/storage"
)

const (
	namespace = "presentation_submission"
)

type BoltSubmissionStorage struct {
	db *storage.BoltDB
}

func NewBoltSubmissionStorage(db *storage.BoltDB) (*BoltSubmissionStorage, error) {
	if db == nil {
		return nil, errors.New("bolt db reference is nil")
	}
	return &BoltSubmissionStorage{db: db}, nil
}

func (b BoltSubmissionStorage) StoreSubmission(submission StoredSubmission) error {
	id := submission.Submission.ID
	if id == "" {
		err := errors.New("could not store submission definition without an ID")
		logrus.WithError(err).Error()
		return err
	}
	jsonBytes, err := json.Marshal(submission)
	if err != nil {
		errMsg := fmt.Sprintf("could not store submission definition: %s", id)
		logrus.WithError(err).Error(errMsg)
		return errors.Wrapf(err, errMsg)
	}
	return b.db.Write(namespace, id, jsonBytes)
}

func (b BoltSubmissionStorage) GetSubmission(id string) (*StoredSubmission, error) {
	jsonBytes, err := b.db.Read(namespace, id)
	if err != nil {
		errMsg := fmt.Sprintf("could not get submission definition: %s", id)
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrapf(err, errMsg)
	}
	if len(jsonBytes) == 0 {
		err := fmt.Errorf("submission definition not found with id: %s", id)
		logrus.WithError(err).Error("could not get submission definition from storage")
		return nil, err
	}
	var stored StoredSubmission
	if err := json.Unmarshal(jsonBytes, &stored); err != nil {
		errMsg := fmt.Sprintf("could not unmarshal stored submission definition: %s", id)
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrapf(err, errMsg)
	}
	return &stored, nil
}
