package storage

import (
	"fmt"

	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/pkg/storage"
)

const (
	namespace = "presentation_definition"
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
		errMsg := fmt.Sprintf("could not get presentation definition: %s", id)
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrapf(err, errMsg)
	}
	if len(jsonBytes) == 0 {
		err := fmt.Errorf("presentation definition not found with id: %s", id)
		logrus.WithError(err).Error("could not get presentation definition from storage")
		return nil, err
	}
	var stored StoredPresentation
	if err := json.Unmarshal(jsonBytes, &stored); err != nil {
		errMsg := fmt.Sprintf("could not unmarshal stored presentation definition: %s", id)
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrapf(err, errMsg)
	}
	return &stored, nil
}

func (b BoltPresentationStorage) DeletePresentation(id string) error {
	if err := b.db.Delete(namespace, id); err != nil {
		errMsg := fmt.Sprintf("could not delete presentation definition: %s", id)
		logrus.WithError(err).Error(errMsg)
		return errors.Wrapf(err, errMsg)
	}
	return nil
}
