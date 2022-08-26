package storage

import (
	"fmt"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

const (
	namespace = "manifest"
)

type BoltManifestStorage struct {
	db *storage.BoltDB
}

func NewBoltManifestStorage(db *storage.BoltDB) (*BoltManifestStorage, error) {
	if db == nil {
		return nil, errors.New("bolt db reference is nil")
	}
	return &BoltManifestStorage{db: db}, nil
}

func (b BoltManifestStorage) StoreManifest(manifest StoredManifest) error {
	//id := manifest.Schema.ID
	id := manifest.Manifest.ID
	if id == "" {
		err := errors.New("could not store manifest without an ID")
		logrus.WithError(err).Error()
		return err
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		errMsg := fmt.Sprintf("could not store manifest: %s", id)
		logrus.WithError(err).Error(errMsg)
		return errors.Wrapf(err, errMsg)
	}
	return b.db.Write(namespace, id, manifestBytes)
}

func (b BoltManifestStorage) GetManifest(id string) (*StoredManifest, error) {
	manifestBytes, err := b.db.Read(namespace, id)
	if err != nil {
		errMsg := fmt.Sprintf("could not get manifest: %s", id)
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrapf(err, errMsg)
	}
	if len(manifestBytes) == 0 {
		err := fmt.Errorf("manifest not found with id: %s", id)
		logrus.WithError(err).Error("could not get manifest from storage")
		return nil, err
	}
	var stored StoredManifest
	if err := json.Unmarshal(manifestBytes, &stored); err != nil {
		errMsg := fmt.Sprintf("could not unmarshal stored manifest: %s", id)
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrapf(err, errMsg)
	}
	return &stored, nil
}

// GetManifests attempts to get all stored manifests. It will return those it can even if it has trouble with some.
func (b BoltManifestStorage) GetManifests() ([]StoredManifest, error) {
	gotmanifests, err := b.db.ReadAll(namespace)
	if err != nil {
		errMsg := "could not get all manifests"
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrap(err, errMsg)
	}
	if len(gotmanifests) == 0 {
		logrus.Info("no manifests to get")
		return nil, nil
	}
	var stored []StoredManifest
	for _, manifestBytes := range gotmanifests {
		var nextmanifest StoredManifest
		if err := json.Unmarshal(manifestBytes, &nextmanifest); err == nil {
			stored = append(stored, nextmanifest)
		}
	}
	return stored, nil
}

func (b BoltManifestStorage) DeleteManifest(id string) error {
	if err := b.db.Delete(namespace, id); err != nil {
		errMsg := fmt.Sprintf("could not delete manifest: %s", id)
		logrus.WithError(err).Error(errMsg)
		return errors.Wrapf(err, errMsg)
	}
	return nil
}
