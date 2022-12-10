package storage

import (
	"fmt"

	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

const (
	manifestNamespace    = "manifest"
	applicationNamespace = "application"
	responseNamespace    = "response"
)

type BoltManifestStorage struct {
	db storage.ServiceStorage
}

func NewBoltManifestStorage(db storage.ServiceStorage) (*BoltManifestStorage, error) {
	if db == nil {
		return nil, errors.New("bolt db reference is nil")
	}
	return &BoltManifestStorage{db: db}, nil
}

func (b BoltManifestStorage) StoreManifest(manifest StoredManifest) error {
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
	return b.db.Write(manifestNamespace, id, manifestBytes)
}

func (b BoltManifestStorage) GetManifest(id string) (*StoredManifest, error) {
	manifestBytes, err := b.db.Read(manifestNamespace, id)
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
	gotManifests, err := b.db.ReadAll(manifestNamespace)
	if err != nil {
		errMsg := "could not get all manifests"
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrap(err, errMsg)
	}
	if len(gotManifests) == 0 {
		logrus.Info("no manifests to get")
		return nil, nil
	}
	var stored []StoredManifest
	for _, manifestBytes := range gotManifests {
		var nextManifest StoredManifest
		if err = json.Unmarshal(manifestBytes, &nextManifest); err == nil {
			stored = append(stored, nextManifest)
		}
	}
	return stored, nil
}

func (b BoltManifestStorage) DeleteManifest(id string) error {
	if err := b.db.Delete(manifestNamespace, id); err != nil {
		return util.LoggingErrorMsgf(err, "could not delete manifest: %s", id)
	}
	return nil
}

func (b BoltManifestStorage) StoreApplication(application StoredApplication) error {
	id := application.Application.ID
	if id == "" {
		return util.LoggingNewError("could not store application without an ID")
	}
	applicationBytes, err := json.Marshal(application)
	if err != nil {
		return util.LoggingErrorMsgf(err, "could not store application: %s", id)
	}
	return b.db.Write(applicationNamespace, id, applicationBytes)
}

func (b BoltManifestStorage) GetApplication(id string) (*StoredApplication, error) {
	applicationBytes, err := b.db.Read(applicationNamespace, id)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get application: %s", id)
	}
	if len(applicationBytes) == 0 {
		return nil, util.LoggingNewErrorf("could not get application from storage; application not found with id: %s", id)
	}
	var stored StoredApplication
	if err = json.Unmarshal(applicationBytes, &stored); err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not unmarshal stored application: %s", id)
	}
	return &stored, nil
}

// GetApplications attempts to get all stored applications. It will return those it can even if it has trouble with some.
func (b BoltManifestStorage) GetApplications() ([]StoredApplication, error) {
	gotApplications, err := b.db.ReadAll(applicationNamespace)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not get all applications")
	}
	if len(gotApplications) == 0 {
		logrus.Info("no applications to get")
		return nil, nil
	}
	var stored []StoredApplication
	for appKey, applicationBytes := range gotApplications {
		var nextApplication StoredApplication
		if err = json.Unmarshal(applicationBytes, &nextApplication); err == nil {
			stored = append(stored, nextApplication)
		} else {
			logrus.WithError(err).Errorf("could not unmarshal stored application: %s", appKey)
		}
	}
	return stored, nil
}

func (b BoltManifestStorage) DeleteApplication(id string) error {
	if err := b.db.Delete(applicationNamespace, id); err != nil {
		return util.LoggingErrorMsgf(err, "could not delete application: %s", id)
	}
	return nil
}

func (b BoltManifestStorage) StoreResponse(response StoredResponse) error {
	id := response.Response.ID
	if id == "" {
		return util.LoggingNewError("could not store response without an ID")
	}
	responseBytes, err := json.Marshal(response)
	if err != nil {
		return util.LoggingErrorMsgf(err, "could not store response: %s", id)
	}
	return b.db.Write(responseNamespace, id, responseBytes)
}

func (b BoltManifestStorage) GetResponse(id string) (*StoredResponse, error) {
	responseBytes, err := b.db.Read(responseNamespace, id)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get response: %s", id)
	}
	if len(responseBytes) == 0 {
		return nil, util.LoggingErrorMsgf(err, "response not found with id: %s", id)
	}
	var stored StoredResponse
	if err = json.Unmarshal(responseBytes, &stored); err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not unmarshal stored response: %s", id)
	}
	return &stored, nil
}

// GetResponses attempts to get all stored responses. It will return those it can even if it has trouble with some.
func (b BoltManifestStorage) GetResponses() ([]StoredResponse, error) {
	gotResponses, err := b.db.ReadAll(responseNamespace)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not get all responses")
	}
	if len(gotResponses) == 0 {
		logrus.Info("no responses to get")
		return nil, nil
	}
	var stored []StoredResponse
	for responseKey, responseBytes := range gotResponses {
		var nextResponse StoredResponse
		if err = json.Unmarshal(responseBytes, &nextResponse); err == nil {
			stored = append(stored, nextResponse)
		} else {
			logrus.WithError(err).Errorf("could not unmarshal stored response: %s", responseKey)
		}
	}
	return stored, nil
}

func (b BoltManifestStorage) DeleteResponse(id string) error {
	if err := b.db.Delete(responseNamespace, id); err != nil {
		return util.LoggingErrorMsgf(err, "could not delete response: %s", id)
	}
	return nil
}
