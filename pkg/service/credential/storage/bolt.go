package storage

import (
	"fmt"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"strings"
)

const (
	namespace = "credential"
)

type BoltCredentialStorage struct {
	db *storage.BoltDB
}

func NewBoltCredentialStorage(db *storage.BoltDB) (*BoltCredentialStorage, error) {
	if db == nil {
		return nil, errors.New("bolt db reference is nil")
	}
	return &BoltCredentialStorage{db: db}, nil
}

func (b BoltCredentialStorage) StoreCredential(credential StoredCredential) error {
	id := credential.Credential.ID
	if id == "" {
		err := errors.New("could not store credential without an ID")
		logrus.WithError(err).Error()
		return err
	}

	// create and set prefix key for the credential
	credential.ID = createPrefixKey(id, credential.Issuer, credential.Subject, credential.Schema)

	credBytes, err := json.Marshal(credential)
	if err != nil {
		errMsg := fmt.Sprintf("could not store credential: %s", id)
		logrus.WithError(err).Error(errMsg)
		return errors.Wrapf(err, errMsg)
	}
	return b.db.Write(namespace, id, credBytes)
}

func (b BoltCredentialStorage) GetCredential(id string) (*StoredCredential, error) {
	credBytes, err := b.db.Read(namespace, id)
	if err != nil {
		errMsg := fmt.Sprintf("could not get credential: %s", id)
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrapf(err, errMsg)
	}
	if len(credBytes) == 0 {
		err := fmt.Errorf("credential not found with id: %s", id)
		logrus.WithError(err).Error("could not get credential from storage")
		return nil, err
	}
	var stored StoredCredential
	if err := json.Unmarshal(credBytes, &stored); err != nil {
		errMsg := fmt.Sprintf("could not unmarshal stored credential: %s", id)
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrapf(err, errMsg)
	}
	return &stored, nil
}

// Note: this is a lazy  implementation. Optimizations are to be had by adjusting prefix
// queries, and nested buckets. It is not intended that bolt is run in production, or at any scale,
// so this is not much of a concern.

func (b BoltCredentialStorage) GetCredentialsByIssuer(issuer string) ([]StoredCredential, error) {
	//TODO implement me
	panic("implement me")
}

func (b BoltCredentialStorage) GetCredentialsBySubject(subject string) ([]StoredCredential, error) {
	//TODO implement me
	panic("implement me")
}

func (b BoltCredentialStorage) GetCredentialsBySchema(schema string) ([]StoredCredential, error) {
	//TODO implement me
	panic("implement me")
}

func (b BoltCredentialStorage) DeleteCredential(id string) error {
	if err := b.db.Delete(namespace, id); err != nil {
		errMsg := fmt.Sprintf("could not delete credential: %s", id)
		logrus.WithError(err).Error(errMsg)
		return errors.Wrapf(err, errMsg)
	}
	return nil
}

// unique key for a credential
func createPrefixKey(id, issuer, subject, schema string) string {
	return strings.Join([]string{"id:" + id, "is:" + issuer, "su:" + subject, "sc:" + schema}, "-")
}
