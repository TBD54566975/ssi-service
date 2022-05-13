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
	return b.db.Write(namespace, credential.ID, credBytes)
}

func (b BoltCredentialStorage) GetCredential(id string) (*StoredCredential, error) {
	prefixValues, err := b.db.ReadPrefix(namespace, id)
	if err != nil {
		errMsg := fmt.Sprintf("could not get credential: %s", id)
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrapf(err, errMsg)
	}
	if len(prefixValues) > 0 {
		err := fmt.Errorf("multiple prefix values matched credential id: %s", id)
		logrus.WithError(err).Error("could not get credential")
		return nil, err
	}

	// since we know the map now only has a single value, we break after the first element
	var credBytes []byte
	for _, v := range prefixValues {
		credBytes = v
		break
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

// GetCredentialsByIssuer gets all credentials stored with a prefix key containing the issuer value
// The method is greedy, meaning if multiple values are found...and some fail during processing, we will
// return only the successful values and log an error for the failures.
func (b BoltCredentialStorage) GetCredentialsByIssuer(issuer string) ([]StoredCredential, error) {
	keys, err := b.db.ReadAllKeys(namespace)
	if err != nil {
		errMsg := fmt.Sprintf("could not read credential storage while searching for creds for issuer: %s", issuer)
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrap(err, errMsg)
	}
	// see if the prefix keys contains the issuer value
	var issuerKeys []string
	for _, k := range keys {
		if strings.Contains(k, issuer) {
			issuerKeys = append(issuerKeys, k)
		}
	}
	if len(issuerKeys) == 0 {
		errMsg := fmt.Sprintf("no credentials found for issuer: %s", issuer)
		logrus.Error(errMsg)
		return nil, errors.New(errMsg)
	}

	// now get each credential by key
	var storedCreds []StoredCredential
	for _, key := range issuerKeys {
		credBytes, err := b.db.Read(namespace, key)
		if err != nil {
			logrus.WithError(err).Errorf("could not read credential with key: %s", key)
		} else {
			var cred StoredCredential
			if err := json.Unmarshal(credBytes, &cred); err != nil {
				logrus.WithError(err).Errorf("could not unmarshal credential with key: %s", key)
			}
			storedCreds = append(storedCreds, cred)
		}
	}

	if len(storedCreds) == 0 {
		logrus.Warnf("no credentials able to be retrieved for issuer: %s", issuerKeys)
	}

	return storedCreds, nil
}

// GetCredentialsBySubject gets all credentials stored with a prefix key containing the subject value
// The method is greedy, meaning if multiple values are found...and some fail during processing, we will
// return only the successful values and log an error for the failures.
func (b BoltCredentialStorage) GetCredentialsBySubject(subject string) ([]StoredCredential, error) {
	keys, err := b.db.ReadAllKeys(namespace)
	if err != nil {
		errMsg := fmt.Sprintf("could not read credential storage while searching for creds for subject: %s", subject)
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrap(err, errMsg)
	}

	// see if the prefix keys contains the subject value
	var subjectKeys []string
	for _, k := range keys {
		if strings.Contains(k, subject) {
			subjectKeys = append(subjectKeys, k)
		}
	}
	if len(subjectKeys) == 0 {
		errMsg := fmt.Sprintf("no credentials found for subject: %s", subject)
		logrus.Error(errMsg)
		return nil, errors.New(errMsg)
	}

	// now get each credential by key
	var storedCreds []StoredCredential
	for _, key := range subjectKeys {
		credBytes, err := b.db.Read(namespace, key)
		if err != nil {
			logrus.WithError(err).Errorf("could not read credential with key: %s", key)
		} else {
			var cred StoredCredential
			if err := json.Unmarshal(credBytes, &cred); err != nil {
				logrus.WithError(err).Errorf("could not unmarshal credential with key: %s", key)
			}
			storedCreds = append(storedCreds, cred)
		}
	}

	if len(storedCreds) == 0 {
		logrus.Warnf("no credentials able to be retrieved for subject: %s", subjectKeys)
	}

	return storedCreds, nil
}

// GetCredentialsBySchema gets all credentials stored with a prefix key containing the schema value
// The method is greedy, meaning if multiple values are found...and some fail during processing, we will
// return only the successful values and log an error for the failures.
func (b BoltCredentialStorage) GetCredentialsBySchema(schema string) ([]StoredCredential, error) {
	keys, err := b.db.ReadAllKeys(namespace)
	if err != nil {
		errMsg := fmt.Sprintf("could not read credential storage while searching for creds for schema: %s", schema)
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrap(err, errMsg)
	}

	// see if the prefix keys contains the schema value
	var schemaKeys []string
	for _, k := range keys {
		if strings.Contains(k, schema) {
			schemaKeys = append(schemaKeys, k)
		}
	}
	if len(schemaKeys) == 0 {
		errMsg := fmt.Sprintf("no credentials found for schema: %s", schema)
		logrus.Error(errMsg)
		return nil, errors.New(errMsg)
	}

	// now get each credential by key
	var storedCreds []StoredCredential
	for _, key := range schemaKeys {
		credBytes, err := b.db.Read(namespace, key)
		if err != nil {
			logrus.WithError(err).Errorf("could not read credential with key: %s", key)
		} else {
			var cred StoredCredential
			if err := json.Unmarshal(credBytes, &cred); err != nil {
				logrus.WithError(err).Errorf("could not unmarshal credential with key: %s", key)
			}
			storedCreds = append(storedCreds, cred)
		}
	}

	if len(storedCreds) == 0 {
		logrus.Warnf("no credentials able to be retrieved for schema: %s", schemaKeys)
	}

	return storedCreds, nil
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
