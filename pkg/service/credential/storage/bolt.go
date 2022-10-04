package storage

import (
	"fmt"
	"strings"

	"github.com/TBD54566975/ssi-sdk/credential/signing"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

const (
	namespace                = "credential"
	credentialNotFoundErrMsg = "credential not found"
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

func (b BoltCredentialStorage) StoreCredential(request StoreCredentialRequest) error {
	if !request.IsValid() {
		return util.LoggingNewError("store request request is not valid")
	}

	// transform the credential into its denormalized form for storage
	storedCredential, err := buildStoredCredential(request)
	if err != nil {
		return errors.Wrap(err, "could not build stored credential")
	}

	storedCredBytes, err := json.Marshal(storedCredential)
	if err != nil {
		errMsg := fmt.Sprintf("could not store request: %s", storedCredential.CredentialID)
		return util.LoggingErrorMsg(err, errMsg)
	}
	// TODO(gabe) conflict checking?
	return b.db.Write(namespace, storedCredential.ID, storedCredBytes)
}

// buildStoredCredential generically parses a store credential request and returns the object to be stored
func buildStoredCredential(request StoreCredentialRequest) (*StoredCredential, error) {
	// assume we have a Data Integrity credential
	cred := request.Credential
	if request.HasJWTCredential() {
		parsedCred, err := signing.ParseVerifiableCredentialFromJWT(*request.CredentialJWT)
		if err != nil {
			return nil, errors.Wrap(err, "could not parse credential from jwt")
		}

		// if we have a JWT credential, update the reference
		cred = parsedCred
	}

	credID := cred.ID
	// Note: we assume the issuer is always a string for now
	issuer := cred.Issuer.(string)
	subject := cred.CredentialSubject.GetID()

	// schema is not a required field, so we must do this check
	schema := ""
	if cred.CredentialSchema != nil {
		schema = cred.CredentialSchema.ID
	}
	return &StoredCredential{
		ID:            createPrefixKey(credID, issuer, subject, schema),
		CredentialID:  credID,
		Credential:    cred,
		CredentialJWT: request.CredentialJWT,
		Issuer:        issuer,
		Subject:       subject,
		Schema:        schema,
		IssuanceDate:  cred.IssuanceDate,
	}, nil
}

func (b BoltCredentialStorage) GetCredential(id string) (*StoredCredential, error) {
	prefixValues, err := b.db.ReadPrefix(namespace, id)
	if err != nil {
		errMsg := fmt.Sprintf("could not get credential from storage: %s", id)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	if len(prefixValues) > 1 {
		err := fmt.Errorf("multiple prefix values matched credential id: %s", id)
		return nil, util.LoggingErrorMsg(err, "could not get credential from storage")
	}

	// since we know the map now only has a single value, we break after the first element
	var credBytes []byte
	for _, v := range prefixValues {
		credBytes = v
		break
	}
	if len(credBytes) == 0 {
		err := fmt.Errorf("%s with id: %s", credentialNotFoundErrMsg, id)
		return nil, util.LoggingErrorMsg(err, "could not get credential from storage")
	}

	var stored StoredCredential
	if err := json.Unmarshal(credBytes, &stored); err != nil {
		errMsg := fmt.Sprintf("could not unmarshal stored credential: %s", id)
		return nil, util.LoggingErrorMsg(err, errMsg)
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
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	// see if the prefix keys contains the issuer value
	var issuerKeys []string
	for _, k := range keys {
		if strings.Contains(k, issuer) {
			issuerKeys = append(issuerKeys, k)
		}
	}
	if len(issuerKeys) == 0 {
		logrus.Warnf("no credentials found for issuer: %s", util.SanitizeLog(issuer))
		return nil, nil
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
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	// see if the prefix keys contains the subject value
	var subjectKeys []string
	for _, k := range keys {
		if strings.Contains(k, subject) {
			subjectKeys = append(subjectKeys, k)
		}
	}
	if len(subjectKeys) == 0 {
		logrus.Warnf("no credentials found for subject: %s", util.SanitizeLog(subject))
		return nil, nil
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
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	// see if the prefix keys contains the schema value
	query := "sc:" + schema
	var schemaKeys []string
	for _, k := range keys {
		if strings.HasSuffix(k, query) {
			schemaKeys = append(schemaKeys, k)
		}
	}
	if len(schemaKeys) == 0 {
		logrus.Warnf("no credentials found for schema: %s", util.SanitizeLog(schema))
		return nil, nil
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
	credDoesNotExistMsg := fmt.Sprintf("credential does not exist, cannot delete: %s", id)

	// first get the credential to regenerate the prefix key
	gotCred, err := b.GetCredential(id)
	if err != nil {
		// no error on deletion for a non-existent credential
		if strings.Contains(err.Error(), credentialNotFoundErrMsg) {
			logrus.Warn(credDoesNotExistMsg)
			return nil
		}

		errMsg := fmt.Sprintf("could not get credential<%s> before deletion", id)
		return util.LoggingErrorMsg(err, errMsg)
	}

	// no error on deletion for a non-existent credential
	if gotCred == nil {
		logrus.Warn(credDoesNotExistMsg)
		return nil
	}

	// re-create the prefix key to delete
	prefix := createPrefixKey(id, gotCred.Issuer, gotCred.Subject, gotCred.Schema)
	if err := b.db.Delete(namespace, prefix); err != nil {
		errMsg := fmt.Sprintf("could not delete credential: %s", id)
		return util.LoggingErrorMsg(err, errMsg)
	}
	return nil
}

// unique key for a credential
func createPrefixKey(id, issuer, subject, schema string) string {
	return strings.Join([]string{id, "is:" + issuer, "su:" + subject, "sc:" + schema}, "-")
}
