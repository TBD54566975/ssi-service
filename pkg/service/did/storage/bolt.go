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
	namespace    = "did"
	keyNamespace = "key"
)

var (
	didMethodToNamespace = map[string]string{
		"key": storage.MakeNamespace(namespace, keyNamespace),
	}
)

type BoltDIDStorage struct {
	db *storage.BoltDB
}

func NewBoltDIDStorage(db *storage.BoltDB) (*BoltDIDStorage, error) {
	if db == nil {
		return nil, errors.New("bolt db reference is nil")
	}
	return &BoltDIDStorage{db: db}, nil
}

func (b BoltDIDStorage) StoreDID(did StoredDID) error {
	couldNotStoreDIDErr := fmt.Sprintf("could not store DID: %s", did.ID)
	namespace, err := getNamespaceForDID(did.ID)
	if err != nil {
		return util.LoggingErrorMsg(err, couldNotStoreDIDErr)
	}
	didBytes, err := json.Marshal(did)
	if err != nil {
		return util.LoggingErrorMsg(err, couldNotStoreDIDErr)
	}
	return b.db.Write(namespace, did.ID, didBytes)
}

func (b BoltDIDStorage) GetDID(id string) (*StoredDID, error) {
	couldNotGetDIDErr := fmt.Sprintf("could not get DID: %s", id)
	namespace, err := getNamespaceForDID(id)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, couldNotGetDIDErr)
	}
	docBytes, err := b.db.Read(namespace, id)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, couldNotGetDIDErr)
	}
	if len(docBytes) == 0 {
		err := fmt.Errorf("did not found: %s", id)
		return nil, util.LoggingErrorMsg(err, couldNotGetDIDErr)
	}
	var stored StoredDID
	if err := json.Unmarshal(docBytes, &stored); err != nil {
		errMsg := fmt.Sprintf("could not ummarshal stored DID: %s", id)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	return &stored, nil
}

// GetDIDs attempts to get all DIDs for a given method. It will return those it can even if it has trouble with some.
func (b BoltDIDStorage) GetDIDs(method string) ([]StoredDID, error) {
	couldNotGetDIDsErr := fmt.Sprintf("could not get DIDs for method: %s", method)
	namespace, err := getNamespaceForMethod(method)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, couldNotGetDIDsErr)
	}
	gotDIDs, err := b.db.ReadAll(namespace)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, couldNotGetDIDsErr)
	}
	if len(gotDIDs) == 0 {
		logrus.Infof("no DIDs found for method: %s", method)
		return nil, nil
	}
	var stored []StoredDID
	for _, didBytes := range gotDIDs {
		var nextDID StoredDID
		if err := json.Unmarshal(didBytes, &nextDID); err == nil {
			stored = append(stored, nextDID)
		}
	}
	return stored, nil
}

func (b BoltDIDStorage) DeleteDID(id string) error {
	couldNotGetDIDErr := fmt.Sprintf("could not delete DID: %s", id)
	namespace, err := getNamespaceForDID(id)
	if err != nil {
		return util.LoggingErrorMsg(err, couldNotGetDIDErr)
	}
	if err := b.db.Delete(namespace, id); err != nil {
		errMsg := fmt.Sprintf("could not delete DID: %s", id)
		return util.LoggingErrorMsg(err, errMsg)
	}
	return nil
}

func getNamespaceForDID(id string) (string, error) {
	method, err := util.GetMethodForDID(id)
	if err != nil {
		return "", err
	}
	namespace, err := getNamespaceForMethod(method)
	if err != nil {
		return "", err
	}
	return namespace, nil
}

func getNamespaceForMethod(method string) (string, error) {
	namespace, ok := didMethodToNamespace[method]
	if !ok {
		return "", fmt.Errorf("no namespace found for DID method: %s", method)
	}
	return namespace, nil
}
