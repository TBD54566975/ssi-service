package storage

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"github.com/tbd54566975/vc-service/pkg/storage"
	"strings"
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
	couldNotStoreDIDErr := fmt.Sprintf("could not store DID: %s", did.DID.ID)
	namespace, err := getNamespaceForDID(did.DID.ID)
	if err != nil {
		return errors.Wrap(err, couldNotStoreDIDErr)
	}
	didBytes, err := json.Marshal(did)
	if err != nil {
		return errors.Wrap(err, couldNotStoreDIDErr)
	}
	return b.db.Write(namespace, did.DID.ID, didBytes)
}

func (b BoltDIDStorage) GetDID(id string) (*StoredDID, error) {
	couldNotGetDIDErr := fmt.Sprintf("could not get DID: %s", id)
	namespace, err := getNamespaceForDID(id)
	if err != nil {
		return nil, errors.Wrap(err, couldNotGetDIDErr)
	}
	docBytes, err := b.db.Read(namespace, id)
	if err != nil {
		return nil, errors.Wrap(err, couldNotGetDIDErr)
	}
	if len(docBytes) == 0 {
		return nil, fmt.Errorf("DID not found: %s", id)
	}
	var stored StoredDID
	if err := json.Unmarshal(docBytes, &stored); err != nil {
		return nil, errors.Wrapf(err, "could not ummarshal stored DID: %s", id)
	}
	return &stored, nil
}

// GetDIDs attempts to get all DIDs for a given method. It will return those it can, even if it has trouble with some.
func (b BoltDIDStorage) GetDIDs(method string) ([]StoredDID, error) {
	couldNotGetDIDsErr := fmt.Sprintf("could not get DIDs for method: %s", method)
	namespace, err := getNamespaceForMethod(method)
	if err != nil {
		return nil, errors.Wrap(err, couldNotGetDIDsErr)
	}
	gotDIDs, err := b.db.ReadAll(namespace)
	if err != nil {
		return nil, errors.Wrap(err, couldNotGetDIDsErr)
	}
	if len(gotDIDs) == 0 {
		return nil, fmt.Errorf("no DIDs found for method: %s", method)
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
		return errors.Wrap(err, couldNotGetDIDErr)
	}
	return b.db.Delete(namespace, id)
}

func getNamespaceForDID(id string) (string, error) {
	method, err := getMethod(id)
	if err != nil {
		return "", err
	}
	namespace, err := getNamespaceForMethod(method)
	if err != nil {
		return "", err
	}
	return namespace, nil
}

// getMethod gets a DID method from a did, the second part of the did (e.g. did:test:abcd, the method is 'test')
func getMethod(did string) (string, error) {
	split := strings.Split(did, ":")
	if len(split) < 3 {
		return "", fmt.Errorf("malformed did: %s", did)
	}
	return split[1], nil
}

func getNamespaceForMethod(method string) (string, error) {
	namespace, ok := didMethodToNamespace[method]
	if !ok {
		return "", fmt.Errorf("no namespace found for DID method: %s", method)
	}
	return namespace, nil
}
