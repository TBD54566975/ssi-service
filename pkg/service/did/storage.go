package did

import (
	"context"
	"fmt"

	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

const (
	namespace    = "did"
	keyNamespace = "key"
	webNamespace = "web"
)

var (
	didMethodToNamespace = map[string]string{
		"key": storage.MakeNamespace(namespace, keyNamespace),
		"web": storage.MakeNamespace(namespace, webNamespace),
	}
)

type StoredDID struct {
	ID          string       `json:"id"`
	DID         did.Document `json:"did"`
	SoftDeleted bool         `json:"softDeleted"`
}

type Storage struct {
	db storage.ServiceStorage
}

func NewDIDStorage(db storage.ServiceStorage) (*Storage, error) {
	if db == nil {
		return nil, errors.New("bolt db reference is nil")
	}
	return &Storage{db: db}, nil
}

func (ds *Storage) StoreDID(ctx context.Context, did StoredDID) error {
	couldNotStoreDIDErr := fmt.Sprintf("could not store DID: %s", did.ID)
	ns, err := getNamespaceForDID(did.ID)
	if err != nil {
		return util.LoggingErrorMsg(err, couldNotStoreDIDErr)
	}
	didBytes, err := json.Marshal(did)
	if err != nil {
		return util.LoggingErrorMsg(err, couldNotStoreDIDErr)
	}
	return ds.db.Write(ctx, ns, did.ID, didBytes)
}

func (ds *Storage) GetDID(ctx context.Context, id string) (*StoredDID, error) {
	couldNotGetDIDErr := fmt.Sprintf("could not get DID: %s", id)
	ns, err := getNamespaceForDID(id)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, couldNotGetDIDErr)
	}
	docBytes, err := ds.db.Read(ctx, ns, id)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, couldNotGetDIDErr)
	}
	if len(docBytes) == 0 {
		err = fmt.Errorf("did not found: %s", id)
		return nil, util.LoggingErrorMsg(err, couldNotGetDIDErr)
	}
	var stored StoredDID
	if err = json.Unmarshal(docBytes, &stored); err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not ummarshal stored DID: %s", id)
	}
	return &stored, nil
}

// GetDIDs attempts to get all DIDs for a given method. It will return those it can even if it has trouble with some.
func (ds *Storage) GetDIDs(ctx context.Context, method string) ([]StoredDID, error) {
	couldNotGetDIDsErr := fmt.Sprintf("could not get DIDs for method: %s", method)
	ns, err := getNamespaceForMethod(method)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, couldNotGetDIDsErr)
	}
	gotDIDs, err := ds.db.ReadAll(ctx, ns)
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
		if err = json.Unmarshal(didBytes, &nextDID); err == nil {
			stored = append(stored, nextDID)
		}
	}
	return stored, nil
}

func (ds *Storage) DeleteDID(ctx context.Context, id string) error {
	couldNotGetDIDErr := fmt.Sprintf("could not delete DID: %s", id)
	ns, err := getNamespaceForDID(id)
	if err != nil {
		return util.LoggingErrorMsg(err, couldNotGetDIDErr)
	}
	if err = ds.db.Delete(ctx, ns, id); err != nil {
		return util.LoggingErrorMsgf(err, "could not delete DID: %s", id)
	}
	return nil
}

func getNamespaceForDID(id string) (string, error) {
	method, err := util.GetMethodForDID(id)
	if err != nil {
		return "", err
	}
	ns, err := getNamespaceForMethod(method)
	if err != nil {
		return "", err
	}
	return ns, nil
}

func getNamespaceForMethod(method string) (string, error) {
	ns, ok := didMethodToNamespace[method]
	if !ok {
		return "", fmt.Errorf("no namespace found for DID method: %s", method)
	}
	return ns, nil
}
