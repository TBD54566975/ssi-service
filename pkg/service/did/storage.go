package did

import (
	"context"
	"fmt"
	"reflect"

	"github.com/TBD54566975/ssi-sdk/did"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
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
	ionNamespace = "ion"
)

var (
	didMethodToNamespace = map[string]string{
		keyNamespace: storage.MakeNamespace(namespace, keyNamespace),
		webNamespace: storage.MakeNamespace(namespace, webNamespace),
		ionNamespace: storage.MakeNamespace(namespace, ionNamespace),
	}
)

// StoredDID is a DID that has been stored in the database. It is an interface to allow
// for different implementations of DID storage based on the DID method.
type StoredDID interface {
	GetID() string
	GetDocument() did.Document
	IsSoftDeleted() bool
}

// DefaultStoredDID is the default implementation of StoredDID if no other implementation requirements are needed.
type DefaultStoredDID struct {
	ID          string       `json:"id"`
	DID         did.Document `json:"did"`
	SoftDeleted bool         `json:"softDeleted"`
}

func (d DefaultStoredDID) GetID() string {
	return d.ID
}

func (d DefaultStoredDID) GetDocument() did.Document {
	return d.DID
}

func (d DefaultStoredDID) IsSoftDeleted() bool {
	return d.SoftDeleted
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
	couldNotStoreDIDErr := fmt.Sprintf("could not store DID: %s", did.GetID())
	ns, err := getNamespaceForDID(did.GetID())
	if err != nil {
		return sdkutil.LoggingErrorMsg(err, couldNotStoreDIDErr)
	}
	didBytes, err := json.Marshal(did)
	if err != nil {
		return sdkutil.LoggingErrorMsg(err, couldNotStoreDIDErr)
	}
	return ds.db.Write(ctx, ns, did.GetID(), didBytes)
}

// GetDID attempts to get a DID from the database. It will return an error if it cannot.
// The out parameter must be a pointer to a struct that implements the StoredDID interface.
func (ds *Storage) GetDID(ctx context.Context, id string, out StoredDID) error {
	if err := validateOut(out); err != nil {
		return errors.Wrap(err, "validating out")
	}
	couldNotGetDIDErr := fmt.Sprintf("could not get DID: %s", id)
	ns, err := getNamespaceForDID(id)
	if err != nil {
		return sdkutil.LoggingErrorMsg(err, couldNotGetDIDErr)
	}
	docBytes, err := ds.db.Read(ctx, ns, id)
	if err != nil {
		return sdkutil.LoggingErrorMsg(err, couldNotGetDIDErr)
	}
	if len(docBytes) == 0 {
		err = fmt.Errorf("did not found: %s", id)
		return sdkutil.LoggingErrorMsg(err, couldNotGetDIDErr)
	}
	if err = json.Unmarshal(docBytes, out); err != nil {
		return sdkutil.LoggingErrorMsgf(err, "could not ummarshal stored DID: %s", id)
	}
	return nil
}

// GetDIDDefault is a convenience method for getting a DID that is stored as a DefaultStoredDID.
func (ds *Storage) GetDIDDefault(ctx context.Context, id string) (*DefaultStoredDID, error) {
	outType := new(DefaultStoredDID)
	if err := ds.GetDID(ctx, id, outType); err != nil {
		return nil, err
	}
	return outType, nil
}

// GetDIDs attempts to get all DIDs for a given method. It will return those it can even if it has trouble with some.
// The out parameter must be a pointer to a struct for a type that implement the StoredDID interface.
// The result is a slice of the type of the out parameter (an array of pointers to the type of the out parameter).)
func (ds *Storage) GetDIDs(ctx context.Context, method string, outType StoredDID) ([]StoredDID, error) {
	if err := validateOut(outType); err != nil {
		return nil, errors.Wrap(err, "validating the out type")
	}
	couldNotGetDIDsErr := fmt.Sprintf("could not get DIDs for method: %s", method)
	ns, err := getNamespaceForMethod(method)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, couldNotGetDIDsErr)
	}
	gotDIDs, err := ds.db.ReadAll(ctx, ns)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, couldNotGetDIDsErr)
	}
	if len(gotDIDs) == 0 {
		logrus.Infof("no DIDs found for method: %s", method)
		return nil, nil
	}

	out := make([]StoredDID, 0, len(gotDIDs))
	for _, didBytes := range gotDIDs {
		nextDID := reflect.New(reflect.TypeOf(outType).Elem()).Interface()
		if err = json.Unmarshal(didBytes, &nextDID); err == nil {
			out = append(out, nextDID.(StoredDID))
		}
	}
	return out, nil
}

func (ds *Storage) GetDIDsDefault(ctx context.Context, method string) ([]DefaultStoredDID, error) {
	gotDIDs, err := ds.GetDIDs(ctx, method, new(DefaultStoredDID))
	if err != nil {
		return nil, err
	}
	typedDIDs := make([]DefaultStoredDID, len(gotDIDs))
	for i, gotDID := range gotDIDs {
		typedDIDs[i] = *gotDID.(*DefaultStoredDID)
	}
	return typedDIDs, nil
}

func (ds *Storage) DeleteDID(ctx context.Context, id string) error {
	couldNotGetDIDErr := fmt.Sprintf("could not delete DID: %s", id)
	ns, err := getNamespaceForDID(id)
	if err != nil {
		return sdkutil.LoggingErrorMsg(err, couldNotGetDIDErr)
	}
	if err = ds.db.Delete(ctx, ns, id); err != nil {
		return sdkutil.LoggingErrorMsgf(err, "could not delete DID: %s", id)
	}
	return nil
}

func validateOut(out StoredDID) error {
	if out == nil {
		return errors.New("cannot be nil")
	}
	// make sure out is a ptr to a struct
	outVal := reflect.ValueOf(out)
	if outVal.Kind() != reflect.Ptr {
		return fmt.Errorf("must be ptr to a struct; is %T", out)
	}

	// dereference the pointer
	outValDeref := outVal.Elem()
	if outValDeref.Kind() != reflect.Struct {
		return fmt.Errorf("must be ptr to a struct; is %T", out)
	}
	return nil
}

func getNamespaceForDID(id string) (string, error) {
	method, err := util.GetMethodForDID(id)
	if err != nil {
		return "", err
	}
	ns, err := getNamespaceForMethod(method.String())
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
