package did

import (
	"fmt"

	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/goccy/go-json"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/pkg/service/did/storage"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
)

func newKeyDIDHandler(s storage.Storage, ks *keystore.Service) (MethodHandler, error) {
	return &keyDIDHandler{storage: s, keyStore: ks}, nil
}

type keyDIDHandler struct {
	storage  storage.Storage
	keyStore *keystore.Service
}

func (h *keyDIDHandler) CreateDID(request CreateDIDRequest) (*CreateDIDResponse, error) {

	logrus.Debugf("creating DID: %+v", request)

	// create the DID
	privKey, doc, err := did.GenerateDIDKey(request.KeyType)
	if err != nil {
		return nil, errors.Wrap(err, "could not create did:key")
	}

	// expand it to the full doc for storage
	expanded, err := doc.Expand()
	if err != nil {
		return nil, errors.Wrap(err, "error generating did:key document")
	}

	// store metadata in DID storage
	id := doc.ToString()
	storedDID := storage.StoredDID{
		ID:  id,
		DID: *expanded,
	}
	if err := h.storage.StoreDID(storedDID); err != nil {
		return nil, errors.Wrap(err, "could not store did:key value")
	}

	// convert to a serialized format for return to the client
	privKeyBase58, err := privateKeyToBase58(privKey)
	if err != nil {
		return nil, errors.Wrap(err, "could not encode private key as base58")
	}

	// store private key in key storage
	keyStoreRequest := keystore.StoreKeyRequest{
		ID:         id,
		Type:       request.KeyType,
		Controller: id,
		Key:        privKey,
	}

	if err := h.keyStore.StoreKey(keyStoreRequest); err != nil {
		return nil, errors.Wrap(err, "could not store did:key private key")
	}

	return &CreateDIDResponse{
		DID:        storedDID.DID,
		PrivateKey: privKeyBase58,
	}, nil
}

func (h *keyDIDHandler) GetDID(request GetDIDRequest) (*GetDIDResponse, error) {

	logrus.Debugf("getting DID: %+v", request)

	id := request.ID
	gotDID, err := h.storage.GetDID(id)
	if err != nil {
		return nil, fmt.Errorf("error getting DID: %s", id)
	}
	if gotDID == nil {
		return nil, fmt.Errorf("did with id<%s> could not be found", id)
	}
	return &GetDIDResponse{DID: gotDID.DID}, nil
}

func privateKeyToBase58(privKey interface{}) (string, error) {
	if haveBytes, ok := privKey.([]byte); ok {
		return base58.Encode(haveBytes), nil
	}
	gotBytes, err := json.Marshal(privKey)
	if err != nil {
		return "", errors.Wrap(err, "could not marshal private key")
	}
	return base58.Encode(gotBytes), nil
}
