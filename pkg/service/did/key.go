package did

import (
	"encoding/json"
	"fmt"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"github.com/tbd54566975/ssi-service/pkg/service/did/storage"
)

func newKeyDIDHandler(s storage.Storage) (MethodHandler, error) {
	return &keyDIDHandler{storage: s}, nil
}

type keyDIDHandler struct {
	storage storage.Storage
}

func (h *keyDIDHandler) CreateDID(request CreateDIDRequest) (*CreateDIDResponse, error) {
	// create the Author
	privKey, doc, err := did.GenerateDIDKey(request.KeyType)
	if err != nil {
		return nil, errors.Wrap(err, "could not create did:key")
	}
	privKeyBase58, err := privateKeyToBase58(privKey)
	if err != nil {
		return nil, errors.Wrap(err, "could not encode private key as base58")
	}

	// expand it to the full doc for storage
	expanded, err := doc.Expand()
	if err != nil {
		return nil, errors.Wrap(err, "error generating did:key document")
	}

	// store it
	storedDID := storage.StoredDID{
		DID:              *expanded,
		PrivateKeyBase58: privKeyBase58,
	}
	if err := h.storage.StoreDID(storedDID); err != nil {
		return nil, errors.Wrap(err, "could not store did:key value")
	}

	return &CreateDIDResponse{
		DID:        storedDID.DID,
		PrivateKey: storedDID.PrivateKeyBase58,
	}, nil
}

func (h *keyDIDHandler) GetDID(request GetDIDRequest) (*GetDIDResponse, error) {
	id := request.ID
	gotDID, err := h.storage.GetDID(id)
	if err != nil {
		return nil, fmt.Errorf("error getting Author: %s", id)
	}
	if gotDID == nil {
		return nil, fmt.Errorf("Author with id<%s> could not be found", id)
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
