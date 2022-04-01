package did

import (
	"encoding/json"
	"fmt"
	"github.com/TBD54566975/did-sdk/did"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	did2 "github.com/tbd54566975/vc-service/pkg/services/did"
)

func NewKeyDIDHandler(s Storage) (did2.ServiceHandler, error) {
	return &keyDIDHandler{storage: s}, nil
}

type keyDIDHandler struct {
	storage Storage
}

func (h *keyDIDHandler) CreateDID(request did2.CreateDIDRequest) (*did2.CreateDIDResponse, error) {
	// create the DID
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
	storedDID := StoredDID{
		DID:              *expanded,
		PrivateKeyBase58: privKeyBase58,
	}
	if err := h.storage.StoreDID(storedDID); err != nil {
		return nil, errors.Wrap(err, "could not store did:key value")
	}

	return &did2.CreateDIDResponse{
		DID:        storedDID.DID,
		PrivateKey: storedDID.PrivateKeyBase58,
	}, nil
}

func (h *keyDIDHandler) GetDID(id string) (*did2.GetDIDResponse, error) {
	gotDID, err := h.storage.GetDID(id)
	if err != nil {
		return nil, fmt.Errorf("error getting DID: %s", id)
	}
	if gotDID == nil {
		return nil, fmt.Errorf("DID with id<%s> could not be found", id)
	}
	return &did2.GetDIDResponse{
		DID: gotDID.DID,
	}, nil
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
