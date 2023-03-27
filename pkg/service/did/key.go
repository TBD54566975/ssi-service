package did

import (
	"context"
	"fmt"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
)

func NewKeyDIDHandler(s *Storage, ks *keystore.Service) MethodHandler {
	return &keyDIDHandler{storage: s, keyStore: ks}
}

type keyDIDHandler struct {
	storage  *Storage
	keyStore *keystore.Service
}

func (h *keyDIDHandler) CreateDID(ctx context.Context, request CreateDIDRequest) (*CreateDIDResponse, error) {

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
	id := doc.String()
	storedDID := StoredDID{
		ID:          id,
		DID:         *expanded,
		SoftDeleted: false,
	}
	if err = h.storage.StoreDID(ctx, storedDID); err != nil {
		return nil, errors.Wrap(err, "could not store did:key value")
	}

	// convert to a serialized format for return to the client
	privKeyBytes, err := crypto.PrivKeyToBytes(privKey)
	if err != nil {
		return nil, errors.Wrap(err, "could not encode private key as base58")
	}
	privKeyBase58 := base58.Encode(privKeyBytes)

	// store private key in key storage
	keyStoreRequest := keystore.StoreKeyRequest{
		ID:               id,
		Type:             request.KeyType,
		Controller:       id,
		PrivateKeyBase58: privKeyBase58,
	}

	if err = h.keyStore.StoreKey(ctx, keyStoreRequest); err != nil {
		return nil, errors.Wrap(err, "could not store did:key private key")
	}

	return &CreateDIDResponse{
		DID:              storedDID.DID,
		PrivateKeyBase58: privKeyBase58,
		KeyType:          request.KeyType,
	}, nil
}

func (h *keyDIDHandler) GetDID(ctx context.Context, request GetDIDRequest) (*GetDIDResponse, error) {

	logrus.Debugf("getting DID: %+v", request)

	id := request.ID
	gotDID, err := h.storage.GetDID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("error getting DID: %s", id)
	}
	if gotDID == nil {
		return nil, fmt.Errorf("did with id<%s> could not be found", id)
	}
	return &GetDIDResponse{DID: gotDID.DID}, nil
}

func (h *keyDIDHandler) GetDIDs(ctx context.Context, method did.Method) (*GetDIDsResponse, error) {

	logrus.Debugf("getting DIDs for method: %s", method)

	gotDIDs, err := h.storage.GetDIDs(ctx, string(method))
	if err != nil {
		return nil, fmt.Errorf("error getting DIDs for method: %s", method)
	}
	dids := make([]did.Document, 0, len(gotDIDs))
	for _, gotDID := range gotDIDs {
		if !gotDID.SoftDeleted {
			dids = append(dids, gotDID.DID)
		}
	}
	return &GetDIDsResponse{DIDs: dids}, nil
}

func (h *keyDIDHandler) SoftDeleteDID(ctx context.Context, request DeleteDIDRequest) error {
	logrus.Debugf("soft deleting DID: %+v", request)

	id := request.ID
	gotStoredDID, err := h.storage.GetDID(ctx, id)
	if err != nil {
		return fmt.Errorf("error getting DID: %s", id)
	}
	if gotStoredDID == nil {
		return fmt.Errorf("did with id<%s> could not be found", id)
	}

	gotStoredDID.SoftDeleted = true

	return h.storage.StoreDID(ctx, *gotStoredDID)
}
