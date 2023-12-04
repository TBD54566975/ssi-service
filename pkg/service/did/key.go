package did

import (
	"context"
	"fmt"
	"time"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/key"
	"github.com/TBD54566975/ssi-sdk/did/resolution"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tbd54566975/ssi-service/pkg/service/common"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
)

func NewKeyHandler(s *Storage, ks *keystore.Service) (MethodHandler, error) {
	if s == nil {
		return nil, errors.New("storage cannot be empty")
	}
	if ks == nil {
		return nil, errors.New("keystore cannot be empty")
	}
	return &keyHandler{method: did.KeyMethod, storage: s, keyStore: ks}, nil
}

type keyHandler struct {
	method   did.Method
	storage  *Storage
	keyStore *keystore.Service
}

func (h *keyHandler) Resolve(ctx context.Context, id string) (*resolution.Result, error) {
	return resolve(ctx, id, h.storage)
}

var _ MethodHandler = (*keyHandler)(nil)

func (h *keyHandler) GetMethod() did.Method {
	return h.method
}

func (h *keyHandler) CreateDID(ctx context.Context, request CreateDIDRequest) (*CreateDIDResponse, error) {
	logrus.Debugf("creating DID: %+v", request)

	// create the DID
	privKey, doc, err := key.GenerateDIDKey(request.KeyType)
	if err != nil {
		return nil, errors.Wrap(err, "creating did:key")
	}

	// expand it to the full docs for storage
	expanded, err := doc.Expand()
	if err != nil {
		return nil, errors.Wrap(err, "generating did:key document")
	}

	// store metadata in DID storage
	id := doc.String()
	nowUTC := time.Now().UTC()
	storedDID := DefaultStoredDID{
		CreatedAt:   nowUTC.Format(time.RFC3339),
		UpdatedAt:   nowUTC.Format(time.RFC3339),
		ID:          id,
		DID:         *expanded,
		SoftDeleted: false,
	}
	if err = h.storage.StoreDID(ctx, storedDID); err != nil {
		return nil, errors.Wrap(err, "storing did:key value")
	}

	// convert to a serialized format for return to the client
	privKeyBytes, err := crypto.PrivKeyToBytes(privKey)
	if err != nil {
		return nil, errors.Wrap(err, "encoding private key as base58")
	}
	privKeyBase58 := base58.Encode(privKeyBytes)

	// store private key in key storage
	keyStoreRequest := keystore.StoreKeyRequest{
		ID:               expanded.VerificationMethod[0].ID,
		Type:             request.KeyType,
		Controller:       id,
		PrivateKeyBase58: privKeyBase58,
	}

	if err = h.keyStore.StoreKey(ctx, keyStoreRequest); err != nil {
		return nil, errors.Wrap(err, "storing did:key private key")
	}
	return &CreateDIDResponse{DID: storedDID.DID}, nil
}

func (h *keyHandler) GetDID(ctx context.Context, request GetDIDRequest) (*GetDIDResponse, error) {
	logrus.Debugf("getting DID: %+v", request)

	id := request.ID
	gotDID, err := h.storage.GetDIDDefault(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("error getting DID: %s", id)
	}
	if gotDID == nil {
		return nil, fmt.Errorf("did with id<%s> could not be found", id)
	}
	return &GetDIDResponse{DID: gotDID.DID}, nil
}

func (h *keyHandler) ListDIDs(ctx context.Context, page *common.Page) (*ListDIDsResponse, error) {
	gotDIDs, err := h.storage.ListDIDsPage(ctx, did.KeyMethod.String(), page, new(DefaultStoredDID))
	if err != nil {
		return nil, errors.Wrap(err, "listing did:web DIDs page")
	}
	dids := make([]did.Document, 0, len(gotDIDs.DIDs))
	for _, gotDID := range gotDIDs.DIDs {
		if !gotDID.IsSoftDeleted() {
			dids = append(dids, gotDID.GetDocument())
		}
	}
	return &ListDIDsResponse{
		DIDs:          dids,
		NextPageToken: gotDIDs.NextPageToken,
	}, nil
}

// ListDeletedDIDs returns only DIDs we have in storage for Key with SoftDeleted flag set to true
func (h *keyHandler) ListDeletedDIDs(ctx context.Context) (*ListDIDsResponse, error) {
	logrus.Debug("listing did:key DIDs")

	gotDIDs, err := h.storage.ListDIDsDefault(ctx, did.KeyMethod.String())
	if err != nil {
		return nil, fmt.Errorf("error getting did:key DIDs")
	}
	dids := make([]did.Document, 0, len(gotDIDs))
	for _, gotDID := range gotDIDs {
		if gotDID.IsSoftDeleted() {
			dids = append(dids, gotDID.GetDocument())
		}
	}
	return &ListDIDsResponse{DIDs: dids}, nil
}

func (h *keyHandler) DeleteDID(ctx context.Context, request DeleteDIDRequest) (*DeleteDIDResponse, error) {
	logrus.Debugf("soft deleting DID: %+v", request)

	id := request.ID
	gotStoredDID, err := h.storage.GetDIDDefault(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("error getting DID: %s", id)
	}
	if gotStoredDID == nil {
		return nil, fmt.Errorf("did with id<%s> could not be found", id)
	}

	nowUTC := time.Now().UTC()
	gotStoredDID.SoftDeleted = true
	gotStoredDID.UpdatedAt = nowUTC.Format(time.RFC3339)

	return nil, h.storage.StoreDID(ctx, *gotStoredDID)
}
