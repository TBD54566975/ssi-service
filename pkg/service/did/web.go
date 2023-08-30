package did

import (
	"context"
	"fmt"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/web"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tbd54566975/ssi-service/pkg/service/common"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
)

func NewWebHandler(s *Storage, ks *keystore.Service) (MethodHandler, error) {
	if s == nil {
		return nil, errors.New("storage cannot be empty")
	}
	if ks == nil {
		return nil, errors.New("keystore cannot be empty")
	}
	return &webHandler{method: did.WebMethod, storage: s, keyStore: ks}, nil
}

type webHandler struct {
	method   did.Method
	storage  *Storage
	keyStore *keystore.Service
}

var _ MethodHandler = (*webHandler)(nil)

type CreateWebDIDOptions struct {
	// e.g. did:web:example.com
	DIDWebID string `json:"didWebId" validate:"required"`
}

func (c CreateWebDIDOptions) Method() did.Method {
	return did.WebMethod
}

func (h *webHandler) GetMethod() did.Method {
	return h.method
}

func (h *webHandler) CreateDID(ctx context.Context, request CreateDIDRequest) (*CreateDIDResponse, error) {
	logrus.Debugf("creating DID: %+v", request)

	if !crypto.IsSupportedKeyType(request.KeyType) {
		return nil, errors.Errorf("key type <%s> not supported", request.KeyType)
	}
	// process options
	if request.Options == nil {
		return nil, errors.New("options cannot be empty")
	}
	opts, ok := request.Options.(CreateWebDIDOptions)
	if !ok || request.Options.Method() != did.WebMethod {
		return nil, fmt.Errorf("invalid options for method, expected %s, got %s", did.WebMethod, request.Options.Method())
	}
	if err := util.IsValidStruct(opts); err != nil {
		return nil, errors.Wrap(err, "processing options")
	}

	didWeb := web.DIDWeb(opts.DIDWebID)

	err := didWeb.Validate(ctx)
	if err == nil {
		return nil, fmt.Errorf("%s exists externally", didWeb.String())
	}

	exists, err := h.storage.DIDExists(ctx, opts.DIDWebID)
	if err != nil {
		return nil, errors.Wrapf(err, "error getting DID: %s", opts.DIDWebID)
	}

	if exists {
		return nil, fmt.Errorf("did with id<%s> already exists", opts.DIDWebID)
	}

	pubKey, privKey, err := crypto.GenerateKeyByKeyType(request.KeyType)
	if err != nil {
		return nil, errors.Wrap(err, "generating key for did:web")
	}

	pubKeyBytes, err := crypto.PubKeyToBytes(pubKey)
	if err != nil {
		return nil, errors.Wrap(err, "converting public key to byte")
	}

	doc, err := didWeb.CreateDoc(request.KeyType, pubKeyBytes)
	if err != nil {
		return nil, errors.Wrap(err, "creating did:web docs")
	}

	// store metadata in DID storage
	id := didWeb.String()
	storedDID := DefaultStoredDID{
		ID:          id,
		DID:         *doc,
		SoftDeleted: false,
	}
	if err = h.storage.StoreDID(ctx, storedDID); err != nil {
		return nil, errors.Wrap(err, "storing did:web value")
	}

	// convert to a serialized format for return to the client
	privKeyBytes, err := crypto.PrivKeyToBytes(privKey)
	if err != nil {
		return nil, errors.Wrap(err, "encoding private key as base58")
	}
	privKeyBase58 := base58.Encode(privKeyBytes)

	// store private key in key storage
	keyStoreRequest := keystore.StoreKeyRequest{
		ID:               doc.VerificationMethod[0].ID,
		Type:             request.KeyType,
		Controller:       id,
		PrivateKeyBase58: privKeyBase58,
	}

	if err = h.keyStore.StoreKey(ctx, keyStoreRequest); err != nil {
		return nil, errors.Wrap(err, "storing did:web private key")
	}
	return &CreateDIDResponse{DID: storedDID.DID}, nil
}

func (h *webHandler) GetDID(ctx context.Context, request GetDIDRequest) (*GetDIDResponse, error) {
	logrus.Debugf("getting DID: %+v", request)

	id := request.ID
	gotDID, err := h.storage.GetDIDDefault(ctx, id)
	if err != nil {
		return nil, errors.Wrapf(err, "error getting DID: %s", id)
	}
	if gotDID == nil {
		return nil, fmt.Errorf("did with id<%s> could not be found", id)
	}
	return &GetDIDResponse{DID: gotDID.GetDocument()}, nil
}

func (h *webHandler) ListDIDs(ctx context.Context, page *common.Page) (*ListDIDsResponse, error) {
	gotDIDs, err := h.storage.ListDIDsPage(ctx, did.WebMethod.String(), page, new(DefaultStoredDID))
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

func (h *webHandler) ListDeletedDIDs(ctx context.Context) (*ListDIDsResponse, error) {
	logrus.Debug("listing deleted did:web DIDs")

	gotDIDs, err := h.storage.ListDIDsDefault(ctx, did.WebMethod.String())
	if err != nil {
		return nil, errors.Wrap(err, "listing did:web DIDs")
	}
	dids := make([]did.Document, 0, len(gotDIDs))
	for _, gotDID := range gotDIDs {
		if gotDID.IsSoftDeleted() {
			dids = append(dids, gotDID.GetDocument())
		}
	}
	return &ListDIDsResponse{DIDs: dids}, nil
}

func (h *webHandler) SoftDeleteDID(ctx context.Context, request DeleteDIDRequest) error {
	logrus.Debugf("soft deleting DID: %+v", request)

	id := request.ID
	gotStoredDID, err := h.storage.GetDIDDefault(ctx, id)
	if err != nil {
		return errors.Wrapf(err, "getting DID: %s", id)
	}
	if gotStoredDID == nil {
		return fmt.Errorf("did with id<%s> could not be found", id)
	}

	gotStoredDID.SoftDeleted = true

	return h.storage.StoreDID(ctx, *gotStoredDID)
}
