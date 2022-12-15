package did

import (
	"fmt"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
)

func newWebDIDHandler(s *Storage, ks *keystore.Service) MethodHandler {
	return &webDIDHandler{storage: s, keyStore: ks}
}

type webDIDHandler struct {
	storage  *Storage
	keyStore *keystore.Service
}

func (h *webDIDHandler) CreateDID(request CreateDIDRequest) (*CreateDIDResponse, error) {
	logrus.Debugf("creating DID: %+v", request)

	if request.DIDWebID == "" {
		return nil, errors.New("url is empty, cannot create did:web")
	}

	didWeb := did.DIDWeb(request.DIDWebID)

	if !didWeb.IsValid() {
		return nil, fmt.Errorf("did:web is not valid, could not resolve did:web DID: %s", didWeb)
	}

	pubKey, privKey, err := crypto.GenerateKeyByKeyType(request.KeyType)
	if err != nil {
		return nil, errors.Wrap(err, "could not generate key for did:web")
	}

	pubKeyBytes, err := crypto.PubKeyToBytes(pubKey)
	if err != nil {
		return nil, errors.Wrap(err, "could not convert public key to byte")
	}

	doc, err := didWeb.CreateDoc(request.KeyType, pubKeyBytes)
	if err != nil {
		return nil, errors.Wrap(err, "could not create did:web doc")
	}

	// store metadata in DID storage
	id := didWeb.String()
	storedDID := StoredDID{
		ID:  id,
		DID: *doc,
	}
	if err = h.storage.StoreDID(storedDID); err != nil {
		return nil, errors.Wrap(err, "could not store did:web value")
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

	if err = h.keyStore.StoreKey(keyStoreRequest); err != nil {
		return nil, errors.Wrap(err, "could not store did:key private key")
	}

	return &CreateDIDResponse{
		DID:              storedDID.DID,
		PrivateKeyBase58: privKeyBase58,
		KeyType:          request.KeyType,
	}, nil
}

func (h *webDIDHandler) GetDID(request GetDIDRequest) (*GetDIDResponse, error) {

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

func (h *webDIDHandler) GetDIDs(method did.Method) (*GetDIDsResponse, error) {

	logrus.Debugf("getting DIDs for method: %s", method)

	gotDIDs, err := h.storage.GetDIDs(string(method))
	if err != nil {
		return nil, fmt.Errorf("error getting DIDs for method: %s", method)
	}
	dids := make([]did.DIDDocument, 0, len(gotDIDs))
	for _, gotDID := range gotDIDs {
		dids = append(dids, gotDID.DID)
	}
	return &GetDIDsResponse{DIDs: dids}, nil
}
