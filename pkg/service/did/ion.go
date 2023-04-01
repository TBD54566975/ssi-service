package did

import (
	"context"
	"fmt"
	"net/http"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/ion"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/google/uuid"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
)

const (
	updateKeySuffix  string = "update"
	recoverKeySuffix string = "recover"
)

func NewIONHandler(baseURL string, s *Storage, ks *keystore.Service) (MethodHandler, error) {
	if baseURL == "" {
		return nil, errors.New("baseURL cannot be empty")
	}
	if s == nil {
		return nil, errors.New("storage cannot be empty")
	}
	if ks == nil {
		return nil, errors.New("keystore cannot be empty")
	}
	r, err := ion.NewIONResolver(http.DefaultClient, baseURL)
	if err != nil {
		return nil, errors.Wrap(err, "creating ion resolver")
	}
	return &ionHandler{method: did.IONMethod, resolver: r, storage: s, keyStore: ks}, nil
}

type ionHandler struct {
	method   did.Method
	resolver *ion.Resolver
	storage  *Storage
	keyStore *keystore.Service
}

type CreateIONDIDOptions struct {
	// TODO(gabe) for now we only allow adding service endpoints upon creation.
	//  we do not allow adding external keys or other properties.
	//  Related:
	//  - https://github.com/TBD54566975/ssi-sdk/issues/336
	//  - https://github.com/TBD54566975/ssi-sdk/issues/335
	ServiceEndpoints []ion.Service `json:"serviceEndpoints"`
}

func (c CreateIONDIDOptions) Method() did.Method {
	return did.IONMethod
}

func (h *ionHandler) GetMethod() did.Method {
	return h.method
}

type ionStoredDID struct {
	ID          string       `json:"id"`
	DID         did.Document `json:"did"`
	SoftDeleted bool         `json:"softDeleted"`
	LongFormDID string       `json:"longFormDID"`
	Operations  []any        `json:"operations"`
}

func (i ionStoredDID) GetID() string {
	return i.ID
}

func (i ionStoredDID) GetDocument() did.Document {
	return i.DID
}

func (i ionStoredDID) IsSoftDeleted() bool {
	return i.SoftDeleted
}

func (h *ionHandler) CreateDID(ctx context.Context, request CreateDIDRequest) (*CreateDIDResponse, error) {
	// process options
	var opts CreateIONDIDOptions
	var ok bool
	if request.Options != nil {
		opts, ok = request.Options.(CreateIONDIDOptions)
		if !ok || request.Options.Method() != did.IONMethod {
			return nil, fmt.Errorf("invalid options for method, expected %s, got %s", did.IONMethod, request.Options.Method())
		}
		if err := util.IsValidStruct(opts); err != nil {
			return nil, errors.Wrap(err, "processing options")
		}
	}

	// create a key for the doc
	_, privKey, err := crypto.GenerateKeyByKeyType(request.KeyType)
	if err != nil {
		return nil, errors.Wrap(err, "could not generate key for ion DID")
	}
	pubKeyJWK, privKeyJWK, err := crypto.PrivateKeyToPrivateKeyJWK(privKey)
	if err != nil {
		return nil, errors.Wrap(err, "could not convert key to JWK")
	}
	keyID := uuid.NewString()
	pubKeys := []ion.PublicKey{
		{
			ID:           keyID,
			Type:         request.KeyType.String(),
			PublicKeyJWK: *pubKeyJWK,
			// TODO(gabe): configurable purposes
			Purposes: []ion.PublicKeyPurpose{ion.Authentication, ion.AssertionMethod},
		},
	}

	// generate the did document's initial state
	doc := ion.Document{PublicKeys: pubKeys, Services: opts.ServiceEndpoints}
	ionDID, createOp, err := ion.NewIONDID(doc)
	if err != nil {
		return nil, errors.Wrap(err, "creating new ION DID")
	}

	// submit the create operation to the ION service
	if err = h.resolver.Anchor(ctx, createOp); err != nil {
		return nil, errors.Wrap(err, "anchoring create operation")
	}

	// construct first document state
	ldKeyType, err := did.KeyTypeToLDKeyType(request.KeyType)
	if err != nil {
		return nil, errors.Wrap(err, "converting key type to LD key type")
	}

	// TODO(gabe): move this to the SDK
	didDoc := did.Document{
		ID: ionDID.ID(),
		VerificationMethod: []did.VerificationMethod{
			{
				ID:           keyID,
				Type:         ldKeyType,
				Controller:   ionDID.ID(),
				PublicKeyJWK: pubKeyJWK,
			},
		},
		Authentication:  []did.VerificationMethodSet{map[string]any{"id": keyID}},
		AssertionMethod: []did.VerificationMethodSet{map[string]any{"id": keyID}},
	}
	for _, s := range opts.ServiceEndpoints {
		didDoc.Services = append(didDoc.Services, did.Service{
			ID:              s.ID,
			Type:            s.Type,
			ServiceEndpoint: s.ServiceEndpoint,
		})
	}

	// store the did document
	storedDID := ionStoredDID{
		ID:          ionDID.ID(),
		DID:         didDoc,
		SoftDeleted: false,
		LongFormDID: ionDID.LongForm(),
		Operations:  ionDID.Operations(),
	}
	if err = h.storage.StoreDID(ctx, storedDID); err != nil {
		return nil, errors.Wrap(err, "storing ion did document")
	}

	// store associated keys
	// 1. update key
	// 2. recovery key
	// 3. key(s) in the did doc
	updateStoreRequest, err := keyToStoreRequest(ionDID.ID()+"#"+updateKeySuffix, ionDID.GetUpdatePrivateKey(), ionDID.ID())
	if err != nil {
		return nil, errors.Wrap(err, "converting update private key to store request")
	}
	if err = h.keyStore.StoreKey(ctx, *updateStoreRequest); err != nil {
		return nil, errors.Wrap(err, "could not store did:ion update private key")
	}

	recoveryStoreRequest, err := keyToStoreRequest(ionDID.ID()+"#"+recoverKeySuffix, ionDID.GetRecoveryPrivateKey(), ionDID.ID())
	if err != nil {
		return nil, errors.Wrap(err, "converting recovery private key to store request")
	}
	if err = h.keyStore.StoreKey(ctx, *recoveryStoreRequest); err != nil {
		return nil, errors.Wrap(err, "could not store did:ion recovery private key")
	}

	keyStoreRequest, err := keyToStoreRequest(ionDID.ID()+"#"+keyID, *privKeyJWK, ionDID.ID())
	if err != nil {
		return nil, errors.Wrap(err, "converting private key to store request")
	}
	if err = h.keyStore.StoreKey(ctx, *keyStoreRequest); err != nil {
		return nil, errors.Wrap(err, "could not store did:ion private key")
	}

	privKeyBytes, err := crypto.PrivKeyToBytes(privKey)
	if err != nil {
		return nil, errors.Wrap(err, "converting private key to bytes")
	}
	return &CreateDIDResponse{
		DID:              didDoc,
		PrivateKeyBase58: base58.Encode(privKeyBytes),
		KeyType:          request.KeyType,
	}, nil
}

func keyToStoreRequest(kid string, privateKeyJWK crypto.PrivateKeyJWK, controller string) (*keystore.StoreKeyRequest, error) {
	privateKey, err := privateKeyJWK.ToPrivateKey()
	if err != nil {
		return nil, errors.Wrap(err, "getting private private key from JWK")
	}
	keyType, err := crypto.GetKeyTypeFromPrivateKey(privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "getting private key type from private privateKeyJWK")
	}
	// convert to a serialized format
	privateKeyBytes, err := crypto.PrivKeyToBytes(privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "could not encode private key as base58 string")
	}
	privateKeyBase58 := base58.Encode(privateKeyBytes)
	return &keystore.StoreKeyRequest{
		ID:               kid,
		Type:             keyType,
		Controller:       controller,
		PrivateKeyBase58: privateKeyBase58,
	}, nil
}

func (h *ionHandler) GetDID(ctx context.Context, request GetDIDRequest) (*GetDIDResponse, error) {
	id := request.ID

	// TODO(gabe) as we are fully custodying ION DIDs this is fine; as we move to a more decentralized model we will
	//  need to either remove local storage or treat it as a cache with a TTL

	// first check if the DID is in the storage
	gotDID := new(ionStoredDID)
	err := h.storage.GetDID(ctx, id, gotDID)
	if err == nil {
		return &GetDIDResponse{DID: gotDID.DID}, nil
	}
	logrus.WithError(err).Warnf("error getting DID from storage: %s", id)

	// if not, resolve it from the network
	resolved, err := h.resolver.Resolve(ctx, id, nil)
	if err != nil {
		return nil, errors.Wrap(err, "resolving DID from network")
	}
	return &GetDIDResponse{DID: resolved.Document}, nil
}

// GetDIDs returns all DIDs we have in storage for ION, it is not feasible to get all DIDs from the network
func (h *ionHandler) GetDIDs(ctx context.Context) (*GetDIDsResponse, error) {
	logrus.Debug("getting stored did:ion DIDs")

	gotDIDs, err := h.storage.GetDIDs(ctx, did.KeyMethod.String(), new(ionStoredDID))
	if err != nil {
		return nil, fmt.Errorf("error getting did:ion DIDs")
	}
	dids := make([]did.Document, 0, len(gotDIDs))
	for _, gotDID := range gotDIDs {
		if !gotDID.IsSoftDeleted() {
			dids = append(dids, gotDID.GetDocument())
		}
	}
	return &GetDIDsResponse{DIDs: dids}, nil
}

// SoftDeleteDID soft deletes a DID from storage but has no effect on the DID's state on the network
func (h *ionHandler) SoftDeleteDID(ctx context.Context, request DeleteDIDRequest) error {
	logrus.Debugf("soft deleting DID: %+v", request)

	id := request.ID
	gotDID := new(ionStoredDID)
	if err := h.storage.GetDID(ctx, id, gotDID); err != nil {
		return fmt.Errorf("error getting DID: %s", id)
	}
	if gotDID.GetID() == "" {
		return fmt.Errorf("did with id<%s> could not be found", id)
	}

	gotDID.SoftDeleted = true

	return h.storage.StoreDID(ctx, *gotDID)
}
