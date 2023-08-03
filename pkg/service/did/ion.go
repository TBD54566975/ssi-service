package did

import (
	"context"
	"fmt"
	"net/http"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/ion"
	"github.com/TBD54566975/ssi-sdk/did/resolution"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/pkg/service/common"
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

// Verify interface compliance https://github.com/uber-go/guide/blob/master/style.md#verify-interface-compliance
var _ MethodHandler = (*ionHandler)(nil)

type CreateIONDIDOptions struct {
	// Services to add to the DID document that will be created.
	ServiceEndpoints []did.Service `json:"serviceEndpoints"`

	// List of JSON Web Signatures serialized using compact serialization. The payload must be a JSON object that
	// represents a publicKey object. Such object must follow the schema described in step 3 of
	// https://identity.foundation/sidetree/spec/#add-public-keys. The payload must be signed
	// with the private key associated with the `publicKeyJwk` that will be added in the DID document.
	// The input will be parsed and verified, and the payload will be used to add public keys to the DID document in the
	// same way in which the `add-public-keys` patch action adds keys (see https://identity.foundation/sidetree/spec/#add-public-keys).
	JWSPublicKeys []string `json:"jwsPublicKeys"`
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
	var publicKeysFromJWS []ion.PublicKey
	if request.Options != nil {
		opts, ok = request.Options.(CreateIONDIDOptions)
		if !ok || request.Options.Method() != did.IONMethod {
			return nil, fmt.Errorf("invalid options for method, expected %s, got %s", did.IONMethod, request.Options.Method())
		}
		if err := util.IsValidStruct(opts); err != nil {
			return nil, errors.Wrap(err, "processing options")
		}

		publicKeysFromJWS = make([]ion.PublicKey, 0, len(opts.JWSPublicKeys))
		for _, jwsString := range opts.JWSPublicKeys {
			m, err := jws.ParseString(jwsString)
			if err != nil {
				return nil, errors.Wrapf(err, "parsing JWS string <%s>", jwsString)
			}

			headers, err := jwx.GetJWSHeaders([]byte(jwsString))
			if err != nil {
				return nil, errors.Wrapf(err, "getting JWS headers from <%s>", jwsString)
			}

			var publicKey ion.PublicKey
			if err := json.Unmarshal(m.Payload(), &publicKey); err != nil {
				return nil, errors.Wrap(err, "unmarshalling payload")
			}
			if err := util.IsValidStruct(publicKey); err != nil {
				return nil, errors.Wrap(err, "invalid publicKey in payload")
			}

			goPublicKey, err := publicKey.PublicKeyJWK.ToPublicKey()
			if err != nil {
				return nil, errors.Wrap(err, "converting JWK to go crypto public key")
			}

			if _, err := jws.Verify([]byte(jwsString), jws.WithKey(headers.Algorithm(), goPublicKey)); err != nil {
				return nil, errors.Wrapf(err, "verifying JWS for <%s>", jwsString)
			}

			publicKeysFromJWS = append(publicKeysFromJWS, publicKey)
		}
	}

	// create a key for the docs
	_, privKey, err := crypto.GenerateKeyByKeyType(request.KeyType)
	if err != nil {
		return nil, errors.Wrap(err, "could not generate key for ion DID")
	}
	pubKeyJWK, privKeyJWK, err := jwx.PrivateKeyToPrivateKeyJWK(uuid.NewString(), privKey)
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
	pubKeys = append(pubKeys, publicKeysFromJWS...)

	// generate the did document's initial state
	doc := ion.Document{PublicKeys: pubKeys, Services: opts.ServiceEndpoints}
	ionDID, createOp, err := ion.NewIONDID(doc)
	if err != nil {
		return nil, errors.Wrap(err, "creating new ION DID")
	}

	// submit the create operation to the ION service
	var resolutionResult *resolution.Result
	if resolutionResult, err = h.resolver.Anchor(ctx, createOp); err != nil {
		return nil, errors.Wrap(err, "anchoring create operation")
	}

	// store the did document
	storedDID := ionStoredDID{
		ID:          resolutionResult.Document.ID,
		DID:         resolutionResult.Document,
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
	// 3. key(s) in the did docs
	updateStoreRequest, err := keyToStoreRequest(resolutionResult.Document.ID+"#"+updateKeySuffix, ionDID.GetUpdatePrivateKey(), resolutionResult.Document.ID)
	if err != nil {
		return nil, errors.Wrap(err, "converting update private key to store request")
	}
	if err = h.keyStore.StoreKey(ctx, *updateStoreRequest); err != nil {
		return nil, errors.Wrap(err, "could not store did:ion update private key")
	}

	recoveryStoreRequest, err := keyToStoreRequest(resolutionResult.Document.ID+"#"+recoverKeySuffix, ionDID.GetRecoveryPrivateKey(), resolutionResult.Document.ID)
	if err != nil {
		return nil, errors.Wrap(err, "converting recovery private key to store request")
	}
	if err = h.keyStore.StoreKey(ctx, *recoveryStoreRequest); err != nil {
		return nil, errors.Wrap(err, "could not store did:ion recovery private key")
	}

	keyStoreID := did.FullyQualifiedVerificationMethodID(resolutionResult.Document.ID, resolutionResult.Document.VerificationMethod[0].ID)
	keyStoreRequest, err := keyToStoreRequest(keyStoreID, *privKeyJWK, resolutionResult.Document.ID)
	if err != nil {
		return nil, errors.Wrap(err, "converting private key to store request")
	}
	if err = h.keyStore.StoreKey(ctx, *keyStoreRequest); err != nil {
		return nil, errors.Wrap(err, "could not store did:ion private key")
	}

	return &CreateDIDResponse{DID: storedDID.DID}, nil
}

func keyToStoreRequest(kid string, privateKeyJWK jwx.PrivateKeyJWK, controller string) (*keystore.StoreKeyRequest, error) {
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

// ListDIDs returns all DIDs we have in storage for ION, it is not feasible to get all DIDs from the network
func (h *ionHandler) ListDIDs(ctx context.Context, page *common.Page) (*ListDIDsResponse, error) {
	gotDIDs, err := h.storage.ListDIDsPage(ctx, did.IONMethod.String(), page, new(ionStoredDID))
	if err != nil {
		return nil, errors.Wrap(err, "error getting did:ion DIDs")
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

// ListDeletedDIDs returns only DIDs we have in storage for ION with SoftDeleted flag set to true
func (h *ionHandler) ListDeletedDIDs(ctx context.Context) (*ListDIDsResponse, error) {
	logrus.Debug("listing stored did:ion DIDs")

	gotDIDs, err := h.storage.ListDIDs(ctx, did.IONMethod.String(), new(ionStoredDID))
	if err != nil {
		return nil, fmt.Errorf("error listing did:ion DIDs")
	}
	dids := make([]did.Document, 0, len(gotDIDs))
	for _, gotDID := range gotDIDs {
		if gotDID.IsSoftDeleted() {
			dids = append(dids, gotDID.GetDocument())
		}
	}
	return &ListDIDsResponse{DIDs: dids}, nil
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
