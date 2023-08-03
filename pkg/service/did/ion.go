package did

import (
	"context"
	"fmt"
	"net/http"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/ion"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/pkg/service/common"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

const (
	updateKeySuffix  string = "update"
	recoverKeySuffix string = "recover"
)

func NewIONHandler(baseURL string, s *Storage, ks *keystore.Service, factory keystore.ServiceFactory, storageFactory StorageFactory) (MethodHandler, error) {
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
	return &ionHandler{
		method:            did.IONMethod,
		resolver:          r,
		storage:           s,
		keyStore:          ks,
		keyStoreFactory:   factory,
		didStorageFactory: storageFactory,
	}, nil
}

type ionHandler struct {
	method            did.Method
	resolver          *ion.Resolver
	storage           *Storage
	keyStore          *keystore.Service
	keyStoreFactory   keystore.ServiceFactory
	didStorageFactory StorageFactory
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

type PreAnchor struct {
	UpdateOperation        *ion.UpdateRequest
	NextUpdatePublicJWK    *jwx.PublicKeyJWK
	UpdatedDID             *ionStoredDID
	NextUpdatePrivateJWKID string
}

type Anchor struct {
	// The result of calling anchor.
	Err string
}

type updateState struct {
	ID        string
	Status    UpdateRequestStatus
	PreAnchor *PreAnchor
	Anchor    *Anchor
}

func (h *ionHandler) UpdateDID(ctx context.Context, request UpdateIONDIDRequest) (*UpdateIONDIDResponse, error) {
	if err := request.StateChange.IsValid(); err != nil {
		return nil, errors.Wrap(err, "validating StateChange")
	}

	updateStatesKey := request.DID.String()
	watchKeys := []storage.WatchKey{
		{
			Namespace: updateRequestStatesNamespace,
			Key:       updateStatesKey,
		},
	}

	execResp, err := h.storage.db.Execute(ctx, h.prepareUpdate(request), watchKeys)
	if err != nil {
		return nil, errors.Wrapf(err, "executing transition to %s", PreAnchorStatus)
	}
	updateStates := execResp.([]updateState)
	state := &updateStates[len(updateStates)-1]

	if state.Status == PreAnchorStatus {
		state.Anchor = new(Anchor)
		_, err := h.resolver.Anchor(ctx, state.PreAnchor.UpdateOperation)
		if err != nil {
			// Signature errors are OK, as they mean that the update operation has already been applied. It means we haven't updated our updateKey to the latest one.
			state.Anchor.Err = err.Error()
			if isPreviouslyAnchoredError(err) {
				state.Status = AnchoredStatus
			} else {
				state.Status = AnchorErrorStatus
				if storeErr := h.storeUpdateStates(ctx, h.storage.db, request.DID.String(), updateStates); storeErr != nil {
					return nil, storeErr
				}
				return nil, err
			}
		} else {
			state.Status = AnchoredStatus
		}
		if err := h.storeUpdateStates(ctx, h.storage.db, request.DID.String(), updateStates); err != nil {
			return nil, err
		}
	}

	_, err = h.storage.db.Execute(ctx, h.applyUpdate(state.ID), watchKeys)
	if err != nil {
		return nil, errors.Wrapf(err, "executing transition to %s", DoneStatus)
	}

	return &UpdateIONDIDResponse{
		DID: state.PreAnchor.UpdatedDID.DID,
	}, nil
}

func (h *ionHandler) applyUpdate(id string) func(ctx context.Context, tx storage.Tx) (any, error) {
	return func(ctx context.Context, tx storage.Tx) (any, error) {
		updateStates, _, err := h.readUpdateStates(ctx, id)
		if err != nil {
			return nil, err
		}
		state := &updateStates[len(updateStates)-1]
		if state.Status == AnchoredStatus {
			keyStore, err := h.keyStoreFactory(tx)
			if err != nil {
				return nil, errors.Wrap(err, "creating key store service")
			}

			gotKey, err := keyStore.GetKey(ctx, keystore.GetKeyRequest{ID: state.PreAnchor.NextUpdatePrivateJWKID})
			if err != nil {
				return nil, errors.Wrap(err, "getting key from keystore")
			}
			_, nextUpdatePrivateJWK, err := jwx.PrivateKeyToPrivateKeyJWK(gotKey.ID, gotKey.Key)
			if err != nil {
				return nil, errors.Wrap(err, "converting stored key to JWK")
			}

			updateStoreRequest, err := keyToStoreRequest(updateKeyID(state.ID), *nextUpdatePrivateJWK, state.ID)
			if err != nil {
				return nil, errors.Wrap(err, "converting update private key to store request")
			}
			if err := keyStore.StoreKey(ctx, *updateStoreRequest); err != nil {
				return nil, errors.Wrap(err, "could not store did:ion update private key")
			}

			didStorage, err := h.didStorageFactory(tx)
			if err != nil {
				return nil, errors.Wrap(err, "creating did storage")
			}
			if err := didStorage.StoreDID(ctx, state.PreAnchor.UpdatedDID); err != nil {
				return nil, errors.Wrap(err, "storing DID in storage")
			}

			state.Status = DoneStatus
			if err := h.storeUpdateStates(ctx, tx, state.ID, updateStates); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}
}

func (h *ionHandler) prepareUpdate(request UpdateIONDIDRequest) func(ctx context.Context, tx storage.Tx) (any, error) {
	return func(ctx context.Context, tx storage.Tx) (any, error) {
		updateStates, updatePrivateKey, err := h.readUpdateStates(ctx, request.DID.String())
		if err != nil {
			return nil, err
		}
		state := &updateStates[len(updateStates)-1]
		if state.Status == DoneStatus || state.Status == AnchorErrorStatus {
			updateStates = append(updateStates, updateState{
				ID: request.DID.String(),
			})
			state = &updateStates[len(updateStates)-1]
		}
		if state.Status == "" {

			didSuffix, err := request.DID.Suffix()
			if err != nil {
				return nil, errors.Wrap(err, "getting did suffix")
			}

			updateKey := updatePrivateKey.ToPublicKeyJWK()
			// ION does not like keys that have KID nor ALG. See https://github.com/decentralized-identity/sidetree-reference-impl/blob/bf1f7aeab251083cfb5ea5d612f481cd41f0ab1b/lib/core/versions/latest/util/Jwk.ts#L35
			updateKey.ALG = ""
			updateKey.KID = ""

			signer, err := ion.NewBTCSignerVerifier(*updatePrivateKey)
			if err != nil {
				return nil, errors.Wrap(err, "creating btc signer verifier")
			}

			nextUpdateKey, nextUpdatePrivateKey, err := h.nextUpdateKey()
			if err != nil {
				return nil, err
			}

			updateOp, err := ion.NewUpdateRequest(didSuffix, updateKey, *nextUpdateKey, *signer, request.StateChange)
			if err != nil {
				return nil, errors.Wrap(err, "creating update request")
			}

			keyStore, err := h.keyStoreFactory(tx)
			if err != nil {
				return nil, errors.Wrap(err, "creating key store service")
			}
			storeRequestForUpdateKey, err := keyToStoreRequest("staging:"+request.DID.String(), *nextUpdatePrivateKey, request.DID.String())
			if err != nil {
				return nil, errors.Wrap(err, "converting update private key to store request")
			}
			if err := keyStore.StoreKey(ctx, *storeRequestForUpdateKey); err != nil {
				return nil, errors.Wrap(err, "could not store did:ion update private key")
			}

			storedDID := new(ionStoredDID)
			if err := h.storage.GetDID(ctx, request.DID.String(), storedDID); err != nil {
				return nil, errors.Wrap(err, "getting ion did from storage")
			}

			updatedLongForm, updatedDIDDoc, err := updateLongForm(request.DID.String(), storedDID.LongFormDID, updateOp)
			if err != nil {
				return nil, err
			}

			updatedDID := &ionStoredDID{
				ID:          storedDID.ID,
				DID:         *updatedDIDDoc,
				SoftDeleted: storedDID.SoftDeleted,
				LongFormDID: updatedLongForm,
				Operations:  append(storedDID.Operations, updateOp),
			}

			state.PreAnchor = &PreAnchor{
				UpdateOperation:        updateOp,
				UpdatedDID:             updatedDID,
				NextUpdatePrivateJWKID: storeRequestForUpdateKey.ID,
				NextUpdatePublicJWK:    nextUpdateKey,
			}
			state.Status = PreAnchorStatus
			if err := h.storeUpdateStates(ctx, tx, request.DID.String(), updateStates); err != nil {
				return nil, err
			}
		}

		return updateStates, nil
	}
}

func updateLongForm(shortFormDID string, longFormDID string, updateOp *ion.UpdateRequest) (string, *did.Document, error) {
	_, initialState, err := ion.DecodeLongFormDID(longFormDID)
	if err != nil {
		return "", nil, errors.Wrap(err, "invalid long form DID")
	}

	delta := ion.Delta{
		Patches:          append(initialState.Delta.Patches, updateOp.Delta.GetPatches()...),
		UpdateCommitment: updateOp.Delta.UpdateCommitment,
	}
	suffixData := initialState.SuffixData
	createRequest := ion.CreateRequest{
		Type:       ion.Create,
		SuffixData: suffixData,
		Delta:      delta,
	}
	updatedInitialState := ion.InitialState{
		Delta:      createRequest.Delta,
		SuffixData: createRequest.SuffixData,
	}
	initialStateBytesCanonical, err := ion.CanonicalizeAny(updatedInitialState)
	if err != nil {
		return "", nil, errors.Wrap(err, "canonicalizing long form DID suffix data")
	}
	encoded := ion.Encode(initialStateBytesCanonical)
	newLongFormDID := shortFormDID + ":" + encoded

	didDoc, err := ion.PatchesToDIDDocument(shortFormDID, newLongFormDID, createRequest.Delta.GetPatches())
	if err != nil {
		return "", nil, errors.Wrap(err, "patching the updated did")
	}
	return newLongFormDID, didDoc, nil
}

func isPreviouslyAnchoredError(_ error) bool {
	// TODO: figure out how to determine this error from the body of the response.
	return false
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
	if _, err = h.resolver.Anchor(ctx, createOp); err != nil {
		return nil, errors.Wrap(err, "anchoring create operation")
	}

	_, initialState, err := ion.DecodeLongFormDID(ionDID.LongForm())
	if err != nil {
		return nil, errors.Wrap(err, "invalid long form DID")
	}
	// TODO: remove the first parameter once it is removed in the SDK (https://github.com/TBD54566975/ssi-sdk/issues/438)
	didDoc, err := ion.PatchesToDIDDocument("unused", ionDID.ID(), initialState.Delta.Patches)
	if err != nil {
		return nil, errors.Wrap(err, "patching the did document locally")
	}

	// store the did document
	storedDID := ionStoredDID{
		ID:          ionDID.ID(),
		DID:         *didDoc,
		SoftDeleted: false,
		LongFormDID: ionDID.LongForm(),
		Operations:  ionDID.Operations(),
	}
	if err = h.storage.StoreDID(ctx, storedDID); err != nil {
		return nil, errors.Wrap(err, "storing ion did document")
	}

	if err := h.storeKeys(ctx, ionDID); err != nil {
		return nil, err
	}

	// 3. key(s) in the did docs
	keyStoreRequest, err := keyToStoreRequest(did.FullyQualifiedVerificationMethodID(ionDID.ID(), didDoc.VerificationMethod[0].ID), *privKeyJWK, ionDID.ID())
	if err != nil {
		return nil, errors.Wrap(err, "converting private key to store request")
	}
	if err = h.keyStore.StoreKey(ctx, *keyStoreRequest); err != nil {
		return nil, errors.Wrap(err, "could not store did:ion private key")
	}

	return &CreateDIDResponse{DID: *didDoc}, nil
}

func (h *ionHandler) storeKeys(ctx context.Context, ionDID *ion.DID) error {
	// store associated keys
	// 1. update key
	// 2. recovery key
	updateStoreRequest, err := keyToStoreRequest(updateKeyID(ionDID.ID()), ionDID.GetUpdatePrivateKey(), ionDID.ID())
	if err != nil {
		return errors.Wrap(err, "converting update private key to store request")
	}
	if err = h.keyStore.StoreKey(ctx, *updateStoreRequest); err != nil {
		return errors.Wrap(err, "could not store did:ion update private key")
	}

	recoveryStoreRequest, err := keyToStoreRequest(recoveryKeyID(ionDID.ID()), ionDID.GetRecoveryPrivateKey(), ionDID.ID())
	if err != nil {
		return errors.Wrap(err, "converting recovery private key to store request")
	}
	if err = h.keyStore.StoreKey(ctx, *recoveryStoreRequest); err != nil {
		return errors.Wrap(err, "could not store did:ion recovery private key")
	}

	return nil
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

func (h *ionHandler) readUpdatePrivateKey(ctx context.Context, did string) (*jwx.PrivateKeyJWK, error) {
	keyID := updateKeyID(did)
	getKeyRequest := keystore.GetKeyRequest{ID: keyID}
	key, err := h.keyStore.GetKey(ctx, getKeyRequest)
	if err != nil {
		return nil, errors.Wrap(err, "fetching update private key")
	}
	_, privateJWK, err := jwx.PrivateKeyToPrivateKeyJWK(keyID, key.Key)
	if err != nil {
		return nil, errors.Wrap(err, "getting update private key")
	}
	return privateJWK, err
}

func updateKeyID(did string) string {
	return did + "#" + updateKeySuffix
}

func recoveryKeyID(did string) string {
	return did + "#" + recoverKeySuffix
}

func (h *ionHandler) nextUpdateKey() (*jwx.PublicKeyJWK, *jwx.PrivateKeyJWK, error) {
	_, nextUpdatePrivateKey, err := crypto.GenerateSECP256k1Key()
	if err != nil {
		return nil, nil, errors.Wrap(err, "generating next update keypair")
	}
	nextUpdatePubKeyJWK, nextUpdatePrivateKeyJWK, err := jwx.PrivateKeyToPrivateKeyJWK(uuid.NewString(), nextUpdatePrivateKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "converting next update key pair to JWK")
	}
	return nextUpdatePubKeyJWK, nextUpdatePrivateKeyJWK, nil
}

const updateRequestStatesNamespace = "update-request-states"

func (h *ionHandler) readUpdateStates(ctx context.Context, id string) ([]updateState, *jwx.PrivateKeyJWK, error) {
	privateUpdateJWK, err := h.readUpdatePrivateKey(ctx, id)
	if err != nil {
		return nil, nil, err
	}

	readData, err := h.storage.db.Read(ctx, updateRequestStatesNamespace, id)
	if err != nil {
		return nil, nil, errors.Wrap(err, "reading update status")
	}
	if readData == nil {
		return []updateState{{
			ID: id,
		}}, privateUpdateJWK, nil
	}
	var statuses []updateState
	if err := json.Unmarshal(readData, &statuses); err != nil {
		return nil, nil, errors.Wrap(err, "unmarhsalling status array")
	}

	return statuses, privateUpdateJWK, nil

}

func (h *ionHandler) storeUpdateStates(ctx context.Context, tx storage.Tx, id string, states []updateState) error {
	bytes, err := json.Marshal(states)
	if err != nil {
		return errors.Wrap(err, "marshalling json")
	}

	if err := tx.Write(ctx, updateRequestStatesNamespace, id, bytes); err != nil {
		return errors.Wrap(err, "writing update states")
	}
	return nil
}
