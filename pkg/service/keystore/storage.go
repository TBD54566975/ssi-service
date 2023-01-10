package keystore

import (
	"context"

	"github.com/goccy/go-json"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

// StoredKey represents a common data model to store data on all key types
type StoredKey struct {
	ID         string         `json:"id"`
	Controller string         `json:"controller"`
	KeyType    crypto.KeyType `json:"keyType"`
	Base58Key  string         `json:"key"`
	CreatedAt  string         `json:"createdAt"`
}

// KeyDetails represents a common data model to get information about a key, without revealing the key itself
type KeyDetails struct {
	ID         string         `json:"id"`
	Controller string         `json:"controller"`
	KeyType    crypto.KeyType `json:"keyType"`
	CreatedAt  string         `json:"createdAt"`
}

type ServiceKey struct {
	Base58Key  string
	Base58Salt string
}

const (
	namespace         = "keystore"
	skKey             = "ssi-service-key"
	keyNotFoundErrMsg = "key not found"
)

type Storage struct {
	db         storage.ServiceStorage
	serviceKey []byte
}

func NewKeyStoreStorage(db storage.ServiceStorage, key ServiceKey) (*Storage, error) {
	keyBytes, err := base58.Decode(key.Base58Key)
	if err != nil {
		return nil, errors.Wrap(err, "could not decode service key")
	}
	bolt := &Storage{db: db, serviceKey: keyBytes}

	// first, store the service key
	if err = bolt.storeServiceKey(context.Background(), key); err != nil {
		return nil, errors.Wrap(err, "could not store service key")
	}
	return bolt, nil
}

// TODO(gabe): support more robust service key operations, including rotation, and caching
func (kss *Storage) storeServiceKey(ctx context.Context, key ServiceKey) error {
	keyBytes, err := json.Marshal(key)
	if err != nil {
		return util.LoggingErrorMsg(err, "could not marshal service key")
	}
	if err = kss.db.Write(ctx, namespace, skKey, keyBytes); err != nil {
		return util.LoggingErrorMsg(err, "could store marshal service key")
	}
	return nil
}

// getAndSetServiceKey attempts to get the service key from memory, and if not available rehydrates it from the DB
func (kss *Storage) getAndSetServiceKey(ctx context.Context) ([]byte, error) {
	if len(kss.serviceKey) != 0 {
		return kss.serviceKey, nil
	}

	storedKeyBytes, err := kss.db.Read(ctx, namespace, skKey)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not get service key")
	}
	if len(storedKeyBytes) == 0 {
		return nil, util.LoggingNewError(keyNotFoundErrMsg)
	}

	var stored ServiceKey
	if err = json.Unmarshal(storedKeyBytes, &stored); err != nil {
		return nil, util.LoggingErrorMsg(err, "could not unmarshal service key")
	}

	keyBytes, err := base58.Decode(stored.Base58Key)
	if err != nil {
		return nil, errors.Wrap(err, "could not decode service key")
	}

	kss.serviceKey = keyBytes
	return keyBytes, nil
}

func (kss *Storage) StoreKey(ctx context.Context, key StoredKey) error {
	id := key.ID
	if id == "" {
		return util.LoggingNewError("could not store key without an ID")
	}

	keyBytes, err := json.Marshal(key)
	if err != nil {
		return util.LoggingErrorMsgf(err, "could not store key: %s", id)
	}

	// get service key
	serviceKey, err := kss.getAndSetServiceKey(ctx)
	if err != nil {
		return util.LoggingErrorMsgf(err, "could not get service key while storing key: %s", id)
	}

	// encrypt key before storing
	encryptedKey, err := util.XChaCha20Poly1305Encrypt(serviceKey, keyBytes)
	if err != nil {
		return util.LoggingErrorMsgf(err, "could not encrypt key: %s", key.ID)
	}

	return kss.db.Write(ctx, namespace, id, encryptedKey)
}

func (kss *Storage) GetKey(ctx context.Context, id string) (*StoredKey, error) {
	storedKeyBytes, err := kss.db.Read(ctx, namespace, id)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get key details for key: %s", id)
	}
	if len(storedKeyBytes) == 0 {
		return nil, util.LoggingNewErrorf("could not find key details for key: %s", id)
	}

	// get service key
	serviceKey, err := kss.getAndSetServiceKey(ctx)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get service key while getting key: %s", id)
	}

	// decrypt key before unmarshaling
	decryptedKey, err := util.XChaCha20Poly1305Decrypt(serviceKey, storedKeyBytes)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not decrypt key: %s", id)
	}

	var stored StoredKey
	if err = json.Unmarshal(decryptedKey, &stored); err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not unmarshal stored key: %s", id)
	}
	return &stored, nil
}

func (kss *Storage) GetKeyDetails(ctx context.Context, id string) (*KeyDetails, error) {
	stored, err := kss.GetKey(ctx, id)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get key details for key: %s", id)
	}
	return &KeyDetails{
		ID:         stored.ID,
		Controller: stored.Controller,
		KeyType:    stored.KeyType,
		CreatedAt:  stored.CreatedAt,
	}, nil
}
