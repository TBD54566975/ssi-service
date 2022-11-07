package storage

import (
	"github.com/goccy/go-json"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"

	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

const (
	namespace         = "keystore"
	skKey             = "ssi-service-key"
	keyNotFoundErrMsg = "key not found"
)

type BoltKeyStoreStorage struct {
	db         *storage.BoltDB
	serviceKey []byte
}

func NewBoltKeyStoreStorage(db *storage.BoltDB, key ServiceKey) (*BoltKeyStoreStorage, error) {
	if db == nil {
		return nil, errors.New("bolt db reference is nil")
	}

	keyBytes, err := base58.Decode(key.Base58Key)
	if err != nil {
		return nil, errors.Wrap(err, "could not decode service key")
	}
	bolt := &BoltKeyStoreStorage{db: db, serviceKey: keyBytes}

	// first, store the service key
	if err = bolt.storeServiceKey(key); err != nil {
		return nil, errors.Wrap(err, "could not store service key")
	}
	return bolt, nil
}

// TODO(gabe): support more robust service key operations, including rotation, and caching
func (b BoltKeyStoreStorage) storeServiceKey(key ServiceKey) error {
	keyBytes, err := json.Marshal(key)
	if err != nil {
		return util.LoggingErrorMsg(err, "could not marshal service key")
	}
	if err := b.db.Write(namespace, skKey, keyBytes); err != nil {
		return util.LoggingErrorMsg(err, "could store marshal service key")
	}
	return nil
}

// getServiceKey attempts to get the service key from memory, and if not available rehydrates it from the DB
func (b BoltKeyStoreStorage) getServiceKey() ([]byte, error) {
	if len(b.serviceKey) != 0 {
		return b.serviceKey, nil
	}

	storedKeyBytes, err := b.db.Read(namespace, skKey)
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

	// decode service key
	keyBytes, err := base58.Decode(stored.Base58Key)
	if err != nil {
		return nil, errors.Wrap(err, "could not decode service key")
	}
	return keyBytes, nil
}

func (b BoltKeyStoreStorage) StoreKey(key StoredKey) error {
	id := key.ID
	if id == "" {
		return util.LoggingNewError("could not store key without an ID")
	}

	keyBytes, err := json.Marshal(key)
	if err != nil {
		return util.LoggingErrorMsgf(err, "could not store key: %s", id)
	}

	// get service key
	serviceKey, err := b.getServiceKey()
	if err != nil {
		return util.LoggingErrorMsgf(err, "could not get service key while storing key: %s", id)
	}

	// encrypt key before storing
	encryptedKey, err := util.XChaCha20Poly1305Encrypt(serviceKey, keyBytes)
	if err != nil {
		return util.LoggingErrorMsgf(err, "could not encrypt key: %s", key.ID)
	}

	return b.db.Write(namespace, id, encryptedKey)
}

func (b BoltKeyStoreStorage) GetKey(id string) (*StoredKey, error) {
	storedKeyBytes, err := b.db.Read(namespace, id)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get key details for key: %s", id)
	}
	if len(storedKeyBytes) == 0 {
		return nil, util.LoggingNewErrorf("could not find key details for key: %s", id)
	}

	// get service key
	serviceKey, err := b.getServiceKey()
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

func (b BoltKeyStoreStorage) GetKeyDetails(id string) (*KeyDetails, error) {
	stored, err := b.GetKey(id)
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
