package storage

import (
	"fmt"

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
	if err := bolt.storeServiceKey(key); err != nil {
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

func (b BoltKeyStoreStorage) StoreKey(key StoredKey) error {
	id := key.ID
	if id == "" {
		return util.LoggingNewError("could not store key without an ID")
	}

	keyBytes, err := json.Marshal(key)
	if err != nil {
		errMsg := fmt.Sprintf("could not store key: %s", id)
		return util.LoggingErrorMsg(err, errMsg)
	}

	// encrypt key before storing
	encryptedKey, err := util.XChaCha20Poly1305Encrypt(b.serviceKey, keyBytes)
	if err != nil {
		return errors.Wrapf(err, "could not encrypt key: %s", key.ID)
	}

	return b.db.Write(namespace, id, encryptedKey)
}

func (b BoltKeyStoreStorage) GetKey(id string) (*StoredKey, error) {
	storedKeyBytes, err := b.db.Read(namespace, id)
	if err != nil {
		errMsg := fmt.Sprintf("could not get key details for key: %s", id)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	if len(storedKeyBytes) == 0 {
		err := fmt.Errorf("could not find key details for key: %s", id)
		return nil, util.LoggingError(err)
	}

	// decrypt key before unmarshaling
	decryptedKey, err := util.XChaCha20Poly1305Decrypt(b.serviceKey, storedKeyBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "could not decrypt key: %s", id)
	}

	var stored StoredKey
	if err := json.Unmarshal(decryptedKey, &stored); err != nil {
		errMsg := fmt.Sprintf("could not unmarshal stored key: %s", id)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	return &stored, nil
}

func (b BoltKeyStoreStorage) GetKeyDetails(id string) (*KeyDetails, error) {
	stored, err := b.GetKey(id)
	if err != nil {
		return nil, errors.Wrapf(err, "could not get key details for key: %s", id)
	}
	return &KeyDetails{
		ID:         stored.ID,
		Controller: stored.Controller,
		KeyType:    stored.KeyType,
		CreatedAt:  stored.CreatedAt,
	}, nil
}
