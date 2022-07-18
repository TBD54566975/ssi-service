package storage

import (
    "fmt"

    "github.com/goccy/go-json"
    "github.com/pkg/errors"

    "github.com/tbd54566975/ssi-service/internal/util"
    "github.com/tbd54566975/ssi-service/pkg/storage"
)

const (
    namespace         = "keystore"
    keyNotFoundErrMsg = "key not found"
)

type BoltKeyStoreStorage struct {
    db          *storage.BoltDB
    kekPassword struct {
        password string
        salt     string
    }
}

func NewBoltKeyStoreStorage(db *storage.BoltDB, kekPassword string) (*BoltKeyStoreStorage, error) {
    if db == nil {
        return nil, errors.New("bolt db reference is nil")
    }
    //
    return &BoltKeyStoreStorage{
        db: db,
        kekPassword: struct {
            password string
            salt     string
        }{
            password: "",
            salt:     "",
        },
    }, nil
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
    return b.db.Write(namespace, id, keyBytes)
}

func (b BoltKeyStoreStorage) GetKeyDetails(id string) (*KeyDetails, error) {
    storedKeyBytes, err := b.db.Read(namespace, id)
    if err != nil {
        errMsg := fmt.Sprintf("could not get key details for key: %s", id)
        return nil, util.LoggingErrorMsg(err, errMsg)
    }
    if len(storedKeyBytes) == 0 {
        err := fmt.Errorf("could not find key details for key: %s", id)
        return nil, util.LoggingError(err)
    }
    var stored StoredKey
    if err := json.Unmarshal(storedKeyBytes, &stored); err != nil {
        errMsg := fmt.Sprintf("could not unmarshal stored key: %s", id)
        return nil, util.LoggingErrorMsg(err, errMsg)
    }
    return &KeyDetails{
        ID:         stored.ID,
        Controller: stored.Controller,
        KeyType:    stored.KeyType,
        CreatedAt:  stored.CreatedAt,
    }, nil
}
