package keystore

import (
	"fmt"
	"time"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	keystorestorage "github.com/tbd54566975/ssi-service/pkg/service/keystore/storage"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type Service struct {
    storage keystorestorage.Storage
    config  config.KeyStoreServiceConfig
}

func (s Service) Type() framework.Type {
    return framework.KeyStore
}

func (s Service) Status() framework.Status {
    if s.storage == nil {
        return framework.Status{
            Status:  framework.StatusNotReady,
            Message: "no storage",
        }
    }
    return framework.Status{Status: framework.StatusReady}
}

func (s Service) Config() config.KeyStoreServiceConfig {
    return s.config
}

func NewKeyStoreService(config config.KeyStoreServiceConfig, s storage.ServiceStorage) (*Service, error) {
    // First, generate a service key
    serviceKey, serviceKeySalt, err := GenerateServiceKey(config.ServiceKeyPassword)
    if err != nil {
        return nil, util.LoggingErrorMsg(err, "could not generate service key")
    }

    // Next, instantiate the key storage
    keyStoreStorage, err := keystorestorage.NewKeyStoreStorage(s, serviceKey, serviceKeySalt)
    if err != nil {
        errMsg := "could not instantiate storage for the keystore service"
        return nil, util.LoggingErrorMsg(err, errMsg)
    }

    return &Service{
        storage: keyStoreStorage,
        config:  config,
    }, nil
}

func (s Service) StoreKey(request StoreKeyRequest) error {

    logrus.Debugf("storing key: %+v", request)

    // check if the provided key type is supported. support entails being able to serialize/deserialize, in addition
    // to facilitating signing/verification and encryption/decryption support.
    if !crypto.IsSupportedKeyType(request.Type) {
        errMsg := fmt.Sprintf("unsupported key type: %s", request.Type)
        return util.LoggingNewError(errMsg)
    }

    key := keystorestorage.StoredKey{
        ID:         request.ID,
        Controller: request.Controller,
        KeyType:    request.Type,
        Key:        request.Key,
        CreatedAt:  time.Now().Format(time.RFC3339),
    }
    if err := s.storage.StoreKey(key); err != nil {
        err := errors.Wrapf(err, "could not store key: %s", request.ID)
        return util.LoggingError(err)
    }
    return nil
}

func (s Service) GetKeyDetails(request GetKeyDetailsRequest) (*GetKeyDetailsResponse, error) {

    logrus.Debugf("getting key: %+v", request)

    id := request.ID
    gotKeyDetails, err := s.storage.GetKeyDetails(id)
    if err != nil {
        err := errors.Wrapf(err, "could not get key details for key: %s", id)
        return nil, util.LoggingError(err)
    }
    if gotKeyDetails == nil {
        err := errors.Wrapf(err, "key with id<%s> could not be found", id)
        return nil, util.LoggingError(err)
    }
    return &GetKeyDetailsResponse{
        ID:         gotKeyDetails.ID,
        Type:       gotKeyDetails.KeyType,
        Controller: gotKeyDetails.Controller,
        CreatedAt:  gotKeyDetails.CreatedAt,
    }, nil
}

// GenerateServiceKey using argon2 for key derivation generate a service key and corresponding salt,
// base58 encoding both values.
func GenerateServiceKey(skPassword string) (key, salt string, err error) {
    saltBytes, err := util.GenerateSalt(util.Argon2SaltSize)
    if err != nil {
        err := errors.Wrap(err, "could not generate salt for service key")
        return "", "", util.LoggingError(err)
    }

    keyBytes, err := util.Argon2KeyGen(skPassword, saltBytes, chacha20poly1305.KeySize)
    if err != nil {
        err := errors.Wrap(err, "could not generate key for service key")
        return "", "", util.LoggingError(err)
    }

    key = base58.Encode(keyBytes)
    salt = base58.Encode(saltBytes)
    return
}

// EncryptKey encrypts another key with the service key using xchacha20-poly1305
func EncryptKey(serviceKey, key []byte) ([]byte, error) {
    encryptedKey, err := util.XChaCha20Poly1305Encrypt(serviceKey, key)
    if err != nil {
        return nil, errors.Wrap(err, "could not encrypt key with service key")
    }
    return encryptedKey, nil
}

// DecryptKey encrypts another key with the service key using xchacha20-poly1305
func DecryptKey(serviceKey, encryptedKey []byte) ([]byte, error) {
    decryptedKey, err := util.XChaCha20Poly1305Decrypt(serviceKey, encryptedKey)
    if err != nil {
        return nil, errors.Wrap(err, "could not decrypt key with service key")
    }
    return decryptedKey, nil
}
