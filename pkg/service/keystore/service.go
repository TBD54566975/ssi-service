package keystore

import (
	"context"
	"fmt"
	"time"

	"github.com/TBD54566975/ssi-sdk/crypto"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/tbd54566975/ssi-service/internal/keyaccess"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type Service struct {
	storage *Storage
	config  config.KeyStoreServiceConfig
}

func (s Service) Type() framework.Type {
	return framework.KeyStore
}

func (s Service) Status() framework.Status {
	ae := sdkutil.NewAppendError()
	if s.storage == nil {
		ae.AppendString("no storage configured")
	}
	if !ae.IsEmpty() {
		return framework.Status{
			Status:  framework.StatusNotReady,
			Message: fmt.Sprintf("key store service is not ready: %s", ae.Error().Error()),
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
		return nil, util.LoggingErrorMsg(err, "generating service key")
	}

	// Next, instantiate the key storage
	keyStoreStorage, err := NewKeyStoreStorage(s, ServiceKey{
		Base58Key:  serviceKey,
		Base58Salt: serviceKeySalt,
	})
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "instantiating storage for the keystore service")
	}

	service := Service{
		storage: keyStoreStorage,
		config:  config,
	}
	if !service.Status().IsReady() {
		return nil, errors.New(service.Status().Message)
	}
	return &service, nil
}

func (s Service) StoreKey(ctx context.Context, request StoreKeyRequest) error {
	logrus.Debugf("storing key: %+v", request)

	// check if the provided key type is supported. support entails being able to serialize/deserialize, in addition
	// to facilitating signing/verification and encryption/decryption support.
	if !crypto.IsSupportedKeyType(request.Type) {
		return util.LoggingNewErrorf("unsupported key type: %s", request.Type)
	}

	key := StoredKey{
		ID:         request.ID,
		Controller: request.Controller,
		KeyType:    request.Type,
		Base58Key:  request.PrivateKeyBase58,
		CreatedAt:  time.Now().Format(time.RFC3339),
	}
	if err := s.storage.StoreKey(ctx, key); err != nil {
		return util.LoggingErrorMsgf(err, "storing key: %s", request.ID)
	}
	return nil
}

func (s Service) GetKey(ctx context.Context, request GetKeyRequest) (*GetKeyResponse, error) {
	logrus.Debugf("getting key: %+v", request)

	id := request.ID
	gotKey, err := s.storage.GetKey(ctx, id)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "getting key with id: %s", id)
	}
	if gotKey == nil {
		return nil, util.LoggingErrorMsgf(err, "key with id<%s> could not be found", id)
	}

	// deserialize the key before returning
	keyBytes, err := base58.Decode(gotKey.Base58Key)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not deserialize key from base58")
	}
	privKey, err := crypto.BytesToPrivKey(keyBytes, gotKey.KeyType)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not reconstruct private key from storage")
	}

	return &GetKeyResponse{
		ID:         gotKey.ID,
		Type:       gotKey.KeyType,
		Controller: gotKey.Controller,
		Key:        privKey,
		CreatedAt:  gotKey.CreatedAt,
		Revoked:    gotKey.Revoked,
		RevokedAt:  gotKey.RevokedAt,
	}, nil
}

func (s Service) RevokeKey(ctx context.Context, request RevokeKeyRequest) error {
	logrus.Debugf("revoking key: %+v", request)
	id := request.ID
	err := s.storage.RevokeKey(ctx, id)
	if err != nil {
		return util.LoggingErrorMsgf(err, "could not delete key: %s", id)
	}
	return nil
}

func (s Service) GetKeyDetails(ctx context.Context, request GetKeyDetailsRequest) (*GetKeyDetailsResponse, error) {

	logrus.Debugf("getting key: %+v", request)

	id := request.ID
	gotKeyDetails, err := s.storage.GetKeyDetails(ctx, id)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get key details for key: %s", id)
	}
	if gotKeyDetails == nil {
		return nil, util.LoggingErrorMsgf(err, "key with id<%s> could not be found", id)
	}
	return &GetKeyDetailsResponse{
		ID:         gotKeyDetails.ID,
		Type:       gotKeyDetails.KeyType,
		Controller: gotKeyDetails.Controller,
		CreatedAt:  gotKeyDetails.CreatedAt,
		Revoked:    gotKeyDetails.Revoked,
		RevokedAt:  gotKeyDetails.RevokedAt,
	}, nil
}

// GenerateServiceKey using argon2 for key derivation generate a service key and corresponding salt,
// base58 encoding both values.
func GenerateServiceKey(skPassword string) (key, salt string, err error) {
	saltBytes, err := util.GenerateSalt(util.Argon2SaltSize)
	if err != nil {
		err = errors.Wrap(err, "generating salt for service key")
		return "", "", util.LoggingError(err)
	}

	keyBytes, err := util.Argon2KeyGen(skPassword, saltBytes, chacha20poly1305.KeySize)
	if err != nil {
		err = errors.Wrap(err, "generating key for service key")
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
		return nil, errors.Wrap(err, "encrypting key with service key")
	}
	return encryptedKey, nil
}

// DecryptKey encrypts another key with the service key using xchacha20-poly1305
func DecryptKey(serviceKey, encryptedKey []byte) ([]byte, error) {
	decryptedKey, err := util.XChaCha20Poly1305Decrypt(serviceKey, encryptedKey)
	if err != nil {
		return nil, errors.Wrap(err, "decrypting key with service key")
	}
	return decryptedKey, nil
}

// Sign fetches the key in the store, and uses it to sign data. Data should be json or json-serializable.
func (s Service) Sign(ctx context.Context, keyID string, data any) (*keyaccess.JWT, error) {
	gotKey, err := s.GetKey(ctx, GetKeyRequest{ID: keyID})
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "getting key with keyID<%s>", keyID)
	}
	keyAccess, err := keyaccess.NewJWKKeyAccess(gotKey.Controller, gotKey.ID, gotKey.Key)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "creating key access for keyID<%s>", keyID)
	}
	schemaToken, err := keyAccess.SignJSON(data)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "signing data with keyID<%s>", keyID)
	}
	return schemaToken, nil
}
