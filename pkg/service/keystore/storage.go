package keystore

import (
	"context"
	"strings"
	"time"

	"github.com/TBD54566975/ssi-sdk/crypto"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/integration/awskms"
	"github.com/google/tink/go/integration/gcpkms"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"github.com/tbd54566975/ssi-service/config"
	"google.golang.org/api/option"

	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

// StoredKey represents a common data model to store data on all key types
type StoredKey struct {
	ID         string         `json:"id"`
	Controller string         `json:"controller"`
	KeyType    crypto.KeyType `json:"keyType"`
	Base58Key  string         `json:"key"`
	Revoked    bool           `json:"revoked"`
	RevokedAt  string         `json:"revokedAt"`
	CreatedAt  string         `json:"createdAt"`
}

// KeyDetails represents a common data model to get information about a key, without revealing the key itself
type KeyDetails struct {
	ID         string         `json:"id"`
	Controller string         `json:"controller"`
	KeyType    crypto.KeyType `json:"keyType"`
	Revoked    bool           `json:"revoked"`
	RevokedAt  string         `json:"revokedAt"`
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
	db        storage.ServiceStorage
	encryptor Encryptor
	decryptor Decryptor
}

func NewKeyStoreStorage(db storage.ServiceStorage, e Encryptor, d Decryptor) (*Storage, error) {
	bolt := &Storage{
		db:        db,
		encryptor: e,
		decryptor: d,
	}

	return bolt, nil
}

type wrappedEncryptor struct {
	tink.AEAD
}

func (w wrappedEncryptor) Encrypt(_ context.Context, plaintext, contextData []byte) ([]byte, error) {
	return w.AEAD.Encrypt(plaintext, contextData)
}

type wrappedDecryptor struct {
	tink.AEAD
}

func (w wrappedDecryptor) Decrypt(_ context.Context, ciphertext, contextInfo []byte) ([]byte, error) {
	return w.AEAD.Decrypt(ciphertext, contextInfo)
}

const (
	gcpKMSScheme = "gcp-kms"
	awsKMSScheme = "aws-kms"
)

func NewEncryption(db storage.ServiceStorage, cfg config.KeyStoreServiceConfig) (Encryptor, Decryptor, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if strings.HasPrefix(cfg.MasterKeyURI, gcpKMSScheme) || strings.HasPrefix(cfg.MasterKeyURI, awsKMSScheme) {
		return NewExternalEncryptor(ctx, cfg)
	}

	// First, generate a service key
	serviceKey, serviceKeySalt, err := GenerateServiceKey(cfg.ServiceKeyPassword)
	if err != nil {
		return nil, nil, sdkutil.LoggingErrorMsg(err, "generating service key")
	}

	key := ServiceKey{
		Base58Key:  serviceKey,
		Base58Salt: serviceKeySalt,
	}
	if err := storeServiceKey(ctx, db, key); err != nil {
		return nil, nil, err
	}
	return &encryptor{db}, &decryptor{db}, nil
}

func NewExternalEncryptor(ctx context.Context, cfg config.KeyStoreServiceConfig) (Encryptor, Decryptor, error) {
	var client registry.KMSClient
	var err error
	if strings.HasPrefix(cfg.MasterKeyURI, gcpKMSScheme) {
		client, err = gcpkms.NewClientWithOptions(ctx, cfg.MasterKeyURI, option.WithCredentialsFile(cfg.KMSCredentialsPath))
		if err != nil {
			return nil, nil, errors.Wrap(err, "creating gcp kms client")
		}
	} else if strings.HasPrefix(cfg.MasterKeyURI, awsKMSScheme) {
		client, err = awskms.NewClientWithCredentials(cfg.MasterKeyURI, cfg.KMSCredentialsPath)
		if err != nil {
			return nil, nil, errors.Wrap(err, "creating aws kms client")
		}
	}
	registry.RegisterKMSClient(client)
	dek := aead.XChaCha20Poly1305KeyTemplate()
	kh, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate(cfg.MasterKeyURI, dek))
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating keyset handle")
	}
	a, err := aead.New(kh)
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating aead from key handl")
	}
	return wrappedEncryptor{a}, wrappedDecryptor{a}, nil
}

// TODO(gabe): support more robust service key operations, including rotation, and caching
func storeServiceKey(ctx context.Context, db storage.ServiceStorage, key ServiceKey) error {
	keyBytes, err := json.Marshal(key)
	if err != nil {
		return sdkutil.LoggingErrorMsg(err, "could not marshal service key")
	}
	if err = db.Write(ctx, namespace, skKey, keyBytes); err != nil {
		return sdkutil.LoggingErrorMsg(err, "could store marshal service key")
	}
	return nil
}

func getServiceKey(ctx context.Context, db storage.ServiceStorage) ([]byte, error) {
	storedKeyBytes, err := db.Read(ctx, namespace, skKey)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not get service key")
	}
	if len(storedKeyBytes) == 0 {
		return nil, sdkutil.LoggingNewError(keyNotFoundErrMsg)
	}

	var stored ServiceKey
	if err = json.Unmarshal(storedKeyBytes, &stored); err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not unmarshal service key")
	}

	keyBytes, err := base58.Decode(stored.Base58Key)
	if err != nil {
		return nil, errors.Wrap(err, "could not decode service key")
	}

	return keyBytes, nil
}

// Encryptor the interface for any encryptor implementation.
type Encryptor interface {
	Encrypt(ctx context.Context, plaintext, contextData []byte) ([]byte, error)
}

// Decryptor is the interface for any decryptor. May be AEAD or Hybrid.
type Decryptor interface {
	// Decrypt decrypts ciphertext. The second parameter may be treated as associated data for AEAD (as abstracted in
	// https://datatracker.ietf.org/doc/html/rfc5116), or as contextInfofor HPKE (https://www.rfc-editor.org/rfc/rfc9180.html)
	Decrypt(ctx context.Context, ciphertext, contextInfo []byte) ([]byte, error)
}

type encryptor struct {
	db storage.ServiceStorage
}

func (e encryptor) Encrypt(ctx context.Context, plaintext, _ []byte) ([]byte, error) {
	// get service key
	serviceKey, err := getServiceKey(ctx, e.db)
	if err != nil {
		return nil, err
	}
	// encrypt key before storing
	encryptedKey, err := util.XChaCha20Poly1305Encrypt(serviceKey, plaintext)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "could not encrypt key")
	}
	return encryptedKey, nil
}

type decryptor struct {
	db storage.ServiceStorage
}

func (d decryptor) Decrypt(ctx context.Context, ciphertext, _ []byte) ([]byte, error) {
	// get service key
	serviceKey, err := getServiceKey(ctx, d.db)
	if err != nil {
		return nil, err
	}

	// decrypt key before unmarshaling
	decryptedKey, err := util.XChaCha20Poly1305Decrypt(serviceKey, ciphertext)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "could not decrypt key")
	}

	return decryptedKey, nil
}

func (kss *Storage) StoreKey(ctx context.Context, key StoredKey) error {
	// TODO(gabe): conflict checking on key id
	id := key.ID
	if id == "" {
		return sdkutil.LoggingNewError("could not store key without an ID")
	}

	keyBytes, err := json.Marshal(key)
	if err != nil {
		return sdkutil.LoggingErrorMsgf(err, "could not store key: %s", id)
	}

	// encrypt key before storing
	encryptedKey, err := kss.encryptor.Encrypt(ctx, keyBytes, nil)
	if err != nil {
		return sdkutil.LoggingErrorMsgf(err, "could not encrypt key: %s", key.ID)
	}

	return kss.db.Write(ctx, namespace, id, encryptedKey)
}

func (kss *Storage) RevokeKey(ctx context.Context, id string) error {
	key, err := kss.GetKey(ctx, id)
	if err != nil {
		return err
	}
	if key == nil {
		return errors.New("key not found")
	}

	key.Revoked = true
	key.RevokedAt = time.Now().UTC().Format(time.RFC3339)
	return kss.StoreKey(ctx, *key)
}

func (kss *Storage) GetKey(ctx context.Context, id string) (*StoredKey, error) {
	storedKeyBytes, err := kss.db.Read(ctx, namespace, id)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "getting key details for key: %s", id)
	}
	if len(storedKeyBytes) == 0 {
		return nil, sdkutil.LoggingNewErrorf("could not find key details for key: %s", id)
	}

	// decrypt key before unmarshaling
	decryptedKey, err := kss.decryptor.Decrypt(ctx, storedKeyBytes, nil)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "could not decrypt key: %s", id)
	}

	var stored StoredKey
	if err = json.Unmarshal(decryptedKey, &stored); err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "unmarshalling stored key: %s", id)
	}
	return &stored, nil
}

func (kss *Storage) GetKeyDetails(ctx context.Context, id string) (*KeyDetails, error) {
	stored, err := kss.GetKey(ctx, id)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "could not get key details for key: %s", id)
	}
	return &KeyDetails{
		ID:         stored.ID,
		Controller: stored.Controller,
		KeyType:    stored.KeyType,
		CreatedAt:  stored.CreatedAt,
		Revoked:    stored.Revoked,
	}, nil
}
