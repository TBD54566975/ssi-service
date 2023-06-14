package keystore

import (
	"context"
	"strings"
	"time"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/benbjohnson/clock"
	"github.com/goccy/go-json"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/integration/awskms"
	"github.com/google/tink/go/integration/gcpkms"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"google.golang.org/api/option"

	"github.com/tbd54566975/ssi-service/config"

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
	ID           string           `json:"id"`
	Controller   string           `json:"controller"`
	KeyType      crypto.KeyType   `json:"keyType"`
	Revoked      bool             `json:"revoked"`
	RevokedAt    string           `json:"revokedAt"`
	CreatedAt    string           `json:"createdAt"`
	PublicKeyJWK jwx.PublicKeyJWK `json:"publicKeyJwk"`
}

type ServiceKey struct {
	Base58Key  string
	Base58Salt string
}

const (
	namespace             = "keystore"
	publicNamespaceSuffix = ":public-keys"
	skKey                 = "ssi-service-key"
	keyNotFoundErrMsg     = "key not found"
)

type Storage struct {
	db        storage.ServiceStorage
	tx        storage.Tx
	encrypter Encrypter
	decrypter Decrypter
	Clock     clock.Clock
}

func NewKeyStoreStorage(db storage.ServiceStorage, e Encrypter, d Decrypter, writer storage.Tx) (*Storage, error) {
	s := &Storage{
		db:        db,
		encrypter: e,
		decrypter: d,
		Clock:     clock.New(),
		tx:        db,
	}
	if writer != nil {
		s.tx = writer
	}

	return s, nil
}

type wrappedEncrypter struct {
	tink.AEAD
}

func (w wrappedEncrypter) Encrypt(_ context.Context, plaintext, contextData []byte) ([]byte, error) {
	return w.AEAD.Encrypt(plaintext, contextData)
}

type wrappedDecrypter struct {
	tink.AEAD
}

func (w wrappedDecrypter) Decrypt(_ context.Context, ciphertext, contextInfo []byte) ([]byte, error) {
	return w.AEAD.Decrypt(ciphertext, contextInfo)
}

const (
	gcpKMSScheme = "gcp-kms"
	awsKMSScheme = "aws-kms"
)

func NewEncryption(db storage.ServiceStorage, tx storage.Tx, cfg config.KeyStoreServiceConfig) (Encrypter, Decrypter, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if len(cfg.MasterKeyURI) != 0 {
		return NewExternalEncrypter(ctx, cfg)
	}

	// First, generate a service key
	serviceKey, serviceKeySalt, err := GenerateServiceKey(cfg.MasterKeyPassword)
	if err != nil {
		return nil, nil, sdkutil.LoggingErrorMsg(err, "generating service key")
	}

	key := ServiceKey{
		Base58Key:  serviceKey,
		Base58Salt: serviceKeySalt,
	}
	if err := storeServiceKey(ctx, tx, key); err != nil {
		return nil, nil, err
	}
	return &encrypter{db}, &decrypter{db}, nil
}

func NewExternalEncrypter(ctx context.Context, cfg config.KeyStoreServiceConfig) (Encrypter, Decrypter, error) {
	var client registry.KMSClient
	var err error
	switch {
	case strings.HasPrefix(cfg.MasterKeyURI, gcpKMSScheme):
		client, err = gcpkms.NewClientWithOptions(ctx, cfg.MasterKeyURI, option.WithCredentialsFile(cfg.KMSCredentialsPath))
		if err != nil {
			return nil, nil, errors.Wrap(err, "creating gcp kms client")
		}
	case strings.HasPrefix(cfg.MasterKeyURI, awsKMSScheme):
		client, err = awskms.NewClientWithCredentials(cfg.MasterKeyURI, cfg.KMSCredentialsPath)
		if err != nil {
			return nil, nil, errors.Wrap(err, "creating aws kms client")
		}
	default:
		return nil, nil, errors.Errorf("master_key_uri value %q is not supported", cfg.MasterKeyURI)
	}
	registry.RegisterKMSClient(client)
	dek := aead.AES256GCMKeyTemplate()
	kh, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate(cfg.MasterKeyURI, dek))
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating keyset handle")
	}
	a, err := aead.New(kh)
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating aead from key handl")
	}
	return wrappedEncrypter{a}, wrappedDecrypter{a}, nil
}

// TODO(gabe): support more robust service key operations, including rotation, and caching
func storeServiceKey(ctx context.Context, tx storage.Tx, key ServiceKey) error {
	keyBytes, err := json.Marshal(key)
	if err != nil {
		return sdkutil.LoggingErrorMsg(err, "could not marshal service key")
	}
	if err = tx.Write(ctx, namespace, skKey, keyBytes); err != nil {
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

// Encrypter the interface for any encrypter implementation.
type Encrypter interface {
	Encrypt(ctx context.Context, plaintext, contextData []byte) ([]byte, error)
}

// Decrypter is the interface for any decrypter. May be AEAD or Hybrid.
type Decrypter interface {
	// Decrypt decrypts ciphertext. The second parameter may be treated as associated data for AEAD (as abstracted in
	// https://datatracker.ietf.org/doc/html/rfc5116), or as contextInfofor HPKE (https://www.rfc-editor.org/rfc/rfc9180.html)
	Decrypt(ctx context.Context, ciphertext, contextInfo []byte) ([]byte, error)
}

type encrypter struct {
	db storage.ServiceStorage
}

func (e encrypter) Encrypt(ctx context.Context, plaintext, _ []byte) ([]byte, error) {
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

type decrypter struct {
	db storage.ServiceStorage
}

func (d decrypter) Decrypt(ctx context.Context, ciphertext, _ []byte) ([]byte, error) {
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
		return sdkutil.LoggingErrorMsg(err, "deserializing key from base58")
	}

	skBytes, err := base58.Decode(key.Base58Key)
	if err != nil {
		return sdkutil.LoggingErrorMsg(err, "deserializing key from base58")
	}

	secretKey, err := crypto.BytesToPrivKey(skBytes, key.KeyType)
	if err != nil {
		return sdkutil.LoggingErrorMsg(err, "reconstructing private key from input")
	}

	publicJWK, _, err := jwx.PrivateKeyToPrivateKeyJWK(key.ID, secretKey)
	if err != nil {
		return sdkutil.LoggingErrorMsg(err, "reconstructing JWK")
	}

	publicBytes, err := json.Marshal(publicJWK)
	if err != nil {
		return sdkutil.LoggingErrorMsg(err, "marshalling JWK")
	}

	if err := kss.tx.Write(ctx, namespace+publicNamespaceSuffix, id, publicBytes); err != nil {
		return sdkutil.LoggingErrorMsgf(err, "writing public key")
	}

	// encrypt key before storing
	encryptedKey, err := kss.encrypter.Encrypt(ctx, keyBytes, nil)
	if err != nil {
		return sdkutil.LoggingErrorMsgf(err, "could not encrypt key: %s", key.ID)
	}

	return kss.tx.Write(ctx, namespace, id, encryptedKey)
}

// RevokeKey revokes a key by setting the revoked flag to true.
func (kss *Storage) RevokeKey(ctx context.Context, id string) error {
	key, err := kss.GetKey(ctx, id)
	if err != nil {
		return err
	}
	if key == nil {
		return sdkutil.LoggingNewErrorf("key not found: %s", id)
	}

	key.Revoked = true
	key.RevokedAt = kss.Clock.Now().Format(time.RFC3339)
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

	// decrypt key before unmarshalling
	decryptedKey, err := kss.decrypter.Decrypt(ctx, storedKeyBytes, nil)
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
		return nil, sdkutil.LoggingErrorMsgf(err, "reading details for private key %q", id)
	}

	storedPublicKeyBytes, err := kss.db.Read(ctx, namespace+publicNamespaceSuffix, id)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "reading details for public key %q", id)
	}
	var storedPublicKey jwx.PublicKeyJWK
	if err = json.Unmarshal(storedPublicKeyBytes, &storedPublicKey); err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "unmarshalling public key")
	}

	return &KeyDetails{
		ID:           stored.ID,
		Controller:   stored.Controller,
		KeyType:      stored.KeyType,
		CreatedAt:    stored.CreatedAt,
		Revoked:      stored.Revoked,
		PublicKeyJWK: storedPublicKey,
	}, nil
}
