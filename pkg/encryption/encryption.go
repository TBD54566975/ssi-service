package encryption

import (
	"context"
	"strings"

	util2 "github.com/TBD54566975/ssi-sdk/util"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/integration/awskms"
	"github.com/google/tink/go/integration/gcpkms"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"
	"github.com/pkg/errors"
	"github.com/tbd54566975/ssi-service/internal/util"
	"google.golang.org/api/option"
)

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

type KeyResolver func(ctx context.Context) ([]byte, error)

type XChaCha20Poly1305Encrypter struct {
	keyResolver KeyResolver
}

func NewXChaCha20Poly1305EncrypterWithKey(key []byte) *XChaCha20Poly1305Encrypter {
	return &XChaCha20Poly1305Encrypter{func(ctx context.Context) ([]byte, error) {
		return key, nil
	}}
}

func NewXChaCha20Poly1305EncrypterWithKeyResolver(resolver KeyResolver) *XChaCha20Poly1305Encrypter {
	return &XChaCha20Poly1305Encrypter{resolver}
}

func (k XChaCha20Poly1305Encrypter) Encrypt(ctx context.Context, plaintext, _ []byte) ([]byte, error) {
	// encrypt key before storing
	key, err := k.keyResolver(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "resolving key")
	}
	encryptedKey, err := util.XChaCha20Poly1305Encrypt(key, plaintext)
	if err != nil {
		return nil, util2.LoggingErrorMsgf(err, "could not encrypt key")
	}
	return encryptedKey, nil
}

func (k XChaCha20Poly1305Encrypter) Decrypt(ctx context.Context, ciphertext, _ []byte) ([]byte, error) {
	if ciphertext == nil {
		return nil, nil
	}

	key, err := k.keyResolver(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "resolving key")
	}
	// decrypt key before unmarshaling
	decryptedKey, err := util.XChaCha20Poly1305Decrypt(key, ciphertext)
	if err != nil {
		return nil, util2.LoggingErrorMsgf(err, "could not decrypt key")
	}

	return decryptedKey, nil
}

var _ Decrypter = (*XChaCha20Poly1305Encrypter)(nil)
var _ Encrypter = (*XChaCha20Poly1305Encrypter)(nil)

type noopDecrypter struct{}

func (n noopDecrypter) Decrypt(_ context.Context, ciphertext, _ []byte) ([]byte, error) {
	return ciphertext, nil
}

type noopEncrypter struct{}

func (n noopEncrypter) Encrypt(_ context.Context, plaintext, _ []byte) ([]byte, error) {
	return plaintext, nil
}

var _ Decrypter = (*noopDecrypter)(nil)
var _ Encrypter = (*noopEncrypter)(nil)

var (
	NoopDecrypter = noopDecrypter{}
	NoopEncrypter = noopEncrypter{}
)

type wrappedEncrypter struct {
	tink.AEAD
}

func (w wrappedEncrypter) Encrypt(_ context.Context, plaintext, contextData []byte) ([]byte, error) {
	return w.AEAD.Encrypt(plaintext, contextData)
}

var _ Encrypter = (*wrappedEncrypter)(nil)

type wrappedDecrypter struct {
	tink.AEAD
}

func (w wrappedDecrypter) Decrypt(_ context.Context, ciphertext, contextInfo []byte) ([]byte, error) {
	return w.AEAD.Decrypt(ciphertext, contextInfo)
}

var _ Decrypter = (*wrappedDecrypter)(nil)

const (
	gcpKMSScheme = "gcp-kms"
	awsKMSScheme = "aws-kms"
)

type ExternalEncryptionConfig interface {
	GetMasterKeyURI() string
	GetKMSCredentialsPath() string
	EncryptionEnabled() bool
}

func NewExternalEncrypter(ctx context.Context, cfg ExternalEncryptionConfig) (Encrypter, Decrypter, error) {
	if !cfg.EncryptionEnabled() {
		return NoopEncrypter, NoopDecrypter, nil
	}
	var client registry.KMSClient
	var err error
	switch {
	case strings.HasPrefix(cfg.GetMasterKeyURI(), gcpKMSScheme):
		client, err = gcpkms.NewClientWithOptions(ctx, cfg.GetMasterKeyURI(), option.WithCredentialsFile(cfg.GetKMSCredentialsPath()))
		if err != nil {
			return nil, nil, errors.Wrap(err, "creating gcp kms client")
		}
	case strings.HasPrefix(cfg.GetMasterKeyURI(), awsKMSScheme):
		client, err = awskms.NewClientWithCredentials(cfg.GetMasterKeyURI(), cfg.GetKMSCredentialsPath())
		if err != nil {
			return nil, nil, errors.Wrap(err, "creating aws kms client")
		}
	default:
		return nil, nil, errors.Errorf("master_key_uri value %q is not supported", cfg.GetMasterKeyURI())
	}
	// TODO: move client registration to be per request (i.e. when things are encrypted/decrypted). https://github.com/TBD54566975/ssi-service/issues/598
	registry.RegisterKMSClient(client)
	dek := aead.AES256GCMKeyTemplate()
	kh, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate(cfg.GetMasterKeyURI(), dek))
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating keyset handle")
	}
	a, err := aead.New(kh)
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating aead from key handl")
	}
	return wrappedEncrypter{a}, wrappedDecrypter{a}, nil
}
