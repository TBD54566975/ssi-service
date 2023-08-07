package storage

import (
	"context"

	"github.com/pkg/errors"

	"github.com/tbd54566975/ssi-service/internal/encryption"
)

type EncryptedWrapper struct {
	s         ServiceStorage
	encrypter encryption.Encrypter
	decrypter encryption.Decrypter
}

func NewEncryptedWrapper(s ServiceStorage, encrypter encryption.Encrypter, decrypter encryption.Decrypter) *EncryptedWrapper {
	return &EncryptedWrapper{
		s:         s,
		encrypter: encrypter,
		decrypter: decrypter,
	}
}

func (e EncryptedWrapper) Init(opts ...Option) error {
	return e.s.Init(opts...)
}

func (e EncryptedWrapper) Type() Type {
	return e.s.Type()
}

func (e EncryptedWrapper) URI() string {
	return e.s.URI()
}

func (e EncryptedWrapper) IsOpen() bool {
	return e.s.IsOpen()
}

func (e EncryptedWrapper) Close() error {
	return e.s.Close()
}

func (e EncryptedWrapper) Write(ctx context.Context, namespace, key string, value []byte) error {
	encryptedData, err := e.encrypter.Encrypt(ctx, value, nil)
	if err != nil {
		return errors.Wrap(err, "encrypting data")
	}
	return e.s.Write(ctx, namespace, key, encryptedData)
}

func (e EncryptedWrapper) WriteMany(ctx context.Context, namespace, keys []string, values [][]byte) error {
	encryptedValues := make([][]byte, 0, len(values))
	for _, value := range values {
		encryptedData, err := e.encrypter.Encrypt(ctx, value, nil)
		if err != nil {
			return errors.Wrap(err, "encrypting data")
		}
		encryptedValues = append(encryptedValues, encryptedData)
	}
	return e.s.WriteMany(ctx, namespace, keys, encryptedValues)
}

func (e EncryptedWrapper) Read(ctx context.Context, namespace, key string) ([]byte, error) {
	storedBytes, err := e.s.Read(ctx, namespace, key)
	if err != nil {
		return nil, err
	}
	decryptedData, err := e.decrypter.Decrypt(ctx, storedBytes, nil)
	if err != nil {
		return nil, errors.Wrap(err, "decrypting data")
	}
	return decryptedData, nil
}

func (e EncryptedWrapper) Exists(ctx context.Context, namespace, key string) (bool, error) {
	return e.s.Exists(ctx, namespace, key)
}

func (e EncryptedWrapper) ReadAll(ctx context.Context, namespace string) (map[string][]byte, error) {
	encryptedKeyedBytes, err := e.s.ReadAll(ctx, namespace)
	if err != nil {
		return nil, err
	}
	return e.decryptMap(ctx, encryptedKeyedBytes)
}

func (e EncryptedWrapper) decryptMap(ctx context.Context, encryptedKeyedBytes map[string][]byte) (map[string][]byte, error) {
	decryptedValues := make(map[string][]byte, len(encryptedKeyedBytes))
	for key, encryptedBytes := range encryptedKeyedBytes {
		decryptedData, err := e.decrypter.Decrypt(ctx, encryptedBytes, nil)
		if err != nil {
			return nil, errors.Wrap(err, "decrypting data")
		}
		decryptedValues[key] = decryptedData
	}
	return decryptedValues, nil
}

func (e EncryptedWrapper) ReadPage(ctx context.Context, namespace string, pageToken string, pageSize int) (results map[string][]byte, nextPageToken string, err error) {
	encryptedResults, nextPageToken, err := e.s.ReadPage(ctx, namespace, pageToken, pageSize)
	if err != nil {
		return nil, "", err
	}
	decryptedMap, err := e.decryptMap(ctx, encryptedResults)
	if err != nil {
		return nil, "", err
	}
	return decryptedMap, nextPageToken, err
}

func (e EncryptedWrapper) ReadPrefix(ctx context.Context, namespace, prefix string) (map[string][]byte, error) {
	encryptedMap, err := e.s.ReadPrefix(ctx, namespace, prefix)
	if err != nil {
		return nil, err
	}
	return e.decryptMap(ctx, encryptedMap)
}

func (e EncryptedWrapper) ReadAllKeys(ctx context.Context, namespace string) ([]string, error) {
	return e.s.ReadAllKeys(ctx, namespace)
}

func (e EncryptedWrapper) Delete(ctx context.Context, namespace, key string) error {
	return e.s.Delete(ctx, namespace, key)
}

func (e EncryptedWrapper) DeleteNamespace(ctx context.Context, namespace string) error {
	return e.s.DeleteNamespace(ctx, namespace)
}

type encryptedTx struct {
	tx        Tx
	encrypter encryption.Encrypter
}

func (m encryptedTx) Write(ctx context.Context, namespace, key string, value []byte) error {
	encryptedData, err := m.encrypter.Encrypt(ctx, value, nil)
	if err != nil {
		return errors.Wrap(err, "encrypting data")
	}
	return m.tx.Write(ctx, namespace, key, encryptedData)
}

func (e EncryptedWrapper) Execute(ctx context.Context, businessLogicFunc BusinessLogicFunc, watchKeys []WatchKey) (any, error) {
	return e.s.Execute(ctx, func(ctx context.Context, tx Tx) (any, error) {
		return businessLogicFunc(ctx, encryptedTx{tx: tx, encrypter: e.encrypter})
	}, watchKeys)
}

var _ ServiceStorage = (*EncryptedWrapper)(nil)
