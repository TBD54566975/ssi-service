package storage

import (
	"context"
	"fmt"
	"reflect"

	"github.com/sirupsen/logrus"
)

type Type string

type BusinessLogicFunc func(ctx context.Context, tx Tx) (any, error)

type WatchKey struct {
	Namespace string
	Key       string
}

type Tx interface {
	Write(ctx context.Context, namespace, key string, value []byte) error
}

const (
	Bolt  Type = "bolt"
	Redis Type = "redis"

	// Common options

	PasswordOption OptionKey = "storage-password-option"
)

var (
	availableStorages = make(map[Type]ServiceStorage)
)

type (
	// OptionKey uniquely represents an option to be used in a storage provider
	OptionKey string
)

// Option represents a single option that may be required for a storage provider
type Option struct {
	ID     OptionKey `json:"id,omitempty"`
	Option any       `json:"option,omitempty"`
}

// ServiceStorage describes the api for storage independent of DB providers
type ServiceStorage interface {
	Init(opts ...Option) error
	Type() Type
	URI() string
	IsOpen() bool
	Close() error
	Write(ctx context.Context, namespace, key string, value []byte) error
	WriteMany(ctx context.Context, namespace, key []string, value [][]byte) error
	Read(ctx context.Context, namespace, key string) ([]byte, error)
	Exists(ctx context.Context, namespace, key string) (bool, error)
	ReadAll(ctx context.Context, namespace string) (map[string][]byte, error)
	ReadPrefix(ctx context.Context, namespace, prefix string) (map[string][]byte, error)
	ReadAllKeys(ctx context.Context, namespace string) ([]string, error)
	Delete(ctx context.Context, namespace, key string) error
	DeleteNamespace(ctx context.Context, namespace string) error
	Update(ctx context.Context, namespace string, key string, values map[string]any) ([]byte, error)
	UpdateValueAndOperation(ctx context.Context, namespace, key string, updater Updater, opNamespace, opKey string, opUpdater ResponseSettingUpdater) (first, op []byte, err error)
	Execute(ctx context.Context, businessLogicFunc BusinessLogicFunc, watchKeys []WatchKey) (any, error)
}

// NewStorage returns the instance of the given storageProvider. If it doesn't exist, then a default implementation
// is created with the given option parameter.
func NewStorage(storageProvider Type, opts ...Option) (ServiceStorage, error) {
	impl := GetStorage(storageProvider)
	if impl == nil {
		return impl, fmt.Errorf("unsupported storage provider: %s", storageProvider)
	}
	logrus.Infof("STORAGE OPTS: %+v", opts)
	err := impl.Init(opts...)
	return impl, err
}

// RegisterStorage registers a storage dynamically by its Type.
func RegisterStorage(storage ServiceStorage) error {
	if availableStorages[storage.Type()] != nil {
		return fmt.Errorf("storage implementation for %s already exists", storage.Type())
	}
	availableStorages[storage.Type()] = storage
	return nil
}

// AvailableStorage returns the supported storage providers.
func AvailableStorage() []Type {
	return []Type{Bolt, Redis}
}

// IsStorageAvailable determines whether a given storage provider is available for instantiation.
func IsStorageAvailable(storage Type) bool {
	all := AvailableStorage()
	for _, s := range all {
		if storage == s {
			return true
		}
	}
	return false
}

// GetStorage fetches a previously registered storage by storage type.
func GetStorage(storageType Type) ServiceStorage {
	tmp := availableStorages[storageType]
	if tmp == nil {
		return tmp
	}
	if reflect.TypeOf(tmp).Kind() == reflect.Ptr {
		// Pointer:
		return reflect.New(reflect.ValueOf(tmp).Elem().Type()).Interface().(ServiceStorage)
	}
	// Not pointer:
	return reflect.New(reflect.TypeOf(tmp)).Elem().Interface().(ServiceStorage)
}
