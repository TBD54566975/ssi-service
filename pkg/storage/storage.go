package storage

import (
	"context"
	"fmt"
	"reflect"
)

type Type string

const (
	Bolt  Type = "bolt"
	Redis Type = "redis"
)

var (
	availableStorages = make(map[Type]ServiceStorage)
)

// ServiceStorage describes the api for storage independent of DB providers
type ServiceStorage interface {
	Init(interface{}) error
	Type() Type
	URI() string
	IsOpen() bool
	Close() error
	Write(ctx context.Context, namespace, key string, value []byte) error
	Read(namespace, key string) ([]byte, error)
	ReadAll(namespace string) (map[string][]byte, error)
	ReadPrefix(namespace, prefix string) (map[string][]byte, error)
	ReadAllKeys(namespace string) ([]string, error)
	Delete(namespace, key string) error
	DeleteNamespace(namespace string) error
	Update(namespace string, key string, values map[string]any) ([]byte, error)
	UpdateValueAndOperation(namespace, key string, updater Updater, opNamespace, opKey string, opUpdater ResponseSettingUpdater) (first, op []byte, err error)
}

// NewStorage returns the instance of the given storageProvider. If it doesn't exist, then a default implementation
// is created with the given option parameter.
func NewStorage(storageProvider Type, option interface{}) (ServiceStorage, error) {
	impl := GetStorage(storageProvider)
	if impl == nil {
		return impl, fmt.Errorf("unsupported storage provider: %s", storageProvider)
	}
	err := impl.Init(option)
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
