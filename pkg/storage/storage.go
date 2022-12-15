package storage

import (
	"fmt"
	"reflect"
)

type Storage string

const (
	Bolt Storage = "bolt"
)

var (
	availableStorages = make(map[Storage]ServiceStorage)
)

// ServiceStorage describes the api for storage independent of DB providers
type ServiceStorage interface {
	Init(interface{}) error
	Type() Storage
	URI() string
	IsOpen() bool
	Close() error
	Write(namespace, key string, value []byte) error
	Read(namespace, key string) ([]byte, error)
	ReadAll(namespace string) (map[string][]byte, error)
	ReadPrefix(namespace, prefix string) (map[string][]byte, error)
	ReadAllKeys(namespace string) ([]string, error)
	Delete(namespace, key string) error
	DeleteNamespace(namespace string) error
	Update(namespace string, key string, values map[string]any) ([]byte, error)
	UpdateValueAndOperation(namespace, key string, updater Updater, opNamespace, opKey string, opUpdater ResponseSettingUpdater) (first, op []byte, err error)
}

// NewStorage creates a new or use exists storage provider and provider specify param based on the input
func NewStorage(storageProvider Storage, option interface{}) (ServiceStorage, error) {
	impl := GetStorage(storageProvider)
	if impl == nil {
		return impl, fmt.Errorf("unsupported storage provider: %s", storageProvider)
	}
	err := impl.Init(option)
	return impl, err
}

// RegisterStorage resister a storage dynamically
func RegisterStorage(storage ServiceStorage) error {
	if availableStorages[storage.Type()] != nil {
		return fmt.Errorf("storage implementation for %s already exists", storage.Type())
	}
	availableStorages[storage.Type()] = storage
	return nil
}

// AvailableStorage returns the supported storage providers
func AvailableStorage() []Storage {
	return []Storage{Bolt}
}

// IsStorageAvailable determines whether a given storage provider is available for instantiation
func IsStorageAvailable(storage string) bool {
	all := AvailableStorage()
	for _, s := range all {
		if storage == string(s) {
			return true
		}
	}
	return false
}

// GetStorage create a new storage by stroage type
func GetStorage(storageType Storage) ServiceStorage {
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
