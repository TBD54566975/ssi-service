package storage

import (
	"fmt"
)

type Storage string

const (
	Bolt Storage = "bolt"
)

// ServiceStorage describes the api for storage independent of DB providers
type ServiceStorage interface {
	Type() Storage
	Close() error
	Write(namespace, key string, value []byte) error
	Read(namespace, key string) ([]byte, error)
	ReadAll(namespace string) (map[string][]byte, error)
	Delete(namespace, key string) error
	DeleteNamespace(namespace string) error
}

// NewStorage creates a new storage provider based on the input
func NewStorage(storageProvider Storage) (ServiceStorage, error) {
	switch storageProvider {
	case Bolt:
		return NewBoltDB()
	default:
		return nil, fmt.Errorf("unsupported storage provider: %s", storageProvider)
	}
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
