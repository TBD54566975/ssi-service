package storage

type Storage string

const (
	Bolt Storage = "bolt"
)

// ServiceStorage describes the api for storage independent of DB providers
type ServiceStorage interface {
	Close() error
	Write(namespace, key string, value []byte) error
	Read(namespace, key string) ([]byte, error)
	ReadAll(namespace string) (map[string][]byte, error)
	Delete(namespace, key string) error
	DeleteNamespace(namespace string) error
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
