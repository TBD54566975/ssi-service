package storage

// ServiceStorage describes the api for storage independent of DB providers
type ServiceStorage interface {
	Close() error
	Write(namespace, key string, value []byte) error
	Read(namespace, key string) ([]byte, error)
	ReadAll(namespace string) (map[string][]byte, error)
	Delete(namespace, key string) error
	DeleteNamespace(namespace string) error
}
