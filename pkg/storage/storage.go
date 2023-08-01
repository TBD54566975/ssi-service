package storage

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/pkg/errors"
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
	Bolt        Type = "bolt"
	DatabaseSQL Type = "database_sql"
	Redis       Type = "redis"

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

	// ReadPage returns a page of elements. When pageSize == -1, all elements are returned. Results are returned
	// starting from the pageToken. pageToken may be empty.
	// Note that pageSize is a hint and may not be enforced by the DB implementation. This is intentional, as some DBs
	// do not have a way to enforce this (e.g. Redis), and the DB may decide to return everything in some cases. A more
	// detailed explanation is available at https://redis.io/commands/scan/, section
	// "Why SCAN may return all the items of an aggregate data type in a single call?".
	ReadPage(ctx context.Context, namespace string, pageToken string, pageSize int) (results map[string][]byte, nextPageToken string, err error)
	ReadPrefix(ctx context.Context, namespace, prefix string) (map[string][]byte, error)
	ReadAllKeys(ctx context.Context, namespace string) ([]string, error)
	Delete(ctx context.Context, namespace, key string) error
	DeleteNamespace(ctx context.Context, namespace string) error
	Execute(ctx context.Context, businessLogicFunc BusinessLogicFunc, watchKeys []WatchKey) (any, error)
}

// NewStorage returns the instance of the given storageProvider. If it doesn't exist, then a default implementation
// is created with the given option parameter.
func NewStorage(storageProvider Type, opts ...Option) (ServiceStorage, error) {
	impl := GetStorage(storageProvider)
	if impl == nil {
		return impl, fmt.Errorf("unsupported storage provider: %s", storageProvider)
	}
	logrus.Infof("Storage options: %+v", opts)
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

// Join combines all parts using `:` as the separator.
func Join(parts ...string) string {
	const separator = ":"
	return strings.Join(parts, separator)
}

// MakeNamespace takes a set of possible namespace values and combines them as a convention
func MakeNamespace(ns ...string) string {
	return strings.Join(ns, "-")
}

// UpdateValueAndOperation updates the value stored in (namespace,key) with the new values specified in the map.
// The updated value is then stored inside the (opNamespace, opKey), and the "done" value is set to true.
func UpdateValueAndOperation(ctx context.Context, s ServiceStorage, namespace, key string, updater Updater, opNamespace, opKey string, opUpdater ResponseSettingUpdater) (first, op []byte, err error) {
	type pair struct {
		first  []byte
		second []byte
	}
	watchKeys := []WatchKey{
		{
			Namespace: namespace,
			Key:       key,
		},
		{
			Namespace: opNamespace,
			Key:       opKey,
		},
	}
	exec, err := s.Execute(ctx, func(ctx context.Context, tx Tx) (any, error) {
		first, err = update(ctx, s, tx, namespace, key, updater)
		if err != nil {
			return nil, err
		}
		opUpdater.SetUpdatedResponse(first)
		op, err = update(ctx, s, tx, opNamespace, opKey, opUpdater)
		if err != nil {
			return nil, err
		}
		return &pair{first: first, second: op}, err
	}, watchKeys)
	if err != nil {
		return nil, nil, err
	}
	execPair := exec.(*pair)
	return execPair.first, execPair.second, nil
}

func Update(ctx context.Context, s ServiceStorage, namespace, key string, m map[string]any) ([]byte, error) {
	watchKeys := []WatchKey{
		{
			Namespace: namespace,
			Key:       key,
		},
	}
	exec, err := s.Execute(ctx, func(ctx context.Context, tx Tx) (any, error) {
		return update(ctx, s, tx, namespace, key, NewUpdater(m))
	}, watchKeys)
	if err != nil {
		return nil, err
	}
	execBytes := exec.([]byte)
	return execBytes, nil
}

func update(ctx context.Context, s ServiceStorage, tx Tx, namespace, key string, updater Updater) ([]byte, error) {
	readData, err := s.Read(ctx, namespace, key)
	if err != nil {
		return nil, err
	}
	if err = updater.Validate(readData); err != nil {
		return nil, errors.Wrap(err, "validating update")
	}
	updatedData, err := updater.Update(readData)
	if err != nil {
		return nil, err
	}
	if err = tx.Write(ctx, namespace, key, updatedData); err != nil {
		return nil, errors.Wrap(err, "writing to db")
	}
	return updatedData, nil
}
