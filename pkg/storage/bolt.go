package storage

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tbd54566975/ssi-service/internal/util"
	bolt "go.etcd.io/bbolt"
)

func init() {
	err := RegisterStorage(&BoltDB{})
	if err != nil {
		panic(err)
	}
}

const (
	DBFilePrefix = "ssi-service"
)

type BoltDB struct {
	db *bolt.DB
}

// Init instantiates a file-based storage instance for Bolt https://github.com/boltdb/bolt
func (b *BoltDB) Init(options interface{}) error {
	if b.db != nil && b.IsOpen() {
		return fmt.Errorf("bolit db already opened with name %s", b.URI())
	}
	dbFilePath := fmt.Sprintf("%s_%s.db", DBFilePrefix, b.Type())
	if options != nil {
		customPath, ok := options.(string)
		if !ok {
			return fmt.Errorf("options should be a string value")
		}
		if customPath != "" {
			dbFilePath = customPath
		}
	}
	db, err := bolt.Open(dbFilePath, 0600, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		return err
	}
	b.db = db
	return nil
}

// URI return filepath of boltDB,
func (b *BoltDB) URI() string {
	return b.db.Path()
}

// IsOpen return if db was opened
func (b *BoltDB) IsOpen() bool {
	if b.db == nil {
		return false
	}
	return b.db.Path() != ""
}

func (b *BoltDB) Type() Type {
	return Bolt
}

func (b *BoltDB) Close() error {
	return b.db.Close()
}

func (b *BoltDB) Write(ctx context.Context, namespace string, key string, value []byte) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte(namespace))
		if err != nil {
			return err
		}
		if err = bucket.Put([]byte(key), value); err != nil {
			return err
		}
		return nil
	})
}

func (b *BoltDB) Read(ctx context.Context, namespace, key string) ([]byte, error) {
	var result []byte
	err := b.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(namespace))
		if bucket == nil {
			logrus.Infof("namespace<%s> does not exist", namespace)
			return nil
		}
		result = bucket.Get([]byte(key))
		return nil
	})
	return result, err
}

// ReadPrefix does a prefix query within a namespace.
func (b *BoltDB) ReadPrefix(ctx context.Context, namespace, prefix string) (map[string][]byte, error) {
	result := make(map[string][]byte)
	err := b.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(namespace))
		if bucket == nil {
			errMsg := fmt.Sprintf("namespace<%s> does not exist", namespace)
			logrus.Error(errMsg)
			return errors.New(errMsg)
		}
		cursor := bucket.Cursor()
		prefix := []byte(prefix)
		for k, v := cursor.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = cursor.Next() {
			result[string(k)] = v
		}
		return nil
	})
	return result, err
}

func (b *BoltDB) ReadAll(ctx context.Context, namespace string) (map[string][]byte, error) {
	result := make(map[string][]byte)
	err := b.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(namespace))
		if bucket == nil {
			logrus.Errorf("namespace<%s> does not exist", namespace)
			return nil
		}
		cursor := bucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			result[string(k)] = v
		}
		return nil
	})
	return result, err
}

func (b *BoltDB) ReadAllKeys(ctx context.Context, namespace string) ([]string, error) {
	var result []string
	err := b.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(namespace))
		if bucket == nil {
			return util.LoggingNewErrorf("namespace<%s> does not exist", namespace)
		}
		cursor := bucket.Cursor()
		for k, _ := cursor.First(); k != nil; k, _ = cursor.Next() {
			result = append(result, string(k))
		}
		return nil
	})
	return result, err
}

func (b *BoltDB) Delete(ctx context.Context, namespace, key string) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(namespace))
		if bucket == nil {
			return util.LoggingNewErrorf("namespace<%s> does not exist", namespace)
		}
		return bucket.Delete([]byte(key))
	})
}

func (b *BoltDB) DeleteNamespace(ctx context.Context, namespace string) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		if err := tx.DeleteBucket([]byte(namespace)); err != nil {
			return util.LoggingErrorMsgf(err, "could not delete namespace<%s>", namespace)
		}
		return nil
	})
}

// UpdaterWithMap is a json map based Updater implementation. The key/values from the map are used to update the
// unmarshalled JSON representation of the stored data.
type UpdaterWithMap struct {
	Values map[string]any
}

// Validate is a default implementation for UpdaterWithMap which does no validation. Users can pass embed UpdaterWithMap
// into a custom struct and redefine this method in order to have custom logic.
func (u UpdaterWithMap) Validate(_ []byte) error {
	return nil
}

// NewUpdater creates a new UpdaterWithMap with the given map.
func NewUpdater(values map[string]any) UpdaterWithMap {
	return UpdaterWithMap{
		Values: values,
	}
}

func (u UpdaterWithMap) Update(v []byte) ([]byte, error) {
	var model map[string]any
	if err := json.Unmarshal(v, &model); err != nil {
		return nil, errors.Wrap(err, "unmarshalling json")
	}
	for k, val := range u.Values {
		model[k] = val
	}
	data, err := json.Marshal(model)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling updated struct")
	}
	return data, nil
}

// Updater encapsulates the Update method, which take a slice of bytes, and updates it before it's stored in the DB.
type Updater interface {
	Update(v []byte) ([]byte, error)
	// Validate runs after the data has been loaded from disk, but before the write is actually performed.
	Validate(v []byte) error
}

type ResponseSettingUpdater interface {
	Updater
	// SetUpdatedResponse sets the response that the Update method will later use to modify the data.
	SetUpdatedResponse([]byte)
}

// UpdateValueAndOperation updates the value stored in (namespace,key) with the new values specified in the map.
// The updated value is then stored inside the (opNamespace, opKey), and the "done" value is set to true.
func (b *BoltDB) UpdateValueAndOperation(ctx context.Context, namespace, key string, updater Updater, opNamespace, opKey string, opUpdater ResponseSettingUpdater) (first, op []byte, err error) {
	err = b.db.Update(func(tx *bolt.Tx) error {
		if err := updateTxFn(namespace, key, updater, &first)(tx); err != nil {
			return err
		}
		opUpdater.SetUpdatedResponse(first)
		if err = updateTxFn(opNamespace, opKey, opUpdater, &op)(tx); err != nil {
			return err
		}
		return nil
	})
	return first, op, err
}

func (b *BoltDB) Update(ctx context.Context, namespace string, key string, values map[string]any) ([]byte, error) {
	var updatedData []byte
	err := b.db.Update(updateTxFn(namespace, key, NewUpdater(values), &updatedData))
	return updatedData, err
}

func updateTxFn(namespace string, key string, updater Updater, updatedData *[]byte) func(tx *bolt.Tx) error {
	return func(tx *bolt.Tx) error {
		data, err := updateTx(tx, namespace, key, updater)
		if err != nil {
			return err
		}
		*updatedData = data
		return nil
	}
}

func updateTx(tx *bolt.Tx, namespace string, key string, updater Updater) ([]byte, error) {
	bucket := tx.Bucket([]byte(namespace))
	if bucket == nil {
		return nil, util.LoggingNewErrorf("namespace<%s> does not exist", namespace)
	}
	v := bucket.Get([]byte(key))
	if v == nil {
		return nil, util.LoggingNewErrorf("key not found %s", key)
	}
	if err := updater.Validate(v); err != nil {
		return nil, util.LoggingErrorMsg(err, "validating update")
	}
	data, err := updater.Update(v)
	if err != nil {
		return nil, err
	}
	if err = bucket.Put([]byte(key), data); err != nil {
		return nil, errors.Wrap(err, "writing to db")
	}
	return data, nil
}

// MakeNamespace takes a set of possible namespace values and combines them as a convention
func MakeNamespace(ns ...string) string {
	return strings.Join(ns, "-")
}
