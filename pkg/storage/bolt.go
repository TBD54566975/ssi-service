package storage

import (
	"fmt"
	"github.com/boltdb/bolt"
	"github.com/pkg/errors"
	"strings"
	"time"
)

const (
	DBFile = "ssi-service.db"
)

type BoltDB struct {
	db *bolt.DB
}

// NewBoltDB instantiates a file-based storage instance for Bolt https://github.com/boltdb/bolt
func NewBoltDB() (*BoltDB, error) {
	return NewBoltDBWithFile(DBFile)
}

func NewBoltDBWithFile(filePath string) (*BoltDB, error) {
	db, err := bolt.Open(filePath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, err
	}
	return &BoltDB{db: db}, nil
}

func (b *BoltDB) Close() error {
	return b.db.Close()
}

func (b *BoltDB) Write(namespace string, key string, value []byte) error {
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

func (b *BoltDB) Read(namespace, key string) ([]byte, error) {
	var result []byte
	err := b.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(namespace))
		if bucket == nil {
			return fmt.Errorf("namespace<%s> does not exist", namespace)
		}
		result = bucket.Get([]byte(key))
		return nil
	})
	return result, err
}

func (b *BoltDB) ReadAll(namespace string) (map[string][]byte, error) {
	result := make(map[string][]byte)
	err := b.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(namespace))
		if bucket == nil {
			return fmt.Errorf("namespace<%s> does not exist", namespace)
		}
		cursor := bucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			result[string(k)] = v
		}
		return nil
	})
	return result, err
}

func (b *BoltDB) Delete(namespace, key string) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(namespace))
		if bucket == nil {
			return fmt.Errorf("namespace<%s> does not exist", namespace)
		}
		return bucket.Delete([]byte(key))
	})
}

func (b *BoltDB) DeleteNamespace(namespace string) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		if err := tx.DeleteBucket([]byte(namespace)); err != nil {
			return errors.Wrapf(err, "could not delete namespace<%s>, n", namespace)
		}
		return nil
	})
}

// MakeNamespace takes a set of possible namespace values and combines them as a convention
func MakeNamespace(ns ...string) string {
	return strings.Join(ns, "-")
}
