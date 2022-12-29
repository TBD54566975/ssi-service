package storage

import (
	"context"
	"fmt"
	"strings"

	goredislib "github.com/go-redis/redis/v8"
	"github.com/go-redsync/redsync/v4"
	"github.com/go-redsync/redsync/v4/redis/goredis/v8"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	NamespaceKeySeparator = ":"
	Pong                  = "PONG"
	RedisScanBatchSize    = 1000
	RedisMutex            = "redis-mutex"
)

func init() {
	err := RegisterStorage(&RedisDB{})
	if err != nil {
		panic(err)
	}
}

type RedisDB struct {
	db    *goredislib.Client
	ctx   context.Context
	mutex *redsync.Mutex
}

func (b *RedisDB) Init(i interface{}) error {
	options := i.(map[string]interface{})

	client := goredislib.NewClient(&goredislib.Options{
		Addr:     options["address"].(string),
		Password: options["password"].(string),
	})

	pool := goredis.NewPool(client)
	rs := redsync.New(pool)

	b.db = client
	b.mutex = rs.NewMutex(RedisMutex)
	b.ctx = context.Background()

	return nil
}

func (b *RedisDB) URI() string {
	return b.db.Options().Addr
}

func (b *RedisDB) IsOpen() bool {
	pong, err := b.db.Ping(b.ctx).Result()
	if err != nil {
		logrus.Error(err)
		return false
	}

	return pong == Pong
}

func (b *RedisDB) Type() Type {
	return Redis
}

func (b *RedisDB) Close() error {
	return b.db.Close()
}

func (b *RedisDB) Write(namespace, key string, value []byte) error {
	nameSpaceKey := getRedisKey(namespace, key)
	// Zero expiration means the key has no expiration time.
	return b.db.Set(b.ctx, nameSpaceKey, value, 0).Err()
}

func (b *RedisDB) WriteMany(namespaces, keys []string, values [][]byte) error {
	if len(namespaces) != len(keys) && len(namespaces) != len(values) {
		return errors.New("namespaces, keys, and values, are not of equal length")
	}

	nameSpaceKeys := make([]string, 0)
	for i := range namespaces {
		nameSpaceKeys = append(nameSpaceKeys, getRedisKey(namespaces[i], keys[i]))
	}

	return b.db.MSet(b.ctx, nameSpaceKeys, values, 0).Err()
}

func (b *RedisDB) Read(namespace, key string) ([]byte, error) {
	nameSpaceKey := getRedisKey(namespace, key)
	res, err := b.db.Get(b.ctx, nameSpaceKey).Bytes()

	// Nil reply returned by Redis when key does not exist.
	if errors.Is(err, goredislib.Nil) {
		return res, nil
	}

	return res, err
}

func (b *RedisDB) ReadPrefix(namespace, prefix string) (map[string][]byte, error) {
	namespacePrefix := getRedisKey(namespace, prefix)

	keys, err := readAllKeys(namespacePrefix, b)
	if err != nil {
		return nil, errors.Wrap(err, "read all keys")
	}

	return readAll(keys, b)
}

func (b *RedisDB) ReadAll(namespace string) (map[string][]byte, error) {
	keys, err := readAllKeys(namespace, b)
	if err != nil {
		return nil, errors.Wrap(err, "read all keys")
	}

	return readAll(keys, b)
}

// TODO: This potentially could dangerous as it might run out of memory as we populate result
func readAll(keys []string, b *RedisDB) (map[string][]byte, error) {
	result := make(map[string][]byte, len(keys))

	if len(keys) == 0 {
		return nil, nil
	}

	values, err := b.db.MGet(b.ctx, keys...).Result()
	if err != nil {
		return nil, errors.Wrap(err, "getting multiple keys")
	}

	if len(keys) != len(values) {
		return nil, errors.New("key length does not match value length")
	}

	// result needs to take the namespace out of the key
	namespaceDashIndex := strings.Index(keys[0], NamespaceKeySeparator)
	for i, val := range values {
		byteValue := []byte(fmt.Sprintf("%v", val))
		key := keys[i][namespaceDashIndex+1:]
		result[key] = byteValue
	}

	return result, nil
}

func (b *RedisDB) ReadAllKeys(namespace string) ([]string, error) {
	keys, err := readAllKeys(namespace, b)
	if err != nil {
		return nil, err
	}

	if len(keys) == 0 {
		return make([]string, 0), nil
	}

	namespaceDashIndex := strings.Index(keys[0], NamespaceKeySeparator)
	for i, key := range keys {
		keyWithoutNamespace := key[namespaceDashIndex+1:]
		keys[i] = keyWithoutNamespace
	}

	return keys, nil
}

// TODO: This potentially could dangerous as it might run out of memory as we populate allKeys
func readAllKeys(namespace string, b *RedisDB) ([]string, error) {
	var cursor uint64

	var allKeys []string

	for {
		keys, nextCursor, err := b.db.Scan(b.ctx, cursor, namespace+"*", RedisScanBatchSize).Result()
		if err != nil {
			return nil, errors.Wrap(err, "scan error")
		}

		allKeys = append(allKeys, keys...)

		if nextCursor == 0 {
			break
		}

		cursor = nextCursor
	}

	return allKeys, nil
}

func (b *RedisDB) Delete(namespace, key string) error {
	nameSpaceKey := getRedisKey(namespace, key)

	if !namespaceExists(namespace, b) {
		return errors.Errorf("namespace<%s> does not exist", namespace)
	}

	res, err := b.db.GetDel(b.ctx, nameSpaceKey).Result()
	if res == "" {
		return errors.Wrapf(err, "key<%s> and namespace<%s> does not exist", key, namespace)
	}

	return err

}

func (b *RedisDB) DeleteNamespace(namespace string) error {
	keys, err := readAllKeys(namespace, b)
	if err != nil {
		return errors.Wrap(err, "read all keys")
	}

	if len(keys) == 0 {
		return errors.Errorf("could not delete namespace<%s>, namespace does not exist", namespace)
	}

	return b.db.Del(b.ctx, keys...).Err()
}

func (b *RedisDB) Update(namespace string, key string, values map[string]any) ([]byte, error) {
	updatedData, err := txWithUpdater(namespace, key, NewUpdater(values), b)
	return updatedData, err
}

func (b *RedisDB) UpdateValueAndOperation(namespace, key string, updater Updater, opNamespace, opKey string, opUpdater ResponseSettingUpdater) (first, op []byte, err error) {
	if err := b.mutex.Lock(); err != nil {
		return nil, nil, errors.Wrap(err, "cannot obtain mutex lock")
	}
	defer func() {
		ok, unlockErr := b.mutex.Unlock()
		if !ok || unlockErr != nil {
			logrus.Error(unlockErr)
		}
	}()

	// The Pipeliner interface provided by the go-redis library guarantees that all the commands queued in the pipeline will either succeed or fail together.
	_, err = b.db.TxPipelined(b.ctx, func(pipe goredislib.Pipeliner) error {

		firstTx, err := txWithUpdater(namespace, key, updater, b)
		if err != nil {
			return err
		}

		opUpdater.SetUpdatedResponse(firstTx)
		secondTx, err := txWithUpdater(opNamespace, opKey, opUpdater, b)
		if err != nil {
			return err
		}

		first = firstTx
		op = secondTx

		return nil
	})

	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to execute transaction")
	}

	return first, op, err
}

func txWithUpdater(namespace, key string, updater Updater, b *RedisDB) ([]byte, error) {
	nameSpaceKey := getRedisKey(namespace, key)
	v, err := b.db.Get(b.ctx, nameSpaceKey).Bytes()
	if err != nil {
		return nil, errors.Wrapf(err, "get error with namespace: %s key: %s", namespace, key)
	}
	if v == nil {
		return nil, errors.Errorf("key not found %s", key)
	}
	if err := updater.Validate(v); err != nil {
		return nil, errors.Wrapf(err, "validating update")
	}

	data, err := updater.Update(v)
	if err != nil {
		return nil, err
	}

	if err = b.db.Set(b.ctx, nameSpaceKey, data, 0).Err(); err != nil {
		return nil, errors.Wrap(err, "writing to db")
	}

	return data, nil
}

func getRedisKey(namespace, key string) string {
	return namespace + NamespaceKeySeparator + key
}

func namespaceExists(namespace string, b *RedisDB) bool {
	keys, _ := b.db.Scan(b.ctx, 0, namespace+"*", RedisScanBatchSize).Val()

	if len(keys) == 0 {
		return false
	}

	return true
}
