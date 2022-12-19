package storage

import (
	"context"
	"fmt"

	goredislib "github.com/go-redis/redis/v8"
	"github.com/go-redsync/redsync/v4"
	"github.com/go-redsync/redsync/v4/redis/goredis/v8"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	PONG               = "PONG"
	RedisScanBatchSize = 1000
	RedisMutex         = "redis-mutex"
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

	if options["flush"].(bool) {
		err := b.db.FlushAll(b.ctx).Err()
		if err != nil {
			return err
		}
	}

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

	return pong == PONG
}

func (b *RedisDB) Type() Type {
	return Redis
}

func (b *RedisDB) Close() error {
	return b.db.Close()
}

func (b *RedisDB) Write(namespace, key string, value []byte) error {
	nameSpaceKey := getRedisKey(namespace, key)

	if err := b.mutex.Lock(); err != nil {
		return errors.Wrap(err, "cannot obtain mutex lock")
	}
	defer func() {
		ok, unlockErr := b.mutex.Unlock()
		if !ok || unlockErr != nil {
			logrus.Error(unlockErr)
		}
	}()

	// Zero expiration means the key has no expiration time.
	return b.db.Set(b.ctx, nameSpaceKey, value, 0).Err()
}

// TODO Add this to interface and replace UpdateValueAndOperation with this
func (b *RedisDB) WriteMany(namespaces, keys []string, values [][]byte) error {
	if len(namespaces) != len(keys) && len(namespaces) != len(values) {
		return errors.New("namespaces, keys, and values, are not of equal length")
	}

	if err := b.mutex.Lock(); err != nil {
		return errors.Wrap(err, "cannot obtain mutex lock")
	}
	defer func() {
		ok, unlockErr := b.mutex.Unlock()
		if !ok || unlockErr != nil {
			logrus.Error(unlockErr)
		}
	}()

	// The Pipeliner interface provided by the go-redis library guarantees that all the commands queued in the pipeline will either succeed or fail together.
	_, err := b.db.TxPipelined(b.ctx, func(pipe goredislib.Pipeliner) error {
		for i := range namespaces {
			namespace := namespaces[i]
			key := keys[i]
			value := values[i]

			nameSpaceKey := getRedisKey(namespace, key)
			err := pipe.Set(b.ctx, nameSpaceKey, value, 0).Err()
			if err != nil {
				return err
			}
		}

		return nil
	})

	return err
}

func (b *RedisDB) Read(namespace, key string) ([]byte, error) {
	nameSpaceKey := getRedisKey(namespace, key)
	return b.db.Get(b.ctx, nameSpaceKey).Bytes()
}

func (b *RedisDB) ReadPrefix(namespace, prefix string) (map[string][]byte, error) {
	namespacePrefix := getRedisKey(namespace, prefix)

	keys, err := readAllKeys(namespacePrefix, b)
	if err != nil {
		return nil, errors.Wrap(err, "read all keys error")
	}

	return readAll(keys, b)
}

func (b *RedisDB) ReadAll(namespace string) (map[string][]byte, error) {
	keys, err := readAllKeys(namespace, b)
	if err != nil {
		return nil, errors.Wrap(err, "read all keys error")
	}

	return readAll(keys, b)
}

// TODO: This potentially could dangerous as it might run out of memory as we populate result
func readAll(keys []string, b *RedisDB) (map[string][]byte, error) {
	result := make(map[string][]byte)

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

	for i, val := range values {
		byteValue := []byte(fmt.Sprintf("%v", val))
		key := keys[i]
		result[key] = byteValue
	}

	return result, nil
}

func (b *RedisDB) ReadAllKeys(namespace string) ([]string, error) {
	return readAllKeys(namespace, b)
}

// TODO: This potentially could dangerous as it might run out of memory as we populate allKeys
func readAllKeys(match string, b *RedisDB) ([]string, error) {
	var cursor uint64

	allKeys := make([]string, 0)

	for {
		keys, nextCursor, err := b.db.Scan(b.ctx, cursor, match+"*", RedisScanBatchSize).Result()
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

	if err := b.mutex.Lock(); err != nil {
		return errors.Wrap(err, "locking")
	}
	defer func() {
		ok, unlockErr := b.mutex.Unlock()
		if !ok || unlockErr != nil {
			logrus.Error(unlockErr)
		}
	}()

	return b.db.Del(b.ctx, nameSpaceKey).Err()
}

func (b *RedisDB) DeleteNamespace(namespace string) error {
	keys, err := readAllKeys(namespace, b)
	if err != nil {
		return errors.Wrap(err, "read all keys")
	}

	if err := b.mutex.Lock(); err != nil {
		return errors.Wrap(err, "cannot obtain mutex lock")
	}
	defer func() {
		ok, unlockErr := b.mutex.Unlock()
		if !ok || unlockErr != nil {
			logrus.Error(unlockErr)
		}
	}()

	return b.db.Del(b.ctx, keys...).Err()
}

// TODO: Implement
func (b *RedisDB) Update(namespace string, key string, values map[string]any) ([]byte, error) {
	panic("implement me")
}

// TODO Implement
func (b *RedisDB) UpdateValueAndOperation(namespace, key string, updater Updater, opNamespace, opKey string, opUpdater ResponseSettingUpdater) (first, op []byte, err error) {
	panic("implement me")
}

func getRedisKey(namespace, key string) string {
	return fmt.Sprintf("%s-%s", namespace, key)
}
