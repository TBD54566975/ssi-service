package storage

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/alicebob/miniredis/v2"
	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tbd54566975/ssi-service/pkg/encryption"
)

func getDBImplementations(t *testing.T) []ServiceStorage {
	dbImpls := make([]ServiceStorage, 0)

	boltDB := setupBoltDB(t)
	dbImpls = append(dbImpls, boltDB)

	redisDB := setupRedisDB(t)
	dbImpls = append(dbImpls, redisDB)

	postgresDB := setupPostgresDB(t)
	dbImpls = append(dbImpls, postgresDB)

	key := make([]byte, 32)
	dbImpls = append(dbImpls, NewEncryptedWrapper(
		boltDB,
		encryption.NewXChaCha20Poly1305EncrypterWithKey(key),
		encryption.NewXChaCha20Poly1305EncrypterWithKey(key),
	))

	return dbImpls
}

func setupBoltDB(t *testing.T) *BoltDB {
	dbName := "test.db"
	db, err := NewStorage(Bolt, Option{
		ID:     BoltDBFilePathOption,
		Option: dbName,
	})
	assert.NoError(t, err)
	assert.NotEmpty(t, db)

	t.Cleanup(func() {
		_ = db.Close()
		_ = os.Remove(dbName)
	})
	return db.(*BoltDB)
}

func setupPostgresDB(t *testing.T) *SQLDB {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	scalar := make([]byte, 32)
	_, err = rand.Read(scalar)
	require.NoError(t, err)

	randomDir := strconv.Itoa(int(binary.BigEndian.Uint32(scalar)))
	postgres := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		BinariesPath(filepath.Join(homeDir, ".embedded-postgres-go", "tmpBin")).
		DataPath(filepath.Join(os.TempDir(), ".embedded-postgres-go", "data", randomDir)).
		RuntimePath(filepath.Join(os.TempDir(), ".embedded-postgres-go", "runtime", randomDir)))
	err = postgres.Start()
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = postgres.Stop()
	})

	options := []Option{
		{
			ID:     SQLConnectionString,
			Option: "host=localhost port=5432 user=postgres password=postgres dbname=postgres sslmode=disable",
		},
		{
			ID:     SQLDriverName,
			Option: "postgres",
		},
	}
	s, err := NewStorage(DatabaseSQL, options...)
	require.NoError(t, err)
	return s.(*SQLDB)
}

func setupRedisDB(t *testing.T) *RedisDB {
	server := miniredis.RunT(t)
	options := []Option{
		{
			ID:     RedisAddressOption,
			Option: server.Addr(),
		},
		{
			ID:     PasswordOption,
			Option: "test-password",
		},
	}
	db, err := NewStorage(Redis, options...)
	assert.NoError(t, err)
	assert.NotEmpty(t, db)

	t.Cleanup(func() {
		_ = db.Close()
	})

	return db.(*RedisDB)
}

func TestDB(t *testing.T) {
	for _, dbImpl := range getDBImplementations(t) {
		db := dbImpl

		// create a name space and a message in it
		namespace := "F1"

		team1 := "Red Bull"
		players1 := []string{"Max Verstappen", "Sergio Pérez"}
		p1Bytes, err := json.Marshal(players1)
		assert.NoError(t, err)

		err = db.Write(context.Background(), namespace, team1, p1Bytes)
		assert.NoError(t, err)

		// get it back
		gotPlayers1, err := db.Read(context.Background(), namespace, team1)
		assert.NoError(t, err)

		var players1Result []string
		err = json.Unmarshal(gotPlayers1, &players1Result)
		assert.NoError(t, err)
		assert.EqualValues(t, players1, players1Result)

		// get a value from a namespace that doesn't exist
		res, err := db.Read(context.Background(), "bad", "worse")
		assert.NoError(t, err)
		assert.Empty(t, res)

		// get a value that doesn't exist in the namespace
		noValue, err := db.Read(context.Background(), namespace, "Porsche")
		assert.NoError(t, err)
		assert.Empty(t, noValue)

		// create a second value in the namespace
		team2 := "McLaren"
		players2 := []string{"Lando Norris", "Daniel Ricciardo"}
		p2Bytes, err := json.Marshal(players2)
		assert.NoError(t, err)

		err = db.Write(context.Background(), namespace, team2, p2Bytes)
		assert.NoError(t, err)

		// get all values from the namespace
		gotAll, err := db.ReadAll(context.Background(), namespace)
		assert.NoError(t, err)
		assert.True(t, len(gotAll) == 2)

		_, gotRedBull := gotAll[team1]
		assert.True(t, gotRedBull)

		_, gotMcLaren := gotAll[team2]
		assert.True(t, gotMcLaren)

		// delete value in the namespace
		err = db.Delete(context.Background(), namespace, team2)
		assert.NoError(t, err)

		gotPlayers2, err := db.Read(context.Background(), namespace, team2)
		assert.NoError(t, err)
		assert.Empty(t, gotPlayers2)

		// delete value in a namespace that doesn't exist
		err = db.Delete(context.Background(), "bad", team2)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "namespace<bad> does not exist")

		// delete a namespace that doesn't exist
		err = db.DeleteNamespace(context.Background(), "bad")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "could not delete namespace<bad>")

		// delete namespace
		err = db.DeleteNamespace(context.Background(), namespace)
		assert.NoError(t, err)

		res, err = db.Read(context.Background(), namespace, team1)
		assert.NoError(t, err)
		assert.Empty(t, res)
	}
}

func TestDBWriteMany(t *testing.T) {
	for _, dbImpl := range getDBImplementations(t) {
		db := dbImpl

		namespace := "blockchains"
		dummyData := []byte("dummy")
		var ns []string
		var keys []string
		var datas [][]byte
		for i := 0; i < 200; i++ {
			ns = append(ns, namespace)
			keys = append(keys, fmt.Sprintf("key-%d", i))
			datas = append(datas, dummyData)
		}
		err := db.WriteMany(context.Background(), ns, keys, datas)
		assert.NoError(t, err)

		results, err := db.ReadAll(context.Background(), namespace)
		assert.NoError(t, err)
		assert.Len(t, results, 200)
	}
}
func TestDBReadPage(t *testing.T) {
	for _, dbImpl := range getDBImplementations(t) {
		db := dbImpl

		namespace := "blockchains"

		dummyData := []byte("dummy")
		err := db.Write(context.Background(), namespace, "bitcoin-testnet", dummyData)
		assert.NoError(t, err)

		err = db.Write(context.Background(), namespace, "bitcoin-mainnet", dummyData)
		assert.NoError(t, err)

		err = db.Write(context.Background(), namespace, "tezos-testnet", dummyData)
		assert.NoError(t, err)

		t.Run(string(db.Type())+" returns all elements when page size is -1", func(t *testing.T) {
			results, nextToken, err := db.ReadPage(context.Background(), namespace, "", -1)
			assert.NoError(t, err)
			assert.Len(t, results, 3)
			assert.Empty(t, nextToken)
		})

		t.Run(string(db.Type())+" returns pageSize elements", func(t *testing.T) {
			if db.Type() == Redis {
				t.Skip("redis can return more than COUNT elements")
			}
			results, nextToken, err := db.ReadPage(context.Background(), namespace, "", 2)
			assert.NoError(t, err)
			assert.Len(t, results, 2)
			assert.NotEmpty(t, nextToken)
		})

		t.Run(string(db.Type())+" pagination works", func(t *testing.T) {
			if db.Type() == Redis {
				t.Skip("miniredis doesn't support scanning with count")
			}

			results, nextToken, err := db.ReadPage(context.Background(), namespace, "", 2)
			assert.NoError(t, err)
			assert.Len(t, results, 2)
			assert.NotEmpty(t, nextToken)

			results, nextToken, err = db.ReadPage(context.Background(), namespace, nextToken, 2)
			assert.NoError(t, err)
			assert.Len(t, results, 1)
			assert.Empty(t, nextToken)
		})
	}
}

func TestDBPrefixAndKeys(t *testing.T) {
	for _, dbImpl := range getDBImplementations(t) {
		db := dbImpl

		namespace := "blockchains"

		// set up prefix read test

		dummyData := []byte("dummy")
		err := db.Write(context.Background(), namespace, "bitcoin-testnet", dummyData)
		assert.NoError(t, err)

		err = db.Write(context.Background(), namespace, "bitcoin-mainnet", dummyData)
		assert.NoError(t, err)

		err = db.Write(context.Background(), namespace, "tezos-testnet", dummyData)
		assert.NoError(t, err)

		err = db.Write(context.Background(), namespace, "tezos-mainnet", dummyData)
		assert.NoError(t, err)

		prefixValues, err := db.ReadPrefix(context.Background(), namespace, "bitcoin")
		assert.NoError(t, err)
		assert.Len(t, prefixValues, 2)

		keys := make([]string, 0, len(prefixValues))
		for k := range prefixValues {
			keys = append(keys, k)
		}
		assert.Contains(t, keys, "bitcoin-testnet")
		assert.Contains(t, keys, "bitcoin-mainnet")

		// read all keys
		allKeys, err := db.ReadAllKeys(context.Background(), namespace)

		assert.NoError(t, err)
		assert.NotEmpty(t, allKeys)
		assert.Len(t, allKeys, 4)
		assert.Contains(t, allKeys, "bitcoin-mainnet")
		assert.Contains(t, allKeys, "tezos-mainnet")
	}
}

func TestDBReadAllKeysForNamespace(t *testing.T) {
	for _, dbImpl := range getDBImplementations(t) {
		db := dbImpl

		namespaceOne := "blockchains-orange"
		namespaceTwo := "blockchains-grey"

		// set up prefix read test

		dummyData := []byte("dummy")
		err := db.Write(context.Background(), namespaceOne, "bitcoin-testnet", dummyData)
		assert.NoError(t, err)

		err = db.Write(context.Background(), namespaceOne, "bitcoin-mainnet", dummyData)
		assert.NoError(t, err)

		err = db.Write(context.Background(), namespaceTwo, "eth-testnet", dummyData)
		assert.NoError(t, err)

		err = db.Write(context.Background(), namespaceTwo, "eth-mainnet", dummyData)
		assert.NoError(t, err)

		// read all keys
		allKeys, err := db.ReadAllKeys(context.Background(), namespaceOne)

		assert.NoError(t, err)
		assert.NotEmpty(t, allKeys)
		assert.Len(t, allKeys, 2)
		assert.Contains(t, allKeys, "bitcoin-testnet")
		assert.Contains(t, allKeys, "bitcoin-mainnet")

		// read all keys
		allKeys, err = db.ReadAllKeys(context.Background(), namespaceTwo)

		assert.NoError(t, err)
		assert.NotEmpty(t, allKeys)
		assert.Len(t, allKeys, 2)
		assert.Contains(t, allKeys, "eth-testnet")
		assert.Contains(t, allKeys, "eth-mainnet")
	}
}

func TestDBEmptyNamespace(t *testing.T) {
	for _, dbImpl := range getDBImplementations(t) {
		db := dbImpl

		namespace := "dne"
		key := "doesnotexist"

		prefixValues, err := db.ReadPrefix(context.Background(), namespace, key)
		assert.NoError(t, err)
		assert.Len(t, prefixValues, 0)

		allKeys, err := db.ReadAllKeys(context.Background(), namespace)
		assert.NoError(t, err)
		assert.Len(t, allKeys, 0)

		allValues, err := db.ReadAll(context.Background(), namespace)
		assert.NoError(t, err)
		assert.Len(t, allValues, 0)

		value, err := db.Read(context.Background(), namespace, key)
		assert.NoError(t, err)
		assert.Nil(t, value)
	}
}

func TestDBExists_FalseWhenNoNamespaceKey(t *testing.T) {
	for _, dbImpl := range getDBImplementations(t) {
		db := dbImpl

		exists, err := db.Exists(context.Background(), "dnenamespace", "dnekey")
		assert.NoError(t, err)
		assert.False(t, exists)
	}
}

func TestDBExists_FalseWhenKeyIsAbsent(t *testing.T) {
	for _, dbImpl := range getDBImplementations(t) {
		db := dbImpl

		namespace := "exists"

		err := db.Write(context.Background(), namespace, "dnedne", nil)
		assert.NoError(t, err)

		exists, err := db.Exists(context.Background(), namespace, "otherdnekey")
		assert.NoError(t, err)
		assert.False(t, exists)
	}
}

func TestDBExists_TrueWhenNilKey(t *testing.T) {
	for _, dbImpl := range getDBImplementations(t) {
		db := dbImpl

		namespace := "exists"
		key := "key1"

		err := db.Write(context.Background(), namespace, key, nil)
		assert.NoError(t, err)

		exists, err := db.Exists(context.Background(), namespace, key)
		assert.NoError(t, err)
		assert.True(t, exists)
	}
}

func TestDBExists_FalseAfterDeletingKey(t *testing.T) {
	for _, dbImpl := range getDBImplementations(t) {
		db := dbImpl

		namespace := "exists"
		key := "key1"

		dummyData := []byte("dummy")
		err := db.Write(context.Background(), namespace, key, dummyData)
		assert.NoError(t, err)

		exists, err := db.Exists(context.Background(), namespace, key)
		assert.NoError(t, err)
		assert.True(t, exists)

		err = db.Delete(context.Background(), namespace, key)
		assert.NoError(t, err)

		exists, err = db.Exists(context.Background(), namespace, key)
		assert.NoError(t, err)
		assert.False(t, exists)
	}
}

type testStruct struct {
	Status int    `json:"status"`
	Reason string `json:"reason"`
}

type operation struct {
	Done     bool   `json:"done"`
	Response []byte `json:"response"`
}

func TestDB_Update(t *testing.T) {
	for _, dbImpl := range getDBImplementations(t) {
		db := dbImpl
		namespace := "simple"

		data, err := json.Marshal(testStruct{
			Status: 0,
			Reason: "",
		})
		require.NoError(t, err)
		require.NoError(t, db.Write(context.Background(), namespace, "123", data))

		type args struct {
			key    string
			values map[string]any
		}
		tests := []struct {
			name          string
			args          args
			expectedData  testStruct
			expectedError assert.ErrorAssertionFunc
		}{
			{
				name: "simple update",
				args: args{
					key: "123",
					values: map[string]any{
						"status": 1,
						"reason": "something here",
					},
				},
				expectedData: testStruct{
					Status: 1,
					Reason: "something here",
				},
				expectedError: assert.NoError,
			},
			{
				name: "other key returns error",
				args: args{
					key: "456",
					values: map[string]any{
						"status": 1,
						"reason": "something here",
					},
				},
				expectedData:  testStruct{},
				expectedError: assert.Error,
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				data, err = Update(context.Background(), db, namespace, tt.args.key, tt.args.values)
				if !tt.expectedError(t, err) {
					return
				}
				var s testStruct
				if tt.expectedData != s {
					assert.NoError(t, json.Unmarshal(data, &s))
					assert.Equal(t, tt.expectedData, s)
				}
			})
		}
	}
}

type testOpUpdater struct {
	UpdaterWithMap
}

func (f testOpUpdater) SetUpdatedResponse(bytes []byte) {
	f.UpdaterWithMap.Values["response"] = bytes
}

func TestDB_Execute(t *testing.T) {
	for _, dbImpl := range getDBImplementations(t) {
		db := dbImpl
		_, err := db.Execute(context.Background(), func(ctx context.Context, tx Tx) (any, error) {
			return nil, tx.Write(ctx, "hello", "my_key", []byte(`some bytes`))
		}, nil)
		assert.NoError(t, err)
		result, err := db.Read(context.Background(), "hello", "my_key")
		assert.NoError(t, err)
		assert.Equal(t, []byte(`some bytes`), result)
	}
}

func TestDB_UpdatedSubmissionAndOperationTxFn(t *testing.T) {
	for _, dbImpl := range getDBImplementations(t) {
		db := dbImpl
		namespace := "simple"
		opNamespace := "operation"

		data, err := json.Marshal(testStruct{
			Status: 0,
			Reason: "",
		})
		require.NoError(t, err)
		require.NoError(t, db.Write(context.Background(), namespace, "123", data))

		data, err = json.Marshal(operation{
			Done:     false,
			Response: nil,
		})
		require.NoError(t, err)
		require.NoError(t, db.Write(context.Background(), opNamespace, "op123", data))

		type args struct {
			namespace   string
			key         string
			updater     Updater
			opNamespace string
			opKey       string
		}
		tests := []struct {
			name           string
			args           args
			wantFirst      *testStruct
			wantOpDone     bool
			wantOpResponse *testStruct
			wantErr        assert.ErrorAssertionFunc
		}{
			{
				name: "first and second get updated",
				args: args{
					namespace: namespace,
					key:       "123",
					updater: NewUpdater(map[string]any{
						"status": 1,
						"reason": "hello",
					}),
					opNamespace: opNamespace,
					opKey:       "op123",
				},
				wantFirst: &testStruct{
					Status: 1,
					Reason: "hello",
				},
				wantOpDone: true,
				wantOpResponse: &testStruct{
					Status: 1,
					Reason: "hello",
				},
				wantErr: assert.NoError,
			},
			{
				name: "non-existent op key returns error",
				args: args{
					namespace: namespace,
					key:       "123",
					updater: NewUpdater(map[string]any{
						"status": 1,
						"reason": "hello",
					}),
					opNamespace: opNamespace,
					opKey:       "crazy key",
				},
				wantErr: assert.Error,
			},
			{
				name: "non-existent key returns error",
				args: args{
					namespace: namespace,
					key:       "crazy key",
					updater: NewUpdater(map[string]any{
						"status": 1,
						"reason": "hello",
					}),
					opNamespace: opNamespace,
					opKey:       "op123",
				},
				wantErr: assert.Error,
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				gotFirstData, gotOpData, err := UpdateValueAndOperation(context.Background(), db, tt.args.namespace, tt.args.key, tt.args.updater, tt.args.opNamespace, tt.args.opKey, testOpUpdater{
					NewUpdater(map[string]any{
						"done": true,
					}),
				})
				if !tt.wantErr(t, err, fmt.Sprintf("UpdateValueAndOperation(%v, %v, %v, %v, %v)", tt.args.namespace, tt.args.key, tt.args.updater, tt.args.opNamespace, tt.args.opKey)) {
					return
				}
				if tt.wantFirst == nil {
					return
				}
				var gotFirst testStruct
				assert.NoError(t, json.Unmarshal(gotFirstData, &gotFirst))
				assert.Equal(t, *tt.wantFirst, gotFirst)

				var gotOp operation
				assert.NoError(t, json.Unmarshal(gotOpData, &gotOp))
				assert.Equal(t, tt.wantOpDone, gotOp.Done)

				var gotOpResponse testStruct
				assert.NoError(t, json.Unmarshal(gotOp.Response, &gotOpResponse))
				assert.Equal(t, *tt.wantOpResponse, gotOpResponse)
			})
		}
	}
}
