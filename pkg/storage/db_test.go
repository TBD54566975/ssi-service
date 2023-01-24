package storage

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getDBImplementations(t *testing.T) []ServiceStorage {
	boltDB := setupBoltDB(t)
	redisDB := setupRedisDB(t)

	dbImpls := make([]ServiceStorage, 0)
	dbImpls = append(dbImpls, boltDB, redisDB)
	return dbImpls
}

func setupBoltDB(t *testing.T) *BoltDB {
	db, err := NewStorage(Bolt, "test.db")
	assert.NoError(t, err)
	assert.NotEmpty(t, db)

	t.Cleanup(func() {
		_ = db.Close()
		_ = os.Remove("test.db")
	})
	return db.(*BoltDB)
}

func setupRedisDB(t *testing.T) *RedisDB {
	server := miniredis.RunT(t)
	options := make(map[string]interface{})
	options["address"] = server.Addr()
	options["password"] = ""

	db, err := NewStorage(Redis, options)
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
		assert.Contains(t, err.Error(), "could not delete namespace<bad>")

		// delete namespace
		err = db.DeleteNamespace(context.Background(), namespace)
		assert.NoError(t, err)

		res, err = db.Read(context.Background(), namespace, team1)
		assert.NoError(t, err)
		assert.Empty(t, res)
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
				data, err = db.Update(context.Background(), namespace, tt.args.key, tt.args.values)
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
				gotFirstData, gotOpData, err := db.UpdateValueAndOperation(context.Background(), tt.args.namespace, tt.args.key, tt.args.updater, tt.args.opNamespace, tt.args.opKey, testOpUpdater{
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
