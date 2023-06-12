package testutil

import (
	"os"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/require"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

func SetupRedisTestDB(t *testing.T) storage.ServiceStorage {
	server := miniredis.RunT(t)
	options := []storage.Option{
		{
			ID:     storage.RedisAddressOption,
			Option: server.Addr(),
		},
		{
			ID:     storage.PasswordOption,
			Option: "test-password",
		},
	}
	s, err := storage.NewStorage(storage.Redis, options...)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = s.Close()
	})

	return s
}

func SetupBoltTestDB(t *testing.T) storage.ServiceStorage {
	file, err := os.CreateTemp("", "bolt")
	require.NoError(t, err)
	name := file.Name()
	err = file.Close()
	require.NoError(t, err)
	s, err := storage.NewStorage(storage.Bolt, storage.Option{
		ID:     storage.BoltDBFilePathOption,
		Option: name,
	})

	require.NoError(t, err)

	t.Cleanup(func() {
		_ = s.Close()
		_ = os.Remove(s.URI())
	})

	return s
}
