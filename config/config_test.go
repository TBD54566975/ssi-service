package config

import (
	"embed"
	"testing"

	"github.com/stretchr/testify/assert"
)

//go:embed testdata
var testdata embed.FS

func TestLoadConfig(t *testing.T) {
	t.Run("returns no errors when passed in file", func(t *testing.T) {
		config, err := LoadConfig(Filename, nil)
		assert.NoError(t, err)
		assert.NotEmpty(t, config)

		assert.False(t, config.Server.ReadTimeout.String() == "")
		assert.False(t, config.Server.WriteTimeout.String() == "")
		assert.False(t, config.Server.ShutdownTimeout.String() == "")
		assert.False(t, config.Server.APIHost == "")

		assert.NotEmpty(t, config.Services.StorageProvider)
	})

	t.Run("returns errors when prod disables encryption", func(t *testing.T) {
		_, err := LoadConfig("testdata/test1.toml", testdata)
		assert.Error(t, err)
		assert.ErrorContains(t, err, "prod environment cannot disable key encryption")
	})
}
