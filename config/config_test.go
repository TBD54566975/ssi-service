package config

import (
	"github.com/stretchr/testify/assert"
	"log"
	"os"
	"testing"
)

func TestConfig(t *testing.T) {
	logger := log.New(os.Stdout, "ssi-test", log.LstdFlags)
	config, err := LoadConfig(logger, DefaultConfigPath)
	assert.NoError(t, err)
	assert.NotEmpty(t, config)

	assert.False(t, config.Server.ReadTimeout.String() == "")
	assert.False(t, config.Server.WriteTimeout.String() == "")
	assert.False(t, config.Server.ShutdownTimeout.String() == "")
	assert.False(t, config.Server.APIHost == "")
	assert.False(t, config.Server.DebugHost == "")

	assert.NotEmpty(t, config.Services.StorageProvider)
}
