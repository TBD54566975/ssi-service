package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfig(t *testing.T) {
	config, err := LoadConfig(Filename)
	assert.NoError(t, err)
	assert.NotEmpty(t, config)

	assert.False(t, config.Server.ReadTimeout.String() == "")
	assert.False(t, config.Server.WriteTimeout.String() == "")
	assert.False(t, config.Server.ShutdownTimeout.String() == "")
	assert.False(t, config.Server.APIHost == "")

	assert.NotEmpty(t, config.Services.StorageProvider)
}
