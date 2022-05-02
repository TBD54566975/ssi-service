package config

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestConfig(t *testing.T) {
	config, err := LoadConfig(DefaultConfigPath)
	assert.NoError(t, err)
	assert.NotEmpty(t, config)

	assert.False(t, config.Server.ReadTimeout.String() == "")
	assert.False(t, config.Server.WriteTimeout.String() == "")
	assert.False(t, config.Server.ShutdownTimeout.String() == "")
	assert.False(t, config.Server.APIHost == "")
	assert.False(t, config.Server.DebugHost == "")

	assert.NotZero(t, config.Services.EnabledServices)

	fmt.Printf("%+v", config.Services)
}
