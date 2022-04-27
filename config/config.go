package config

import (
	"github.com/BurntSushi/toml"
	"github.com/ardanlabs/conf"
	"github.com/pkg/errors"
	"time"
)

type (
	StorageType string
	ServiceType string
)

const ()

type SSIServiceConfig struct {
	conf.Version
	Server   ServerConfig
	Services ServicesConfig
}

// ServerConfig represents configurable properties for the HTTP server
type ServerConfig struct {
	APIHost         string        `conf:"default:0.0.0.0:3000"`
	DebugHost       string        `conf:"default:0.0.0.0:4000"`
	ReadTimeout     time.Duration `conf:"default:5s"`
	WriteTimeout    time.Duration `conf:"default:5s"`
	ShutdownTimeout time.Duration `conf:"default:5s"`
}

// ServicesConfig represents configurable properties for the components of the SSI Service
type ServicesConfig struct {
	Enabled []string
	Service map[string]ServiceConfig
}

// ServiceConfig represents configurable properties for a specific component of the SSI Service
type ServiceConfig struct {
	DependentServices []string
	Storage           string
}

func LoadConfig(path string) (*SSIServiceConfig, error) {
	var config SSIServiceConfig
	if _, err := toml.DecodeFile(path, &config); err != nil {
		return nil, errors.Wrapf(err, "could not load config: %s", path)
	}
	return &config, nil
}
