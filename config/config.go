package config

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/ardanlabs/conf"
	"github.com/pkg/errors"
	"os"
	"strings"
	"time"
)

const (
	DefaultConfigPath = "config.toml"
	ServiceName       = "ssi-service"
)

type SSIServiceConfig struct {
	conf.Version
	Server   ServerConfig   `toml:"server"`
	Services ServicesConfig `toml:"services"`
}

// ServerConfig represents configurable properties for the HTTP server
type ServerConfig struct {
	APIHost         string        `toml:"api_host" conf:"default:0.0.0.0:3000"`
	DebugHost       string        `toml:"debug_host" conf:"default:0.0.0.0:4000"`
	ReadTimeout     time.Duration `toml:"read_timeout" conf:"default:5s"`
	WriteTimeout    time.Duration `toml:"write_timeout" conf:"default:5s"`
	ShutdownTimeout time.Duration `toml:"shutdown_timeout" conf:"default:5s"`
}

// ServicesConfig represents configurable properties for the components of the SSI Service
type ServicesConfig struct {
	EnabledServices []string `toml:"enabled"`
	Config          map[string]interface{}
}

// ServiceConfig represents configurable properties for a specific component of the SSI Service
type ServiceConfig struct {
	Storage           string   `toml:"storage"`
	DependentServices []string `toml:"dependent_services,omitempty"`
}

// LoadConfig attempts to load a TOML config file from the given path, and coerce it into our object model.
// Before loading, defaults are applied on certain properties, which are overwritten if specified in the TOML file.
func LoadConfig(path string) (*SSIServiceConfig, error) {
	if !strings.Contains(path, ".toml") {
		return nil, fmt.Errorf("path<%s> did not match the expected TOML format", path)
	}

	// create the config object
	var config SSIServiceConfig

	// parse and apply defaults
	if err := conf.Parse(os.Args[1:], ServiceName, &config); err != nil {
		switch err {
		case conf.ErrHelpWanted:
			usage, err := conf.Usage(ServiceName, &config)
			if err != nil {
				return nil, errors.Wrap(err, "parsing config")
			}
			fmt.Println(usage)

			return nil, nil

		case conf.ErrVersionWanted:
			version, err := conf.VersionString(ServiceName, &config)
			if err != nil {
				return nil, errors.Wrap(err, "generating config version")
			}

			fmt.Println(version)
			return nil, nil
		}

		return nil, errors.Wrap(err, "parsing config")
	}

	// load from TOML file
	if _, err := toml.DecodeFile(path, &config); err != nil {
		return nil, errors.Wrapf(err, "could not load config: %s", path)
	}

	return &config, nil
}
