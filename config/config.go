package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/ardanlabs/conf"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	DefaultConfigPath = "config/config.toml"
	ConfigFileName    = "config.toml"
	ServiceName       = "ssi-service"
	ConfigExtension   = ".toml"
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
	JagerHost       string        `toml:"jager_host" conf:"http://jaeger:14268/api/traces"`
	JagerEnabled    bool          `toml:"jager_enabled" conf:"default:false"`
	ReadTimeout     time.Duration `toml:"read_timeout" conf:"default:5s"`
	WriteTimeout    time.Duration `toml:"write_timeout" conf:"default:5s"`
	ShutdownTimeout time.Duration `toml:"shutdown_timeout" conf:"default:5s"`
	LogLocation     string        `toml:"log_location" conf:"default:log"`
	LogLevel        string        `toml:"log_level" conf:"default:debug"`
}

// ServicesConfig represents configurable properties for the components of the SSI Service
type ServicesConfig struct {
	// at present, it is assumed that a single storage provider works for all services
	// in the future it may make sense to have per-service storage providers (e.g. mysql for one service,
	// mongo for another)
	StorageProvider string `toml:"storage"`

	// Embed all service-specific configs here. The order matters: from which should be instantiated first, to last

	DIDConfig        DIDServiceConfig        `toml:"did,omitempty"`
	SchemaConfig     SchemaServiceConfig     `toml:"schema,omitempty"`
	CredentialConfig CredentialServiceConfig `toml:"credential,omitempty"`
	KeyStoreConfig   KeyStoreServiceConfig   `toml:"keystore,omitempty"`
	ManifestConfig   ManifestServiceConfig   `toml:"manifest,omitempty"`
}

// BaseServiceConfig represents configurable properties for a specific component of the SSI Service
// Can be wrapped and extended for any specific service config
type BaseServiceConfig struct {
	Name string `toml:"name"`
}

type DIDServiceConfig struct {
	*BaseServiceConfig
	Methods []string `toml:"methods"`
}

func (d *DIDServiceConfig) IsEmpty() bool {
	if d == nil {
		return true
	}
	return reflect.DeepEqual(d, &DIDServiceConfig{})
}

type SchemaServiceConfig struct {
	*BaseServiceConfig
}

func (s *SchemaServiceConfig) IsEmpty() bool {
	if s == nil {
		return true
	}
	return reflect.DeepEqual(s, &SchemaServiceConfig{})
}

type CredentialServiceConfig struct {
	*BaseServiceConfig
	// TODO(gabe) supported key and signature types
}

type ManifestServiceConfig struct {
	*BaseServiceConfig
}

type KeyStoreServiceConfig struct {
	*BaseServiceConfig
	// Service key password. Used by a KDF whose key is used by a symmetric cypher for key encryption.
	// The password is salted before usage.
	ServiceKeyPassword string
}

// LoadConfig attempts to load a TOML config file from the given path, and coerce it into our object model.
// Before loading, defaults are applied on certain properties, which are overwritten if specified in the TOML file.
func LoadConfig(path string) (*SSIServiceConfig, error) {
	// no path, load default config
	defaultConfig := false
	if path == "" {
		logrus.Info("no config path provided, loading default config...")
		defaultConfig = true
	} else if filepath.Ext(path) != ConfigExtension {
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

	if defaultConfig {
		config.Services = ServicesConfig{
			StorageProvider: "bolt",
			DIDConfig: DIDServiceConfig{
				BaseServiceConfig: &BaseServiceConfig{Name: "did"},
				Methods:           []string{"key"},
			},
			SchemaConfig: SchemaServiceConfig{
				BaseServiceConfig: &BaseServiceConfig{Name: "schema"},
			},
			CredentialConfig: CredentialServiceConfig{
				BaseServiceConfig: &BaseServiceConfig{Name: "credential"},
			},
			KeyStoreConfig: KeyStoreServiceConfig{
				BaseServiceConfig:  &BaseServiceConfig{Name: "keystore"},
				ServiceKeyPassword: "default-password",
			},
		}
	} else {
		// load from TOML file
		if _, err := toml.DecodeFile(path, &config); err != nil {
			return nil, errors.Wrapf(err, "could not load config: %s", path)
		}
	}

	return &config, nil
}
