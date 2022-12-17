package config

import (
	"path"
	"reflect"
	"time"

	"github.com/pkg/errors"
	"github.com/suutaku/nice-config/pkg/conf"
)

const (
	defaultConfigPath = "config"
	configFileName    = "config.toml"
	ServiceName       = "ssi-service"
	ConfigExtension   = ".toml"

	DefaultServiceEndpoint = "http://localhost:8080"
)

type Info struct {
	Title string `toml:"title"`
	Svn   string `toml:"svn"`
	Desc  string `toml:"desc"`
}

type SSIServiceConfig struct {
	Info
	Server   ServerConfig   `toml:"server" comment:"http service configuration"`
	Services ServicesConfig `toml:"services"`
}

// ServerConfig represents configurable properties for the HTTP server
type ServerConfig struct {
	APIHost             string        `toml:"api_host"`
	DebugHost           string        `toml:"debug_host"`
	JagerHost           string        `toml:"jager_host"`
	JagerEnabled        bool          `toml:"jager_enabled"`
	ReadTimeout         time.Duration `toml:"read_timeout" comment:"5 seconds, time is in nanoseconds"`
	WriteTimeout        time.Duration `toml:"write_timeout"`
	ShutdownTimeout     time.Duration `toml:"shutdown_timeout"`
	LogLocation         string        `toml:"log_location"`
	LogLevel            string        `toml:"log_level" comment:"options: trace, debug, info, warning, error, fatal, panic"`
	EnableSchemaCaching bool          `toml:"enable_schema_caching"`
}

// ServicesConfig represents configurable properties for the components of the SSI Service
type ServicesConfig struct {
	// at present, it is assumed that a single storage provider works for all services
	// in the future it may make sense to have per-service storage providers (e.g. mysql for one service,
	// mongo for another)
	StorageProvider string      `toml:"storage" comment:"a implementation type of github.com/tbd54566975/ssi-service/pkg/storage.ServiceStorage"`
	StorageOption   interface{} `toml:"storage_option" comment:"this is a sotrage implementation specify option can be any struct"`
	ServiceEndpoint string      `toml:"service_endpoint"`

	// Embed all service-specific configs here. The order matters: from which should be instantiated first, to last
	KeyStoreConfig     KeyStoreServiceConfig     `toml:"keystore,omitempty" comment:"per-service configuration"`
	DIDConfig          DIDServiceConfig          `toml:"did,omitempty"`
	SchemaConfig       SchemaServiceConfig       `toml:"schema,omitempty"`
	CredentialConfig   CredentialServiceConfig   `toml:"credential,omitempty"`
	ManifestConfig     ManifestServiceConfig     `toml:"manifest,omitempty"`
	PresentationConfig PresentationServiceConfig `toml:"presentation,omitempty"`
}

// BaseServiceConfig represents configurable properties for a specific component of the SSI Service
// Can be wrapped and extended for any specific service config
type BaseServiceConfig struct {
	Name            string `toml:"name,omitempty"`
	ServiceEndpoint string `toml:"service_endpoint,omitempty"`
}

type KeyStoreServiceConfig struct {
	BaseServiceConfig
	// Service key password. Used by a KDF whose key is used by a symmetric cypher for key encryption.
	// The password is salted before usage.
	ServiceKeyPassword string `toml:"password,omitempty"`
}

func (k *KeyStoreServiceConfig) IsEmpty() bool {
	if k == nil {
		return true
	}
	return reflect.DeepEqual(k, &KeyStoreServiceConfig{})
}

type DIDServiceConfig struct {
	BaseServiceConfig
	Methods           []string `toml:"methods"`
	ResolutionMethods []string `toml:"resolution_methods"`
}

func (d *DIDServiceConfig) IsEmpty() bool {
	if d == nil {
		return true
	}
	return reflect.DeepEqual(d, &DIDServiceConfig{})
}

type SchemaServiceConfig struct {
	BaseServiceConfig
}

func (s *SchemaServiceConfig) IsEmpty() bool {
	if s == nil {
		return true
	}
	return reflect.DeepEqual(s, &SchemaServiceConfig{})
}

type CredentialServiceConfig struct {
	BaseServiceConfig

	// TODO(gabe) supported key and signature types
}

func (c *CredentialServiceConfig) IsEmpty() bool {
	if c == nil {
		return true
	}
	return reflect.DeepEqual(c, &CredentialServiceConfig{})
}

type ManifestServiceConfig struct {
	BaseServiceConfig
}

func (m *ManifestServiceConfig) IsEmpty() bool {
	if m == nil {
		return true
	}
	return reflect.DeepEqual(m, &ManifestServiceConfig{})
}

type PresentationServiceConfig struct {
	BaseServiceConfig
}

func (p *PresentationServiceConfig) IsEmpty() bool {
	if p == nil {
		return true
	}
	return reflect.DeepEqual(p, &PresentationServiceConfig{})
}

var defaultConfig = SSIServiceConfig{
	Info: Info{
		Title: "SSI Service Config",
		Svn:   "0.0.1",
		Desc:  "Default configuration to be used while running the service as a single go process.",
	},
	Server: ServerConfig{
		APIHost:             "0.0.0.0:3000",
		DebugHost:           "0.0.0.0:3000",
		JagerHost:           "http://jaeger:14268/api/traces",
		JagerEnabled:        false,
		ReadTimeout:         5 * time.Second,
		WriteTimeout:        5 * time.Second,
		ShutdownTimeout:     5 * time.Second,
		LogLocation:         "logs",
		LogLevel:            "debug",
		EnableSchemaCaching: true,
	},
	Services: ServicesConfig{
		StorageProvider: "bolt",
		ServiceEndpoint: DefaultServiceEndpoint,
		KeyStoreConfig: KeyStoreServiceConfig{
			BaseServiceConfig:  BaseServiceConfig{Name: "keystore"},
			ServiceKeyPassword: "default-password",
		},
		DIDConfig: DIDServiceConfig{
			BaseServiceConfig: BaseServiceConfig{Name: "did"},
			Methods:           []string{"key", "web"},
			ResolutionMethods: []string{"key", "peer", "web", "pkh"},
		},
		SchemaConfig: SchemaServiceConfig{
			BaseServiceConfig: BaseServiceConfig{Name: "schema"},
		},
		CredentialConfig: CredentialServiceConfig{
			BaseServiceConfig: BaseServiceConfig{Name: "credential", ServiceEndpoint: DefaultServiceEndpoint},
		},
		ManifestConfig: ManifestServiceConfig{
			BaseServiceConfig: BaseServiceConfig{Name: "manifest"},
		},
		PresentationConfig: PresentationServiceConfig{
			BaseServiceConfig: BaseServiceConfig{Name: "presentation"},
		},
	},
}

// LoadConfig attempts to load a TOML config file from the given home path, and coerce it into our object model.
// If config file not exists, create a deault config.toml
func LoadConfig(home string) (*SSIServiceConfig, error) {
	if home == "" {
		home = "."
	}
	parser := conf.NewConfigureParser(home, path.Join(defaultConfigPath, configFileName))
	ret := &SSIServiceConfig{}
	err := parser.LoadWithMerge(ret, defaultConfig)
	if err != nil {
		return nil, errors.Wrapf(err, "could not load config: %s/config.toml", home)
	}
	err = parser.Save(ret)
	return ret, err
}
