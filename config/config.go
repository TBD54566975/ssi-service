package config

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/ardanlabs/conf"
	"github.com/joho/godotenv"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/pkg/storage"
)

const (
	DefaultConfigPath = "config/dev.toml"
	DefaultEnvPath    = "config/.env"
	Filename          = "dev.toml"
	Extension         = ".toml"

	EnvironmentDev  Environment = "dev"
	EnvironmentTest Environment = "test"
	EnvironmentProd Environment = "prod"

	ConfigPath EnvironmentVariable = "CONFIG_PATH"
	DBPassword EnvironmentVariable = "DB_PASSWORD"
)

type (
	Environment         string
	EnvironmentVariable string
)

func (e EnvironmentVariable) String() string {
	return string(e)
}

type SSIServiceConfig struct {
	Server   ServerConfig   `toml:"server"`
	Services ServicesConfig `toml:"services"`
}

// ServerConfig represents configurable properties for the HTTP server
type ServerConfig struct {
	Environment         Environment   `toml:"env" conf:"default:dev"`
	APIHost             string        `toml:"api_host" conf:"default:0.0.0.0:3000"`
	JagerHost           string        `toml:"jager_host" conf:"default:http://jaeger:14268/api/traces"`
	JagerEnabled        bool          `toml:"jager_enabled" conf:"default:false"`
	ReadTimeout         time.Duration `toml:"read_timeout" conf:"default:5s"`
	WriteTimeout        time.Duration `toml:"write_timeout" conf:"default:5s"`
	ShutdownTimeout     time.Duration `toml:"shutdown_timeout" conf:"default:5s"`
	LogLocation         string        `toml:"log_location" conf:"default:log"`
	LogLevel            string        `toml:"log_level" conf:"default:debug"`
	EnableSchemaCaching bool          `toml:"enable_schema_caching" conf:"default:true"`
	EnableAllowAllCORS  bool          `toml:"enable_allow_all_cors" conf:"default:false"`
}

// ServicesConfig represents configurable properties for the components of the SSI Service
type ServicesConfig struct {
	// at present, it is assumed that a single storage provider works for all services
	// in the future it may make sense to have per-service storage providers (e.g. mysql for one service,
	// mongo for another)
	StorageProvider string           `toml:"storage" conf:"default:bolt"`
	StorageOptions  []storage.Option `toml:"storage_option"`
	ServiceEndpoint string           `toml:"service_endpoint" conf:"default:http://localhost:8080"`
	StatusEndpoint  string           `toml:"status_endpoint"`

	// Application level encryption configuration. Defines how values are encrypted before they are stored in the
	// configured KV store.
	AppLevelEncryptionConfiguration EncryptionConfig `toml:"storage_encryption,omitempty"`

	// Embed all service-specific configs here. The order matters: from which should be instantiated first, to last
	KeyStoreConfig   KeyStoreServiceConfig   `toml:"keystore,omitempty"`
	DIDConfig        DIDServiceConfig        `toml:"did,omitempty"`
	CredentialConfig CredentialServiceConfig `toml:"credential,omitempty"`
	WebhookConfig    WebhookServiceConfig    `toml:"webhook,omitempty"`
}

type KeyStoreServiceConfig struct {
	EncryptionConfig
}

type EncryptionConfig struct {
	DisableEncryption bool `toml:"disable_encryption" conf:"default:false"`

	// The URI for a master key. We use tink for envelope encryption as described in https://github.com/google/tink/blob/9bc2667963e20eb42611b7581e570f0dddf65a2b/docs/KEY-MANAGEMENT.md#key-management-with-tink
	// When left empty and DisableEncryption is off, then a random key is generated and used. This random key is persisted unencrypted in the
	// configured storage. Production deployments should never leave this field empty.
	MasterKeyURI string `toml:"master_key_uri"`

	// Path for credentials. Required when MasterKeyURI is set. More info at https://github.com/google/tink/blob/9bc2667963e20eb42611b7581e570f0dddf65a2b/docs/KEY-MANAGEMENT.md#credentials
	KMSCredentialsPath string `toml:"kms_credentials_path"`
}

func (e EncryptionConfig) GetMasterKeyURI() string {
	return e.MasterKeyURI
}

func (e EncryptionConfig) GetKMSCredentialsPath() string {
	return e.KMSCredentialsPath
}

func (e EncryptionConfig) EncryptionEnabled() bool {
	return !e.DisableEncryption
}

func (k *KeyStoreServiceConfig) IsEmpty() bool {
	if k == nil {
		return true
	}
	// this returns false since reflection will fail on the EncryptionConfig struct
	return false
}

func (k *KeyStoreServiceConfig) GetMasterKeyURI() string {
	return k.MasterKeyURI
}

func (k *KeyStoreServiceConfig) GetKMSCredentialsPath() string {
	return k.KMSCredentialsPath
}

func (k *KeyStoreServiceConfig) EncryptionEnabled() bool {
	return !k.DisableEncryption
}

type DIDServiceConfig struct {
	Methods                  []string `toml:"methods" conf:"default:key;web"`
	LocalResolutionMethods   []string `toml:"local_resolution_methods" conf:"default:key;peer;web;jwk;pkh"`
	UniversalResolverURL     string   `toml:"universal_resolver_url"`
	UniversalResolverMethods []string `toml:"universal_resolver_methods"`
	IONResolverURL           string   `toml:"ion_resolver_url"`
	// BatchCreateMaxItems set's the maximum amount that can be.
	BatchCreateMaxItems int `toml:"batch_create_max_items" conf:"default:100"`
}

func (d *DIDServiceConfig) IsEmpty() bool {
	if d == nil {
		return true
	}
	return reflect.DeepEqual(d, &DIDServiceConfig{})
}

type CredentialServiceConfig struct {
	// BatchCreateMaxItems set's the maximum amount of credentials that can be created in a single request.
	BatchCreateMaxItems int `toml:"batch_create_max_items" conf:"default:100"`
	// BatchUpdateStatusMaxItems set's the maximum amount of credentials statuses that can be updated in a single request.
	BatchUpdateStatusMaxItems int `toml:"batch_update_status_max_items" conf:"default:100"`

	// TODO(gabe) supported key and signature types
}

func (c *CredentialServiceConfig) IsEmpty() bool {
	if c == nil {
		return true
	}
	return reflect.DeepEqual(c, &CredentialServiceConfig{})
}

type WebhookServiceConfig struct {
	WebhookTimeout string `toml:"webhook_timeout" conf:"default:10s"`
}

func (p *WebhookServiceConfig) IsEmpty() bool {
	if p == nil {
		return true
	}
	return reflect.DeepEqual(p, &WebhookServiceConfig{})
}

// LoadConfig attempts to load a TOML config file from the given path, and coerce it into our object model.
// Before loading, defaults are applied on certain properties, which are overwritten if specified in the TOML file.
func LoadConfig(path string, fs fs.FS) (*SSIServiceConfig, error) {
	if fs == nil {
		fs = os.DirFS(".")
	}
	useDefaultConfig, err := checkValidConfigPath(path)
	if err != nil {
		return nil, errors.Wrap(err, "validate config path")
	}

	// create the config object
	config := new(SSIServiceConfig)
	if err = parseConfig(config); err != nil {
		return nil, errors.Wrap(err, "parse and apply defaults")
	}

	if !useDefaultConfig {
		if err = loadTOMLConfig(path, config, fs); err != nil {
			return nil, errors.Wrap(err, "load toml config")
		}
	}

	if err = applyEnvVariables(config); err != nil {
		return nil, errors.Wrap(err, "apply env variables")
	}

	if err = validateConfig(config); err != nil {
		return nil, errors.Wrap(err, "validating config values")
	}
	return config, nil
}

func validateConfig(s *SSIServiceConfig) error {
	if s.Server.Environment == EnvironmentProd {
		if s.Services.KeyStoreConfig.DisableEncryption {
			return errors.New("prod environment cannot disable key encryption")
		}
		if s.Services.AppLevelEncryptionConfiguration.DisableEncryption {
			logrus.Warn("Prod environment detected without app level encryption. This is strongly discouraged.")
		}
	}
	return nil
}

func checkValidConfigPath(path string) (bool, error) {
	// no path, load default config
	defaultConfig := false
	if path == "" {
		logrus.Info("no config path provided, loading default config...")
		defaultConfig = true
	} else if filepath.Ext(path) != Extension {
		return false, fmt.Errorf("file extension for path %q must be %q", path, Extension)
	}
	return defaultConfig, nil
}

func parseConfig(cfg *SSIServiceConfig) error {
	// parse and apply defaults
	err := conf.Parse(os.Args[1:], ServiceName, cfg)
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, conf.ErrHelpWanted):
		usage, err := conf.Usage(ServiceName, &cfg)
		if err != nil {
			return errors.Wrap(err, "parsing config")
		}
		logrus.Info(usage)

		return nil
	case errors.Is(err, conf.ErrVersionWanted):
		version, err := conf.VersionString(ServiceName, &cfg)
		if err != nil {
			return errors.Wrap(err, "generating config version")
		}

		logrus.Info(version)
		return nil
	}
	return errors.Wrap(err, "parsing config")
}

func loadTOMLConfig(path string, config *SSIServiceConfig, fs fs.FS) error {
	// load from TOML file
	file, err := fs.Open(path)
	if err != nil {
		return errors.Wrapf(err, "opening path %s", path)
	}
	if _, err = toml.NewDecoder(file).Decode(&config); err != nil {
		return errors.Wrapf(err, "could not load config: %s", path)
	}
	return nil
}

func applyEnvVariables(config *SSIServiceConfig) error {
	if err := godotenv.Load(DefaultEnvPath); err != nil {
		// The error indicates that the file or directory does not exist.
		if os.IsNotExist(err) {
			logrus.Info("no .env file found, skipping apply env variables...")
			return nil
		}
		return errors.Wrap(err, "dotenv parsing")
	}

	dbPassword, present := os.LookupEnv(DBPassword.String())
	if present {
		if len(config.Services.StorageOptions) != 0 {
			for _, storageOption := range config.Services.StorageOptions {
				if storageOption.ID == storage.PasswordOption {
					storageOption.Option = dbPassword
					break
				}
			}
		}
	}

	return nil
}
