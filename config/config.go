package config

import (
	"fmt"
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
	ServiceName       = "ssi-service"
	Extension         = ".toml"

	DefaultServiceEndpoint = "http://localhost:8080"

	EnvironmentDev  Environment = "dev"
	EnvironmentTest Environment = "test"
	EnvironmentProd Environment = "prod"

	ConfigPath       EnvironmentVariable = "CONFIG_PATH"
	KeystorePassword EnvironmentVariable = "KEYSTORE_PASSWORD"
	DBPassword       EnvironmentVariable = "DB_PASSWORD"
)

type (
	Environment         string
	EnvironmentVariable string
)

func (e EnvironmentVariable) String() string {
	return string(e)
}

type SSIServiceConfig struct {
	conf.Version
	Server   ServerConfig   `toml:"server"`
	Services ServicesConfig `toml:"services"`
}

// ServerConfig represents configurable properties for the HTTP server
type ServerConfig struct {
	Environment         Environment   `toml:"env" conf:"default:dev"`
	APIHost             string        `toml:"api_host" conf:"default:0.0.0.0:3000"`
	JagerHost           string        `toml:"jager_host" conf:"http://jaeger:14268/api/traces"`
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
	StorageProvider string           `toml:"storage"`
	StorageOptions  []storage.Option `toml:"storage_option"`
	ServiceEndpoint string           `toml:"service_endpoint"`

	// Embed all service-specific configs here. The order matters: from which should be instantiated first, to last
	KeyStoreConfig        KeyStoreServiceConfig     `toml:"keystore,omitempty"`
	DIDConfig             DIDServiceConfig          `toml:"did,omitempty"`
	SchemaConfig          SchemaServiceConfig       `toml:"schema,omitempty"`
	CredentialConfig      CredentialServiceConfig   `toml:"credential,omitempty"`
	OperationConfig       OperationServiceConfig    `toml:"operation,omitempty"`
	PresentationConfig    PresentationServiceConfig `toml:"presentation,omitempty"`
	ManifestConfig        ManifestServiceConfig     `toml:"manifest,omitempty"`
	IssuanceServiceConfig IssuanceServiceConfig     `toml:"issuance,omitempty"`
	WebhookConfig         WebhookServiceConfig      `toml:"webhook,omitempty"`
}

// BaseServiceConfig represents configurable properties for a specific component of the SSI Service
// Can be wrapped and extended for any specific service config
type BaseServiceConfig struct {
	Name            string `toml:"name"`
	ServiceEndpoint string `toml:"service_endpoint"`
}

type KeyStoreServiceConfig struct {
	*BaseServiceConfig
	// Master key password. Used by a KDF whose key is used by a symmetric cypher for key encryption.
	// The password is salted before usage.
	// Note that this field is only used when MasterKeyURI is empty.
	MasterKeyPassword string `toml:"password"`

	// The URI for the master key. We use tink for envelope encryption as described in https://github.com/google/tink/blob/9bc2667963e20eb42611b7581e570f0dddf65a2b/docs/KEY-MANAGEMENT.md#key-management-with-tink
	// When left empty, then MasterKeyPassword is used.
	MasterKeyURI string `toml:"master_key_uri"`

	// Path for credentials. Required when using an external KMS. More info at https://github.com/google/tink/blob/9bc2667963e20eb42611b7581e570f0dddf65a2b/docs/KEY-MANAGEMENT.md#credentials
	KMSCredentialsPath string `toml:"kms_credentials_path"`
}

func (k *KeyStoreServiceConfig) IsEmpty() bool {
	if k == nil {
		return true
	}
	return reflect.DeepEqual(k, &KeyStoreServiceConfig{})
}

type DIDServiceConfig struct {
	*BaseServiceConfig
	Methods                  []string `toml:"methods"`
	LocalResolutionMethods   []string `toml:"local_resolution_methods"`
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
	// BatchCreateMaxItems set's the maximum amount that can be.
	BatchCreateMaxItems int `toml:"batch_create_max_items" conf:"default:100"`

	// TODO(gabe) supported key and signature types
}

func (c *CredentialServiceConfig) IsEmpty() bool {
	if c == nil {
		return true
	}
	return reflect.DeepEqual(c, &CredentialServiceConfig{})
}

type OperationServiceConfig struct {
	*BaseServiceConfig
}

func (o *OperationServiceConfig) IsEmpty() bool {
	if o == nil {
		return true
	}
	return reflect.DeepEqual(o, &OperationServiceConfig{})
}

type PresentationServiceConfig struct {
	*BaseServiceConfig
	ExpirationDuration time.Duration `toml:"expiration_duration" conf:"default:30m"`
}

func (p *PresentationServiceConfig) IsEmpty() bool {
	if p == nil {
		return true
	}
	return reflect.DeepEqual(p, &PresentationServiceConfig{})
}

type ManifestServiceConfig struct {
	*BaseServiceConfig
	ExpirationDuration time.Duration `toml:"expiration_duration" conf:"default:30m"`
}

func (m *ManifestServiceConfig) IsEmpty() bool {
	if m == nil {
		return true
	}
	return reflect.DeepEqual(m, &ManifestServiceConfig{})
}

type IssuanceServiceConfig struct {
	*BaseServiceConfig
}

func (s *IssuanceServiceConfig) IsEmpty() bool {
	if s == nil {
		return true
	}
	return reflect.DeepEqual(s, &IssuanceServiceConfig{})
}

type WebhookServiceConfig struct {
	*BaseServiceConfig
	WebhookTimeout string `toml:"webhook_timeout"`
}

func (p *WebhookServiceConfig) IsEmpty() bool {
	if p == nil {
		return true
	}
	return reflect.DeepEqual(p, &WebhookServiceConfig{})
}

// LoadConfig attempts to load a TOML config file from the given path, and coerce it into our object model.
// Before loading, defaults are applied on certain properties, which are overwritten if specified in the TOML file.
func LoadConfig(path string) (*SSIServiceConfig, error) {
	loadDefaultConfig, err := checkValidConfigPath(path)
	if err != nil {
		return nil, errors.Wrap(err, "validate config path")
	}

	// create the config object
	var config SSIServiceConfig
	if err = parseAndApplyDefaults(config); err != nil {
		return nil, errors.Wrap(err, "parse and apply defaults")
	}

	if loadDefaultConfig {
		defaultServicesConfig := getDefaultServicesConfig()
		config.Services = defaultServicesConfig
	} else if err = loadTOMLConfig(path, &config); err != nil {
		return nil, errors.Wrap(err, "load toml config")
	}

	if err = applyEnvVariables(&config); err != nil {
		return nil, errors.Wrap(err, "apply env variables")
	}

	return &config, nil
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

func parseAndApplyDefaults(config SSIServiceConfig) error {
	// parse and apply defaults
	err := conf.Parse(os.Args[1:], ServiceName, &config)
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, conf.ErrHelpWanted):
		usage, err := conf.Usage(ServiceName, &config)
		if err != nil {
			return errors.Wrap(err, "parsing config")
		}
		logrus.Println(usage)

		return nil
	case errors.Is(err, conf.ErrVersionWanted):
		version, err := conf.VersionString(ServiceName, &config)
		if err != nil {
			return errors.Wrap(err, "generating config version")
		}

		logrus.Println(version)
		return nil
	}
	return errors.Wrap(err, "parsing config")
}

// TODO(gabe) remove this from config in https://github.com/TBD54566975/ssi-service/issues/502
func getDefaultServicesConfig() ServicesConfig {
	return ServicesConfig{
		StorageProvider: "bolt",
		ServiceEndpoint: DefaultServiceEndpoint,
		KeyStoreConfig: KeyStoreServiceConfig{
			BaseServiceConfig: &BaseServiceConfig{Name: "keystore", ServiceEndpoint: DefaultServiceEndpoint + "/v1/keys"},
			MasterKeyPassword: "default-password",
		},
		DIDConfig: DIDServiceConfig{
			BaseServiceConfig:      &BaseServiceConfig{Name: "did", ServiceEndpoint: DefaultServiceEndpoint + "/v1/dids"},
			Methods:                []string{"key", "web"},
			LocalResolutionMethods: []string{"key", "peer", "web", "jwk", "pkh"},
		},
		SchemaConfig: SchemaServiceConfig{
			BaseServiceConfig: &BaseServiceConfig{Name: "schema", ServiceEndpoint: DefaultServiceEndpoint + "/v1/schemas"},
		},
		CredentialConfig: CredentialServiceConfig{
			BaseServiceConfig: &BaseServiceConfig{Name: "credential", ServiceEndpoint: DefaultServiceEndpoint + "/v1/credentials"},
		},
		OperationConfig: OperationServiceConfig{
			BaseServiceConfig: &BaseServiceConfig{Name: "operation", ServiceEndpoint: DefaultServiceEndpoint + "/v1/operations"},
		},
		PresentationConfig: PresentationServiceConfig{
			BaseServiceConfig: &BaseServiceConfig{Name: "presentation", ServiceEndpoint: DefaultServiceEndpoint + "/v1/presentations"},
		},
		ManifestConfig: ManifestServiceConfig{
			BaseServiceConfig: &BaseServiceConfig{Name: "manifest", ServiceEndpoint: DefaultServiceEndpoint + "/v1/manifests"},
		},
		IssuanceServiceConfig: IssuanceServiceConfig{
			BaseServiceConfig: &BaseServiceConfig{Name: "issuance", ServiceEndpoint: DefaultServiceEndpoint + "/v1/issuancetemplates"},
		},
		WebhookConfig: WebhookServiceConfig{
			BaseServiceConfig: &BaseServiceConfig{Name: "webhook", ServiceEndpoint: DefaultServiceEndpoint + "/v1/webhooks"},
			WebhookTimeout:    "10s",
		},
	}
}

func loadTOMLConfig(path string, config *SSIServiceConfig) error {
	// load from TOML file
	if _, err := toml.DecodeFile(path, &config); err != nil {
		return errors.Wrapf(err, "could not load config: %s", path)
	}

	// apply defaults
	services := config.Services
	endpoint := services.ServiceEndpoint + "/v1"
	if services.KeyStoreConfig.IsEmpty() {
		services.KeyStoreConfig = KeyStoreServiceConfig{
			BaseServiceConfig: new(BaseServiceConfig),
		}
	}
	services.KeyStoreConfig.ServiceEndpoint = endpoint + "/keys"
	if services.DIDConfig.IsEmpty() {
		services.DIDConfig = DIDServiceConfig{
			BaseServiceConfig: new(BaseServiceConfig),
		}
	}
	services.DIDConfig.ServiceEndpoint = endpoint + "/dids"
	if services.SchemaConfig.IsEmpty() {
		services.SchemaConfig = SchemaServiceConfig{
			BaseServiceConfig: new(BaseServiceConfig),
		}
	}
	services.SchemaConfig.ServiceEndpoint = endpoint + "/schemas"
	if services.CredentialConfig.IsEmpty() {
		services.CredentialConfig = CredentialServiceConfig{
			BaseServiceConfig: new(BaseServiceConfig),
		}
	}
	services.CredentialConfig.ServiceEndpoint = endpoint + "/credentials"
	if services.OperationConfig.IsEmpty() {
		services.OperationConfig = OperationServiceConfig{
			BaseServiceConfig: new(BaseServiceConfig),
		}
	}
	services.OperationConfig.ServiceEndpoint = endpoint + "/operations"
	if services.PresentationConfig.IsEmpty() {
		services.PresentationConfig = PresentationServiceConfig{
			BaseServiceConfig: new(BaseServiceConfig),
		}
	}
	services.PresentationConfig.ServiceEndpoint = endpoint + "/presentations"
	if services.ManifestConfig.IsEmpty() {
		services.ManifestConfig = ManifestServiceConfig{
			BaseServiceConfig: new(BaseServiceConfig),
		}
	}
	services.ManifestConfig.ServiceEndpoint = endpoint + "/manifests"
	if services.IssuanceServiceConfig.IsEmpty() {
		services.IssuanceServiceConfig = IssuanceServiceConfig{
			BaseServiceConfig: new(BaseServiceConfig),
		}
	}
	services.IssuanceServiceConfig.ServiceEndpoint = endpoint + "/issuancetemplates"
	if services.WebhookConfig.IsEmpty() {
		services.WebhookConfig = WebhookServiceConfig{
			BaseServiceConfig: new(BaseServiceConfig),
		}
	}
	services.WebhookConfig.ServiceEndpoint = endpoint + "/webhooks"
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

	keystorePassword, present := os.LookupEnv(KeystorePassword.String())
	if present {
		config.Services.KeyStoreConfig.MasterKeyPassword = keystorePassword
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
