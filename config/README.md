# Configuration

Configuration is managed using
a [TOML](https://toml.io/en/) [file](https://github.com/TBD54566975/ssi-service/blob/main/config/config.toml). There are
sets of configuration values for the server (e.g. which port to listen on), the services (e.g. which database to use),
and each service.

Each service may define specific configuration, such as which DID methods are enabled for the DID service.

# Usage

The service, upon boot, looks for a file called `config.toml` to find its configuration.

There are a number of configuration files in this directory provided as defaults.
Specifically, `[config.toml](config.toml)`
is intended to be used when the service is run as a local go process. There is another
file, `[compose.toml](compose.toml)`,
which is intended to be used when the service is run via docker compose. To make this switch, it's recommended that one
renames the file to `config.toml` and then maintains the original `compose.toml` file as `local.toml` or similar. 