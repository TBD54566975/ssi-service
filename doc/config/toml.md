# TOML Config File
Config is managed using a [TOML](https://toml.io/en/) [file](https://github.com/TBD54566975/ssi-service/blob/main/config/config.toml). There are sets of configuration values for the server
(e.g. which port to listen on), the services (e.g. which database to use), and each service.

Each service may define specific configuration, such as which DID methods are enabled for the DID service.

## Usage

How it works:
1. On startup: SSI-Service loads default values into the `SSIServiceConfig`
2. Checks for a TOML config file:
    - If exists...load toml file
    - If does not exist...it uses a default config defined in the code inline
3. Loads the `config/.env` file and adds the env variables defined in this file to the final `SSIServiceConfig`

There are a number of configuration files in this directory provided as defaults.
Specifically, `config.toml`is intended to be used when the service is run as a local go process. There is another
file, `compose.toml`, which is intended to be used when the service is run via docker compose. To make this switch,
it's recommended that one renames the file to `config.toml` and then maintains the original `compose.toml` file as
`local.toml` or similar. 
