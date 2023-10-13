# TOML Config File

Config is managed using a [TOML](https://toml.io/en/) [file](../../config/dev.toml). There are sets of configuration values for the server
(e.g. which port to listen on), the services (e.g. which database to use), and each service.

Each service may define specific configuration, such as which DID methods are enabled for the DID service.

A full config example is [provided here](../../config/kitchensink.toml).

## Usage

How it works:

1. On startup: SSI-Service loads default values into the `SSIServiceConfig`
2. Checks for a TOML config file:
   - If exists, load toml file
   - If does not exist, it uses a default config defined in the code inline
3. Loads the `config/.env` file and adds the env variables defined in this file to the final `SSIServiceConfig`

There are a number of configuration files in this directory provided as defaults:

- `dev.toml`: intended to be used when running the service as a local go process
- `test.toml`: intended to be used when testing the service
- `prod.toml`: intended to be used when running the service via docker compose

By default, the `SSIServiceConfig` imports `dev.toml`. To use a different TOML file:
1. Copy desired TOML. Use `config.toml` for non-prod (dev/test). Use `compose.toml` for prod on your env.
```bash
# Only use if running in local non-prod (dev/test)
cp config/dev.toml config/config.toml
```
```bash
# Only use if running in prod via docker compose
cp config/prod.toml config/compose.toml
```

2. Copy and rename the `.env.example` to `.env`
```bash
cp config/.env.example config/.env
```

3. To use the TOML you selected, you can take 1 of 2 actions below
- Open `docker-compose.yml` and update the `environment` section of `ssi` to set `CONFIG_PATH` and `GIN_MODE`
```yml
    environment:
      # select either config or compose based on the command you ran in step 1
      - CONFIG_PATH=/app/config/<config | compose>.toml
      - JAEGER_HTTP_URL=http://jaeger:14268/api/traces
      # select either debug (non-prod) or release (prod) based on the command you ran in step 1
      - GIN_MODE=<debug | release>
```

- Open `.env`, uncomment the `CONFIG_PATH` var and update it with the path to the locally desired TOML you copied above
```conf
# select either config or compose based on the command you ran in step 1
CONFIG_PATH=config/<config | compose>.toml
```

5. Add any additional env vars to the `.env` file, e.g
```conf
; DB_PASSWORD & AUTH_TOKEN are user generated
; Be sure to generate your own if in prod
; See auth.md for how to do this
DB_PASSWORD="f52fbd32b2b3b86ff88ef6c490628285f482af15ddcb29541f94bcf526a3f6c7"
AUTH_TOKEN="f52fbd32b2b3b86ff88ef6c490628285f482af15ddcb29541f94bcf526a3f6c7"
```
