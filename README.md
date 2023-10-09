[![godoc ssi-service](https://img.shields.io/badge/godoc-ssi--service-blue)](https://github.com/TBD54566975/ssi-service)
[![go version 1.21.1](https://img.shields.io/badge/go_version-1.21.1-brightgreen)](https://go.dev/)
[![license Apache 2](https://img.shields.io/badge/license-Apache%202-black)](https://github.com/TBD54566975/ssi-service/blob/main/LICENSE)
[![issues](https://img.shields.io/github/issues/TBD54566975/ssi-service)](https://github.com/TBD54566975/ssi-service/issues)
![push](https://github.com/TBD54566975/ssi-service/workflows/ssi-service-ci/badge.svg?branch=main&event=push)

# ssi-service

The Self Sovereign Identity Service (SSIS) is a RESTful web service that facilitates all things relating
to [DIDs](https://www.w3.org/TR/did-core/),
[Verifiable Credentials](https://www.w3.org/TR/vc-data-model) and their related standards-based interactions. Most of
the functionality in this service
relies upon the SSI primitives exposed in the [SSI-SDK](https://github.com/TBD54566975/ssi-sdk) project.

## Core Functionality

- Lifecycle management for Decentralized Identifiers
    - Multiple local, web, and blockchain methods supported
- Create and manage Verifiable Credentials
    - Multiple securing mechanisms
    - Data schemas using JSON Schema
    - Lifecycle management with credential status (revocation, suspension, etc.)
- More robust DID and Verifiable Credential interactions such as...
    - Enabling the application of credentials
    - Verifying sets of credentials with custom logic
    - Linking a DID to a web domain
    - Integration into your existing systems with webhooks
    - Trust management
- And much more!

## Documentation

### Vision, Features, and Development

The vision for the project is laid out in [this document](doc/service/vision.md).

The project follows a proposal-based improvement format called [SIPs, outlined here](doc/sip/README.md).

Please [join Discord](https://discord.com/invite/tbd), or open an [issue](https://github.com/TBD54566975/ssi-service/issues) if you are interested in helping shape the future of the
project.

### API Documentation

API documentation is generated using [Swagger](https://swagger.io/). The most recent
docs [can be found here](doc/swagger.yaml).

When running the service you can find API documentation at: `http://localhost:8080/swagger/index.html`

**Note:** Your port may differ; swagger docs are hosted on the same endpoint as the ssi service itself.

### How To's

We have a set of tutorials and how-to documents, instructing you on how to create a DID, issue your first credential,
and more! The docs can be found [in our docs here](doc/README.md).

## Build & Test

### Local Development
This project uses [mage](https://magefile.org/), please
view [CONTRIBUTING](https://github.com/TBD54566975/ssi-service/blob/main/CONTRIBUTING.md) for more information.

After installing mage, you can build and test the SDK with the following commands:

```
mage build
mage test
```

A utility is provided to run _clean, build, lint, and test_ in sequence with:

```
mage cblt
```

### Continuous Integration

CI is managed via [GitHub Actions](https://github.com/TBD54566975/ssi-service/actions). Actions are triggered to run for
each Pull Request, and on merge to `main`.
You can run CI locally using a tool like [act](https://github.com/nektos/act).

## Deployment

The service is packaged as a [Docker container](https://www.docker.com/), runnable in a wide variety of
environments.

There are pre-build images built by GitHub Actions on each merge to the `main` branch,
which [you can access here](https://github.com/orgs/TBD54566975/packages?repo_name=ssi-service).

[Docker Compose](https://docs.docker.com/compose/) is used for simplification and orchestration. To run
the service, you can use the following command, which will start the service on port `8080`:

```shell
mage run
```

Or, you can run docker-compose yourself, building from source:

```shell
cd build && docker-compose up --build
```

To use the pre-published images:

```shell
cd build && docker-compose up -d
```

## Using the Service

### Configuration

Managed via:
[TOML](https://toml.io/en/) [file](config/dev.toml). Configuration documentation and sample config
files [can be found here](doc/README.md#configuration).

There are sets of configuration values for the server (e.g. which port to listen on), the services (e.g. which database
to use),
and each service. Each service may define specific configuration, such as which DID methods are enabled for the DID
service.

More information on configuration can be found in the [configuration section of our docs](doc/README.md).

### Authentication and Authorization

The SSI server uses the [Gin framework](https://github.com/gin-gonic/gin), which allows various kinds of middleware.
Look in `pkg/middleware/Authentication.go` and `pkg/middleware/Authorization.go` for details on how you can wire up
authentication and authorization for your use case.

### Health and Readiness Checks

Note: port 3000 is used by default, specified in `config` folder. An example would be [`dev.toml`](config/dev.toml), for the SSI Service process. If you're running
via `mage run` or docker compose, the port to access will be `8080`.

Run for health check (status: OK, then you are up):

```shell
 ~ curl localhost:3000/health | jq
```
```json
{
    "status": "OK"
}
```

Run to check if all services are up and ready (credential, did, and schema):

```bash
~ curl localhost:8080/readiness | jq
```
```json
{
  "status": {
    "status": "ready",
    "message": "all services ready"
  },
  "serviceStatuses": {
    "credential": {
      "status": "ready"
    },
    "did": {
      "status": "ready"
    },
    "issuance": {
      "status": "ready"
    },
    "keystore": {
      "status": "ready"
    },
    "manifest": {
      "status": "ready"
    },
    "operation": {
      "status": "ready"
    },
    "presentation": {
      "status": "ready"
    },
    "schema": {
      "status": "ready"
    },
    "webhook": {
      "status": "ready"
    }
  }
}
```

## Project Resources

| Resource                                                                                   | Description                                                                   |
|--------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| [Components Readme](https://github.com/TBD54566975/ssi-service/blob/main/doc/README.md)    | Documentation for various components of the SSI Service                       |
| [VISION](https://github.com/TBD54566975/ssi-service/blob/main/doc/VISION.md)               | Outlines the project vision                                                   |
| [SIPs](doc/sip/README.md)                                                                      | Proposals for improving the SSI Service                                       |
| [VERSIONING](https://github.com/TBD54566975/ssi-service/blob/main/doc/VERSIONING.md)       | Project versioning strategy                                                   |
| [CODEOWNERS](https://github.com/TBD54566975/ssi-service/blob/main/CODEOWNERS)              | Outlines the project lead(s)                                                  |
| [CODE_OF_CONDUCT](https://github.com/TBD54566975/ssi-service/blob/main/CODE_OF_CONDUCT.md) | Expected behavior for project contributors, promoting a welcoming environment |
| [CONTRIBUTING](https://github.com/TBD54566975/ssi-service/blob/main/CONTRIBUTING.md)       | Developer guide to build, test, run, access CI, chat, discuss, file issues    |
| [GOVERNANCE](https://github.com/TBD54566975/ssi-service/blob/main/GOVERNANCE.md)           | Project governance                                                            |
| [SECURITY](https://github.com/TBD54566975/ssi-service/blob/main/SECURITY.md)               | Vulnerability and bug reporting                                               |
| [LICENSE](https://github.com/TBD54566975/ssi-service/blob/main/LICENSE)                    | Apache License, Version 2.0                                                   |
