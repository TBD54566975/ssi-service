[![godoc ssi-service](https://img.shields.io/badge/godoc-ssi--service-blue)](https://github.com/TBD54566975/ssi-service)
[![go version 1.19.4](https://img.shields.io/badge/go_version-1.19.4-brightgreen)](https://go.dev/)
[![license Apache 2](https://img.shields.io/badge/license-Apache%202-black)](https://github.com/TBD54566975/ssi-service/blob/main/LICENSE)
[![issues](https://img.shields.io/github/issues/TBD54566975/ssi-service)](https://github.com/TBD54566975/ssi-service/issues)
![push](https://github.com/TBD54566975/ssi-service/workflows/ssi-service-ci/badge.svg?branch=main&event=push)

# ssi-service

A web service that exposes the ssi-sdk as an HTTP API. Support operations for Verifiable Credentials, Decentralized Identifiers and things Self Sovereign Identity!

## Introduction
The Self Sovereign Identity Service (SSIS) facilitates all things relating to [DIDs](https://www.w3.org/TR/did-core/)
and [Verifiable Credentials](https://www.w3.org/TR/vc-data-model) - in a box! The service is a part of a larger
Decentralized Web Platform architecture which you can learn more about in our
[collaboration repo](https://github.com/TBD54566975/collaboration).

## Core Functionality
- Create and manage Decentralized Identifiers
- Create and manage Verifiable Credentials
- Credential Suspension
- Interacting with the standards around Verifiable Credentials such as
  - Credential Revocations
  - Applying for Credentials
  - Exchanging Credentials
  - Data Schemas (for credentials and other verifiable data)

## Use Cases (more to come!)
### Business: Issuing Verifiable Credentials <br />
[Follow Tutorial](https://developer.tbd.website/docs/tutorials/issue-verifiable-credential-manually)

Steps to issue an Employment Status Credential:
1. Spin up and host the SSI-Service
2. Add the ability for your employees to click 'apply for a credential' on your internal EMS (should we show a front end button code example)
3. [Create an Issuer DID](blob/main/integration/common.go#L36) for your business
4. [Create a Schema](blob/main/integration/common.go#L66)
5. [Create a Credential Manifest](blob/main/integration/common.go#L154)
6. [Submit a Credential Application](blob/main/integration/common.go#L173)

## Configuration

Managed via:
[TOML](https://toml.io/en/) [file](https://github.com/TBD54566975/ssi-service/blob/main/config/config.toml)

There are sets of configuration values for the server (e.g. which port to listen on), the services (e.g. which database to use),
and each service. Each service may define specific configuration, such as which DID methods are enabled for the DID
service.

### Steps for SSI-Service to consume its configuration:
1. On startup: SSI-Service loads default values into the SSIServiceConfig
2. Checks for a TOML config file:
  - If exists...load toml file
  - If does not exist...it uses a default config defined in the code inline
3. Finally, it loads the config/.env file and adds the env variables defined in this file to the final SSIServiceConfig

## Build & Test

This project uses [mage](https://magefile.org/), please
view [CONTRIBUTING](https://github.com/TBD54566975/ssi-service/blob/main/CONTRIBUTING.md) for more information.

After installing mage, you can build and test the SDK with the following commands:

```
mage build
mage test
```

A utility is provided to run _clean, build, and test_ in sequence with:

```
mage cbt
```

## Deployment

The service is packaged as a [Docker container](https://www.docker.com/), runnable in a wide variety of
environments.

[Docker Compose](https://docs.docker.com/compose/) is used for simplification and orchestration. To run
the service, you can use the following command, which will start the service on port `8080`:
```shell
mage run
```

Or, you can run docker-compose yourself:
```shell
cd build && docker-compose up --build
```

## Health and Readiness Checks

Note: port 3000 is used by default, specified in `config.toml`, for the SSI Service process. If you're running
via `mage run` or docker compose, the port to access will be `8080`.

Run for health check (status: OK, then you are up):

```shell
 ~ curl localhost:3000/health
{"status":"OK"}
```

Run to check if all services are up and ready (credential, did, and schema):

```bash
~ curl localhost:8080/readiness
{
    "status": {
        "status": "ready",
        "message": "all service ready"
    },
    "serviceStatuses": {
        "credential": {
            "status": "ready"
        },
        "did": {
            "status": "ready"
        },
        "schema": {
            "status": "ready"
        }
    }
}
```

## Continuous Integration

CI is managed via [GitHub Actions](https://github.com/TBD54566975/ssi-service/actions). Actions are triggered to run
for each Pull Request, and on merge to `main`. You can run CI locally using a tool
like [act](https://github.com/nektos/act).

## HTTP Endpoints
You can find all HTTP endpoints by checking out the swagger docs at: `http://localhost:8002/docs`

Note: Your port by differ, the range of the ports for swagger are between `8002` and `8080`.

## What's Supported?
- [x] [DID Management](https://www.w3.org/TR/did-core/)
  - [x] [did:key](https://w3c-ccg.github.io/did-method-key/)
  - [x] [did:web](https://w3c-ccg.github.io/did-method-web/)
  - [ ] [did:ion](https://identity.foundation/ion/)
- [x] [Verifiable Credential Schema](https://w3c-ccg.github.io/vc-json-schemas/v2/index.html) Management
- [x] [Verifiable Credential](https://www.w3.org/TR/vc-data-model) Issuance & Verification
  - [x] Signing and verification with [JWTs](https://w3c.github.io/vc-jwt/)
  - [ ] Signing and verification with [Data Integrity Proofs](https://w3c.github.io/vc-data-integrity/)
- [x] Applying for Verifiable Credentials using [Credential Manifest](https://identity.foundation/credential-manifest/)
- [x] Requesting, Receiving, and the Validation of Verifiable Claims
  using [Presentation Exchange](https://identity.foundation/presentation-exchange/)
- [x] Status of Verifiable Credentials using the [Status List 2021](https://w3c-ccg.github.io/vc-status-list-2021/)
- [ ] Creating and managing Trust documents using [Trust Establishment](https://identity.foundation/trust-establishment/)
- [x] [DID Well Known Configuration](https://identity.foundation/.well-known/resources/did-configuration/) documents

## Vision, Features, and Development

The vision for the project is laid out in [this document](doc/VISION.md).

The project follows a proposal-based improvement format called [SIPs, outlined here.](sip/README.md).

Please [open a discussion](https://forums.tbd.website/c/self-sovereign-identity/16), join Discord [SSI conversations](https://discord.com/channels/937858703112155166/969272692891086868),
or [issue](https://github.com/TBD54566975/ssi-service/issues) if you are interested in helping shape the future of the project.

## Project Resources

| Resource                                                                                   | Description                                                                   |
|--------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| [VISION](https://github.com/TBD54566975/ssi-service/blob/main/doc/VISION.md)               | Outlines the project vision                                                   |
| [SIPs](sip/README.md)                                                                      | Proposals for improving the SSI Service                                       |
| [VERSIONING](https://github.com/TBD54566975/ssi-service/blob/main/doc/VERSIONING.md)       | Project versioning strategy                                                   |
| [CODEOWNERS](https://github.com/TBD54566975/ssi-service/blob/main/CODEOWNERS)              | Outlines the project lead(s)                                                  |
| [CODE_OF_CONDUCT](https://github.com/TBD54566975/ssi-service/blob/main/CODE_OF_CONDUCT.md) | Expected behavior for project contributors, promoting a welcoming environment |
| [CONTRIBUTING](https://github.com/TBD54566975/ssi-service/blob/main/CONTRIBUTING.md)       | Developer guide to build, test, run, access CI, chat, discuss, file issues    |
| [GOVERNANCE](https://github.com/TBD54566975/ssi-service/blob/main/GOVERNANCE.md)           | Project governance                                                            |
| [SECURITY](https://github.com/TBD54566975/ssi-service/blob/main/SECURITY.md)               | Vulnerability and bug reporting                                               |
| [LICENSE](https://github.com/TBD54566975/ssi-service/blob/main/LICENSE)                    | Apache License, Version 2.0                                                   |
