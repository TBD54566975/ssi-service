[![godoc ssi-service](https://img.shields.io/badge/godoc-ssi--service-blue)](https://github.com/TBD54566975/ssi-service)
[![go version 1.20.6](https://img.shields.io/badge/go_version-1.20.6-brightgreen)](https://go.dev/)
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
3. [Create an Issuer DID](https://github.com/TBD54566975/ssi-service/blob/eabbb2a58eec06ce3998d088811c4afc53026afd/integration/common.go#L38) for your business
4. [Create a Schema](https://github.com/TBD54566975/ssi-service/blob/eabbb2a58eec06ce3998d088811c4afc53026afd/integration/common.go#L90)
5. [Create a Credential Manifest](https://github.com/TBD54566975/ssi-service/blob/main/integration/common.go#L180)
6. [Submit a Credential Application](https://github.com/TBD54566975/ssi-service/blob/eabbb2a58eec06ce3998d088811c4afc53026afd/integration/common.go#L199)

## Configuration

Managed via:
[TOML](https://toml.io/en/) [file](config/dev.toml)

There are sets of configuration values for the server (e.g. which port to listen on), the services (e.g. which database to use),
and each service. Each service may define specific configuration, such as which DID methods are enabled for the DID
service.

### Key Management

SSI-service can store keys that are used to digitally sign credentials (and other data). All such keys are encrypted at
the application before being stored using a MasterKey (a.k.a. a Key Encryption Key or KEK). The MasterKey can be
generated automatically during boot time, or we can use the MasterKey housed in an external Key 
Management System (KMS) like GCP KMS or AWS KMS.

For production deployments, using external KMS is strongly recommended.

To use an external KMS: 
1. Create a symmetric encryption key in your KMS. You MUST select the algorithm that uses AES-256 block cipher in Galois/Counter Mode (GCM). At the time of writing, this is the only algorithm supported by AWS and GCP.
2. Set the `master_key_uri` field of the `[services.keystore]` section using the format described in [tink](https://github.com/google/tink/blob/9bc2667963e20eb42611b7581e570f0dddf65a2b/docs/KEY-MANAGEMENT.md#key-management-systems)
(we use the tink library under the hood).
3. Set the `kms_credentials_path` field of the `[services.keystore]` section to point to your credentials file, according to [this section](https://github.com/google/tink/blob/9bc2667963e20eb42611b7581e570f0dddf65a2b/docs/KEY-MANAGEMENT.md#credentials).
4. Win!

To use a randomly generated encryption key (NOT RECOMMENDED FOR ANY PRODUCTION ENVIRONMENT):
1. Make sure that `master_key_uri` and `kms_credentials_path` of the `[services.keystore]` section are not set.

Note that at this time, we do not currently support rotating the master key.

### Steps for SSI-Service to consume its configuration:
1. On startup: SSI-Service loads default values into the SSIServiceConfig
2. Checks for a TOML config file:
- If exists...load toml file
- If does not exist...it uses a default config defined in the code inline
3. Finally, it loads the config/.env file and adds the env variables defined in this file to the final SSIServiceConfig

### Authentication and Authorization

The ssi server uses the Gin framework from Golang, which allows various kinds of middleware. Look in `pkg/middleware/Authentication.go` and `pkg/middleware/Authorization.go` for details on how you can wire up authentication and authorization for your use case.

## Pre-built images to use

There are pre-build images built by github actions on each merge to the main branch, which you can access here:
https://github.com/orgs/TBD54566975/packages?repo_name=ssi-service


## Build & Test

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

## Deployment

The service is packaged as a [Docker container](https://www.docker.com/), runnable in a wide variety of
environments.

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

## API Documentation
You can find all HTTP endpoints by checking out the swagger docs at: `http://localhost:8080/swagger/index.html`

Note: Your port may differ; swagger docs are hosted on the same endpoint as the ssi service itself.

## What's Supported?
- [x] [DID Management](https://www.w3.org/TR/did-core/)
  - [x] [did:key](https://w3c-ccg.github.io/did-method-key/)
  - [x] [did:web](https://w3c-ccg.github.io/did-method-web/)
  - [x] [did:ion](https://identity.foundation/ion/) _Note: updates not yet supported_
  - [x] [did:pkh](https://w3c-ccg.github.io/did-method-pkh/) _Resolution only_
  - [x] [did:peer](https://identity.foundation/peer-did-method-spec/) _Resolution only_
- [x] [Verifiable Credential Schema](https://w3c-ccg.github.io/vc-json-schemas/v2/index.html) Management
- [x] [Verifiable Credential](https://www.w3.org/TR/vc-data-model) Issuance & Verification
  - [x] Signing and verification with [JWTs](https://w3c.github.io/vc-jwt/)
  - [ ] Signing and verification with [Data Integrity Proofs](https://w3c.github.io/vc-data-integrity/)
- [x] Applying for Verifiable Credentials using [Credential Manifest](https://identity.foundation/credential-manifest/)
- [x] Requesting, Receiving, and the Validation of Verifiable Claims
  using [Presentation Exchange](https://identity.foundation/presentation-exchange/)
- [x] Status of Verifiable Credentials using the [Status List 2021](https://w3c-ccg.github.io/vc-status-list-2021/)
- [x] [DID Well Known Configuration](https://identity.foundation/.well-known/resources/did-configuration/) documents
- [ ] Creating and managing Trust documents using [Trust Establishment](https://identity.foundation/trust-establishment/)

## Vision, Features, and Development

The vision for the project is laid out in [this document](doc/VISION.md).

The project follows a proposal-based improvement format called [SIPs, outlined here.](sip/README.md).

Please [join Discord](https://discord.com/invite/tbd),
or open an [issue](https://github.com/TBD54566975/ssi-service/issues) if you are interested in helping shape the future of the project.


## Project Resources

| Resource                                                                                   | Description                                                                   |
|--------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| [Components Readme](https://github.com/TBD54566975/ssi-service/blob/main/doc/README.md)    | Documentation for various components of the SSI Service                       |
| [VISION](https://github.com/TBD54566975/ssi-service/blob/main/doc/VISION.md)               | Outlines the project vision                                                   |
| [SIPs](sip/README.md)                                                                      | Proposals for improving the SSI Service                                       |
| [VERSIONING](https://github.com/TBD54566975/ssi-service/blob/main/doc/VERSIONING.md)       | Project versioning strategy                                                   |
| [CODEOWNERS](https://github.com/TBD54566975/ssi-service/blob/main/CODEOWNERS)              | Outlines the project lead(s)                                                  |
| [CODE_OF_CONDUCT](https://github.com/TBD54566975/ssi-service/blob/main/CODE_OF_CONDUCT.md) | Expected behavior for project contributors, promoting a welcoming environment |
| [CONTRIBUTING](https://github.com/TBD54566975/ssi-service/blob/main/CONTRIBUTING.md)       | Developer guide to build, test, run, access CI, chat, discuss, file issues    |
| [GOVERNANCE](https://github.com/TBD54566975/ssi-service/blob/main/GOVERNANCE.md)           | Project governance                                                            |
| [SECURITY](https://github.com/TBD54566975/ssi-service/blob/main/SECURITY.md)               | Vulnerability and bug reporting                                               |
| [LICENSE](https://github.com/TBD54566975/ssi-service/blob/main/LICENSE)                    | Apache License, Version 2.0                                                   |
