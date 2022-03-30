[![godoc](https://img.shields.io/badge/godoc-vc--service-blue)](https://pkg.go.dev/github.com/TBD54566975/vc-service)
[![goversion](https://img.shields.io/badge/go_version-1.17.6-brightgreen)](https://golang.org/)
[![license](https://img.shields.io/badge/license-Apache%202-black)](https://github.com/TBD54566975/vc-service/blob/main/LICENSE)
[![issues](https://img.shields.io/github/issues/TBD54566975/vc-service)](https://github.com/TBD54566975/vc-service/issues)

# vc-service

## Introduction

The Verifiable Credentials Service (VCS) facilitates all things [Verifiable Credentials](https://www.w3.org/TR/vc-data-model)
-- in a box! The service is a part of a larger Decentralized Web Platform architecture which you can learn more about
in our [collaboration repo](https://github.com/TBD54566975/collaboration). The VC Service is a RESTful web service that
wraps the [did-sdk](https://github.com/TBD54566975/did-sdk). The core functionality of the VCS includes, 
but is not limited to: interacting with the standards around Verifiable Credentials, Credential Revocations, requesting
Credentials, exchanging Credentials, data schemas for Credentials and other verifiable data, messaging using ID Hubs,
and usage of Decentralized Identifiers. Using these core standards, the VCS enables robust functionality to facilitate
all verifiable interactions such as creating, signing, issuing, curating, requesting, revoking, exchanging, validating, 
verifying credentials in varying degrees of complexity.


## Deployment

The service will be packaged as a [Docker container](https://www.docker.com/), runnable in a wide variety of
environments. It may be expanded to support multiple protocols and transports besides HTTP/REST.

## What's Supported?

- [] [DID Management](https://www.w3.org/TR/did-core/)
- [] [Verifiable Credential Schema](https://w3c-ccg.github.io/vc-json-schemas/v2/index.html) Management
- [] [Verifiable Credential](https://www.w3.org/TR/vc-data-model) Issuance & Verification
- [] Requesting, Receiving, and the Validation of Verifiable Claims using [Presentation Exchange](https://identity.foundation/presentation-exchange/)
- [] Applying for Verifiable Credentials using [Credential Manifest](https://identity.foundation/credential-manifest/)
- [] Revocations of Verifiable Credentials using the [Status List 2021](https://w3c-ccg.github.io/vc-status-list-2021/)
- [] [ID Hub](https://identity.foundation/identity-hub/spec/) Messaging

## Design Thinking

The design of the service, at present, assumes it will be run by a single organization. Further design work is needed
around authentication and authorization schemes to access the service and its functionalities, possible User Interfaces
to use the service, and much more!

## Contributing

This project is fully open source, and we welcome contributions! For more information please see
[CONTRIBUTING](CONTRIBUTING.md). Our current thinking about the development of the library is captured in
[GitHub Issues](https://github.com/TBD54566975/vc-service/issues).

## Project Resources

| Resource                                   | Description                                                                   |
|--------------------------------------------|-------------------------------------------------------------------------------|
| [CODEOWNERS](./CODEOWNERS)                 | Outlines the project lead(s)                                                  |
| [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) | Expected behavior for project contributors, promoting a welcoming environment |
| [CONTRIBUTING.md](./CONTRIBUTING.md)       | Developer guide to build, test, run, access CI, chat, discuss, file issues    |
| [GOVERNANCE.md](./GOVERNANCE.md)           | Project governance                                                            |
| [LICENSE](./LICENSE)                       | Apache License, Version 2.0                                                   |