# Docs

Home for all content related to the SSI Service.

## Service Documentation

Service documentation is focused on explaining the "whys" and "hows" of the SSI Service. It is intended to be a
resource for developers and users of the SSI Service.

| Resource                                                                                     | Description                                       |
|----------------------------------------------------------------------------------------------|---------------------------------------------------|
| [Vision](https://github.com/TBD54566975/ssi-service/blob/main/doc/service/vision.md)         | Describes the vision for the service              |
| [Versioning](https://github.com/TBD54566975/ssi-service/blob/main/doc/service/versioning.md) | Describes versioning practices for the service    |
| [Webhooks](https://github.com/TBD54566975/ssi-service/blob/main/doc/service/webhook.md)      | Describes how to use webhooks in the service      |
| [Features](https://github.com/TBD54566975/ssi-service/blob/main/doc/service/features.md)     | Features currently supported by the service       |
| [Authorization](https://github.com/TBD54566975/ssi-service/blob/main/doc/service/authorization.md)     | How to setup token authentication and extend for authorization      |


## Service Improvement Proposals (SIPs)

All feature proposal documents for the SSI Service follow a common format and are known as SSI Improvement Proposals or
SIPs. SIPs [have their own documentation which can be found here](https://github.com/TBD54566975/ssi-service/blob/main/doc/sip/README.md)

## Configuration

There are a few ways to configure the service. There are a few choices you can make, including which database to use,
which DID methods to enable, and which port to listen on. Read the docs below for more details!

| Resource                                                                                                   | Description                            |
|------------------------------------------------------------------------------------------------------------|----------------------------------------|
| [TOML Config Files](https://github.com/TBD54566975/ssi-service/blob/main/doc/config/toml.md)                   | Describes how to use TOML config files |
| [Using a Cloud Key Management Service](https://github.com/TBD54566975/ssi-service/blob/main/doc/config/kms.md) | Describes how to configure a KMS       |
| [Storage](https://github.com/TBD54566975/ssi-service/blob/main/doc/service/storage.md)       | Describes alternatives for storage by the service |
| [Authentication](https://github.com/TBD54566975/ssi-service/blob/main/doc/service/authorization.md)       | Describes how to setup out of the box token authentication |

## API Documentation

API documentation is generated using [Swagger](https://swagger.io/). The most recent API docs file [can be found here](doc/swagger.yaml), which can be pasted into the [Swagger Editor](https://editor.swagger.io/) for interaction.

When running the service you can find API documentation at: `http://localhost:8080/swagger/index.html`

**Note:** Your port may differ; swagger docs are hosted on the same endpoint as the ssi service itself.

## How To's

How to documentation is focused on explaining usage of the SSI Service. It is intended to be a resource for users of
the SSI Service to get up to speed with its functionality.

| Resource                                                                                                                                     | Description                                            |
|----------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------|
| [Creating a DID](https://github.com/TBD54566975/ssi-service/blob/main/doc/howto/credential.md)                                               | Get started with DID functionality                     |
| [Creating a Schema](https://github.com/TBD54566975/ssi-service/blob/main/doc/howto/schema.md)                                                | Get started with schema functionality                  |
| [Issuing a Credential](https://github.com/TBD54566975/ssi-service/blob/main/doc/howto/credential.md)                                         | Get started with credential issuance functionality     |
| [Verify a Credential](https://github.com/TBD54566975/ssi-service/blob/main/doc/howto/verification.md)                                        | Get started with credential verification functionality |
| [Revoke/Suspend a Credential](https://github.com/TBD54566975/ssi-service/blob/main/doc/howto/status.md)                                      | Get started with credential status functionality       |
| [[TODO] Requesting and Verifying Credentials with Presentation Exchange](https://github.com/TBD54566975/ssi-service/issues/606)              | Get started with Presentation Exchange functionality   |
| [[TODO] Accepting Applications for and Issuing Credentials using Credential Manifest](https://github.com/TBD54566975/ssi-service/issues/606) | Get started with Credential Manifest functionality     |
| [Link your DID with a Website](./howto/wellknown.md)                                                                                         | Get started with DID Well Known functionality          |


