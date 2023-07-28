# How To: Create a Schema

## Background

When creating [Verifiable Credentials](https://www.w3.org/TR/vc-data-model) it's useful to have a mechanism to define the shape the data in the credential takes, in a consistent manner. The VC Data Model uses an open world data model, and with it, provides a mechanism to "extend" the core terminology to add any term with a technology known as [JSON-LD](https://json-ld.org/). JSON-LD is responsible for the `@context` property visible in VCs, DIDs, and other documents in the SSI space. However, JSON-LD is focused on _semantics_, answering the question "do we have a shared understanding of what this thing is?" more specifically, for a name credential, does your concept of "name" match mine. Though the core data model is a JSON-LD data model, processing VCs as JSON-LD is not a requirement. The SSI Service chooses to take a simpler approach and [process VCs as pure JSON](https://www.w3.org/TR/vc-data-model/#json).

When constructing and processing VCs as pure JSON it is useful to have a mechanism to define the data and add some light validation onto the shape that data takes. [JSON Schema](https://json-schema.org/) is a widely used, and widely supported toolset that enables such functionalty: the ability to define a schema, which provides a set of properties (both required and optional), and some light validation on top of those properties. The VC Data Model has [a section on data schemas](https://www.w3.org/TR/vc-data-model/#data-schemas) that enables this functionality.

## Intro to JSON Schema with Verifiable Credentials

Making use of the `credentialSchema` property [defined in the VC Data Model](https://www.w3.org/TR/vc-data-model/#data-schemas) TBD and other collaborators in the W3C are working on [a new specification](https://w3c.github.io/vc-json-schema/) which enables a standards-compliant path to using JSON Schema with Verifiable Crednetials. The VC JSON Schema specification defines two options for using JSON Schemas: the first, a plan JSON Schema that can apply to _any set of properties_ in a VC, and the second, a Verifiable Credential that wraps a JSON Schema.

In some cases it is useful to package a JSON Schema as a Verifiable Credential to retain information about authorship (who created the schema), when it was created, and enable other features the VC Data Model offers, such as the ability to suspend the usage of a schema with [a status](https://www.w3.org/TR/vc-data-model/#status).

An example JSON Schema using [JSON Schema Draft 2020-12]() providing an `emailAddress` property is shown below:

```json

```



## Creating a Schema

