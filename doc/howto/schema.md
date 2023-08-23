# How To: Create a Schema

## Background

When creating [Verifiable Credentials](https://www.w3.org/TR/vc-data-model) it's useful to have a mechanism to define the shape the data in the credential takes, in a consistent manner. The VC Data Model uses an open world data model, and with it, provides a mechanism to "extend" the core terminology to add any term with a technology known as [JSON-LD](https://json-ld.org/). JSON-LD is responsible for the `@context` property visible in VCs, DIDs, and other documents in the SSI space. However, JSON-LD is focused on _semantics_, answering the question "do we have a shared understanding of what this thing is?" more specifically, for a name credential, does your concept of "name" match mine. Though the core data model is a JSON-LD data model, processing VCs as JSON-LD is not a requirement. The SSI Service chooses to take a simpler approach and [process VCs as pure JSON](https://www.w3.org/TR/vc-data-model/#json).

When constructing and processing VCs as pure JSON it is useful to have a mechanism to define the data and add some light validation onto the shape that data takes. [JSON Schema](https://json-schema.org/) is a widely used, and widely supported toolset that enables such functionalty: the ability to define a schema, which provides a set of properties (both required and optional), and some light validation on top of those properties. The VC Data Model has [a section on data schemas](https://www.w3.org/TR/vc-data-model/#data-schemas) that enables this functionality.

## Intro to JSON Schema with Verifiable Credentials

Making use of the `credentialSchema` property [defined in the VC Data Model](https://www.w3.org/TR/vc-data-model/#data-schemas) TBD and other collaborators in the W3C are working on [a new specification](https://w3c.github.io/vc-json-schema/) which enables a standards-compliant path to using JSON Schema with Verifiable Credentials. The VC JSON Schema specification defines two options for using JSON Schemas: the first, a plan JSON Schema that can apply to _any set of properties_ in a VC, and the second, a Verifiable Credential that wraps a JSON Schema.

In some cases it is useful to package a JSON Schema as a Verifiable Credential to retain information about authorship (who created the schema), when it was created, and enable other features the VC Data Model offers, such as the ability to suspend the usage of a schema with [a status](https://www.w3.org/TR/vc-data-model/#status).

An example email JSON Schema using [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12/json-schema-core.html) is provided below:

```json
{
  "$id": "https://example.com/schemas/email.json",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "name": "Email Address",
  "type": "object",
  "properties": {
    "emailAddress": {
      "type": "string",
      "format": "email"
    }
  },
  "required": ["emailAddress"]
}
```

We can see that the schema defines a property `emailAddress` of JSON type `string`, and it is required. This means that any piece of JSON we apply this schema to will pass if a valid `emailAddress` property is present and fail otherwise.

Now that we have a valid JSON Schema, we'll need to transform it so it's useful in being applied to a Verifiable Credential, not just any arbitrary JSON. We know that we want the presence of an `emailAddress` in the `credentialSubject` property of a VC and adjust the schema accordingly:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "name": "Email Credential",
  "type": "object",
  "properties": {
    "credentialSubject": {
      "type": "object",
      "properties": {
        "emailAddress": {
          "type": "string",
          "format": "email"
        }
      },
      "required": ["emailAddress"]
    }
  }
}
```

Now our schema, applied to a Verifiable Credential, will guarantee that the `credentialSubject` property contains a valid `emailAddress` property.

## Creating a Schema

The service exposes a set of APIs for managing schemas. To create a schema you have two options: signed or not. As mentioned earlier, the signed version of a schema is packaged as a Verifiable Credential. To create a signed schema you'll need to pass in two additional properties – the issuer DID and the ID of the verification method to use to sign the schema. We'll keep things simple for now and create an unsigned schema.

After forming a valid JSON Schema, generate a `PUT` request to `/v1/schemas` as follows:

```bash
curl -X PUT localhost:3000/v1/schemas -d '{
  "name": "Email Credential",
  "schema": {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {
      "credentialSubject": {
        "type": "object",
        "properties": {
          "emailAddress": {
            "type": "string",
            "format": "email"
          }
        },
        "required": ["emailAddress"]
      }
    }
  }
}'
```

Upon success you'll see a response which includes the schema you passed in, with a service-generated identifier for the schema. You'll also notice a type `JsonSchema`, which is defined by the [VC JSON Schema specification](https://w3c.github.io/vc-json-schema/#jsonschema):

```json
{
  "id": "ebeebf7b-d452-4832-b8d3-0042ec80e108",
  "type": "JsonSchema",
  "schema": {
    "$id": "http://localhost:3000/v1/schemas/ebeebf7b-d452-4832-b8d3-0042ec80e108",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "name": "Email Credential",
    "properties": {
      "credentialSubject": {
        "properties": {
          "emailAddress": {
            "format": "email",
            "type": "string"
          }
        },
        "required": [
          "emailAddress"
        ],
        "type": "object"
      }
    },
    "type": "object"
  }
}
```

Now you're ready to use the schema in [creating a credential](credential.md).

## Getting Schemas

Once you've created multiple schemas, you can view them all by make a `GET` request to the `v1/schemas` endpoint. Future enhancements may enable filtering based on name, author, or other properties.

You can get a specific schema by make a `GET` request to the `v1/schemas/{schemaId}` endpoint.

