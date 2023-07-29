# How To: Create a Credential

## Background

A [Verifiable Credential (VC)](https://www.w3.org/TR/vc-data-model/) is a standard format to package a set of claims that an _issuer_ makes about a _subject_. The Verifiable Credentials Data Model, a W3C standard, introduces a number of concepts, most notable among them, the [three party model](https://www.w3.org/TR/vc-data-model/#ecosystem-overview) of **issuers**, **holders**, and **verifiers**. The model is a novel way of empowering entities to have tamper-evident representations of their data which acts as a mechanism to present the data to any third party (a verifier) without necessitating contact between the verifier and issuer. With the three party model entities are given more [control, transparency, privacy, and utility](https://www.lifewithalacrity.com/2016/04/the-path-to-self-soverereign-identity.html) for data that is rightfully theirs.

VCs are defined by a data model, which does not provide guidance on transmitting or sharing credentials between parties (protocols). The data model also does not provide guidance on _securing_ the credential (which puts the verifiable in verifiable credential). There are two prominent options here: [Data Integrity](https://www.w3.org/TR/vc-data-integrity/) and [JOSE/COSE](https://www.w3.org/TR/vc-jose-cose/) both of which we have demonstrated support for. The data model has a number of required (core) properties, and multiple means of extension to meet many use cases and functional needs.

## VCs in the SSI Service

VCs are a core component of SSI (Self Sovereign Identity) systems and work hand-in-hand with [DIDs](did.md). In our system, DIDs are used to represent the _issuer_ as well as the _subject_ of a credential. To define which content is in a VC we make use of [JSON schemas](schema.md).

The SSI Service is transport-agnostic and does not mandate the usage of a single mechanism to deliver credentials to an intended holder. We have begun integration with both [Web5](https://github.com/TBD54566975/dwn-sdk-js#readme) and [OpenID Connect](https://openid.net/sg/openid4vc/) transportation mechanisms but leave the door open to any number of possibile options.

At present, the service supports issuing credentials using the [v1.1 data model as a JWT](https://www.w3.org/TR/vc-data-model/#json-web-token). There is support for verifying credentials that make use of select [Data Integrity cryptographic suites](https://w3c.github.io/vc-data-integrity/) though use is discouraged due to complexity and potential security risks. Support for [v2.0](https://w3c.github.io/vc-data-model/) of the data model is planned and coming soon!

Out of the box we have support for exposing two [credential statuses](status.md) using the [Verifiable Credentials Status List](https://w3c.github.io/vc-status-list-2021/) specification: suspension and revocation.

## Creating a Verifiable Credential

Creating a credential using the SSI Service currently requires four pieces of data: an `issuer` DID, a `verificationMethodId` which must be contained within the issuer's DID Document, a `subject` DID (the DID who the claims are about), and `data` which is an arbitrary JSON object for the claims that you wish to be in the credential (in the `credentialSubject` property).

There are additional optional properties that let you specify `evidence`, an `expiry`, and whether you want to make the credential `revocable` or `suspendable`. Let's keep things simple and issue our first credential which will attest to a person's first and last name.

### 1. Create an issuer DID

We need two pieces of issuer information to create the credential: their DID and a verification method identifier. To get both, let's create a `did:key` to act as the issuer, with the following `PUT` command to `/v1/dids/key`.

```bash
curl -X PUT localhost:3000/v1/dids/key -d '{"keyType": "Ed25519"}'
```

We get back a response with the `id` as `did:key:z6Mkm1TmRWRPK6n21QncUZnk1tdYkje896mYCzhMfQ67assD`. Since we're using DID key we know that there is only a single key and its' `verificationMethodId` is the DID suffix: `did:key:z6Mkm1TmRWRPK6n21QncUZnk1tdYkje896mYCzhMfQ67assD#z6Mkm1TmRWRPK6n21QncUZnk1tdYkje896mYCzhMfQ67assD`. This value could be retrieved by resolving the DID or by making a `GET` request to `/v1/dids/key/did:key:z6Mkm1TmRWRPK6n21QncUZnk1tdYkje896mYCzhMfQ67assD` as well.

### 2. Create a person schema

Because we want to include information about the subject in the credential, let's first create a schema to define the shape of the credential's data with required `firstName` and `lastName` values. While this step is optional, it's a good practice to have a schema that describes the shape of the data.

Once we have our schema, we'll submit it to the service with a `PUT` request to `v1/schemas` as follows:

```bash
curl -X PUT localhost:3000/v1/schemas -d '{
  "name": "Person Credential",
  "schema": {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {
      "credentialSubject": {
        "type": "object",
        "properties": {
          "firstName": {
            "type": "string"
         },
          "lastName": {
            "type": "string"
         }
        },
        "required": ["firstName", "lastName"]
      }
    }
  }
}'
```

After submission we get back an identifier to refer to the schema as `aed6f4f0-5ed7-4d7a-a3df-56430e1b2a88`.

### 3. Create a credential

Separately, we've figured out that the subject we're creating the credential for has the DID `did:key:z6MkmNnvnfzW3nLiePweN3niGLnvp2BjKx3NM186vJ2yRg2z`. Now we have all the set up done we're ready to create our credential.

Construct a `PUT` request to `/v1/credentials` as follows:

```bash
curl -X PUT localhost:3000/v1/credentials -d '{
  "issuer": "did:key:z6Mkm1TmRWRPK6n21QncUZnk1tdYkje896mYCzhMfQ67assD",
  "verificationMethodId": "did:key:z6Mkm1TmRWRPK6n21QncUZnk1tdYkje896mYCzhMfQ67assD#z6Mkm1TmRWRPK6n21QncUZnk1tdYkje896mYCzhMfQ67assD",
  "subject": "did:key:z6MkmNnvnfzW3nLiePweN3niGLnvp2BjKx3NM186vJ2yRg2z",
  "schemaId": "aed6f4f0-5ed7-4d7a-a3df-56430e1b2a88",
  "data": {
    "firstName": "Satoshi",
    "lastName": "Nakamoto"
  }
}'
```

Upon success we see a response such as:

```json
{
  "id": "46bc3d25-6aaf-4f50-99ed-61c4b35f6411",
  "fullyQualifiedVerificationMethodId": "did:key:z6Mkm1TmRWRPK6n21QncUZnk1tdYkje896mYCzhMfQ67assD#z6Mkm1TmRWRPK6n21QncUZnk1tdYkje896mYCzhMfQ67assD",
  "credential": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "id": "http://localhost:3000/v1/credentials/46bc3d25-6aaf-4f50-99ed-61c4b35f6411",
    "type": ["VerifiableCredential"],
    "issuer": "did:key:z6Mkm1TmRWRPK6n21QncUZnk1tdYkje896mYCzhMfQ67assD",
    "issuanceDate": "2023-07-28T12:45:15-07:00",
    "credentialSubject": {
      "id": "did:key:z6MkmNnvnfzW3nLiePweN3niGLnvp2BjKx3NM186vJ2yRg2z",
      "firstName": "Satoshi",
      "lastName": "Nakamoto"
    },
    "credentialSchema": {
      "id": "aed6f4f0-5ed7-4d7a-a3df-56430e1b2a88",
      "type": "JsonSchema2023"
    }
  },
  "credentialJwt": "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa20xVG1SV1JQSzZuMjFRbmNVWm5rMXRkWWtqZTg5Nm1ZQ3poTWZRNjdhc3NEI3o2TWttMVRtUldSUEs2bjIxUW5jVVpuazF0ZFlramU4OTZtWUN6aE1mUTY3YXNzRCIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2OTA1NzM1MTUsImlzcyI6ImRpZDprZXk6ejZNa20xVG1SV1JQSzZuMjFRbmNVWm5rMXRkWWtqZTg5Nm1ZQ3poTWZRNjdhc3NEIiwianRpIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwL3YxL2NyZWRlbnRpYWxzLzQ2YmMzZDI1LTZhYWYtNGY1MC05OWVkLTYxYzRiMzVmNjQxMSIsIm5iZiI6MTY5MDU3MzUxNSwibm9uY2UiOiIzMGMwNDYxZi1jMWUxLTQwNDctYWUwYS01NjgzMjdkMzY4YTYiLCJzdWIiOiJkaWQ6a2V5Ono2TWttTm52bmZ6VzNuTGllUHdlTjNuaUdMbnZwMkJqS3gzTk0xODZ2SjJ5UmcyeiIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiZmlyc3ROYW1lIjoiU2F0b3NoaSIsImxhc3ROYW1lIjoiTmFrYW1vdG8ifSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6ImFlZDZmNGYwLTVlZDctNGQ3YS1hM2RmLTU2NDMwZTFiMmE4OCIsInR5cGUiOiJKc29uU2NoZW1hMjAyMyJ9fX0.xwqpDuO6PDeEqYr6DflbeR6mhuwvVg0uR43i-7Zhy2DdaH1e3Jt4DuiMy09tZQ2jAXki0rjMNgLt7dPpzOl8BA"
}
```

In the `credential` property we see an unsecured, but readable, version of the VC. The VC is signed and packaged as a JWT in the `credentialJwt` property. If you're interested, you can decode the JWT using a tool such as [jwt.io](https://jwt.io/). If you were to 'issue' or transmit the credential to a _holder_ you would just send this JWT value.

## Getting Credentials

Once you've created multiple credentials, you can view all credentials by making a `GET` request to `/v1/credentials`. This endpoint also supports three query parameters: `issuer`, `schema`, and `subject` which can be used mutually exclusively.

You can get a single credential by making a `GET` request to `/v1/credentials/{id}`.

## Other Credential Operations

To learn about verifying credentials [read more here](verification.md). You can also learn more about [credential status here](status.md).

