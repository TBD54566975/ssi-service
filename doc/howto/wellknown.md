# How To: Link your DID with a Website

## Background

A [DID Configuration Resource](https://identity.foundation/.well-known/resources/did-configuration/) provides proof of a bi-directional relationship between the controller of a web domain and a DID via cryptographically verifiable signature, associated with a DID's key material.

## Steps

You can use a DID Configuration Resource to advertise that the same entity which controls a given website also controls a DID. The SSI Service does all the heavy lifting to make it easy to create such a resource, linking DIDs that created within the service to a website you control. The steps for doing so are outlined below.

### Prerequisites

* A DID was created with SSI Service. See [How To: Create A DID](./did.md)
* You control an origin (e.g. like https://www.tbd.website).
* You are able to host files in a path within that origin.(e.g. you can host the file returned by https://www.tbd.website/.well-known/did-configuration.json)

For the purposes of our example, let's assume that the did created was `did:key:z6MkkZDjunoN4gyPMx5TSy7Mfzw22D2RZQZUcx46bii53Ex3`.

### 1. Create a DIDConfiguration

Make a `PUT` request to `/v1/did-configurations`:

```json
{
  "expirationDate": "2051-10-05T14:48:00.000Z",
  "issuanceDate": "2021-10-05T14:48:00.000Z",
  "issuerDid": "did:key:z6MkmM43K3x5xAgzkLRW9r6HCv5c4QKfD2wjfi6tiW3CuzjZ",
  "origin": "https://www.tbd.website",
  "verificationMethodId": "did:key:z6MkmM43K3x5xAgzkLRW9r6HCv5c4QKfD2wjfi6tiW3CuzjZ#z6MkmM43K3x5xAgzkLRW9r6HCv5c4QKfD2wjfi6tiW3CuzjZ"
}
```

Or if you like CURLing:

```shell
curl -X PUT 'localhost:3000/v1/did-configurations' -d '{
  "expirationDate": "2051-10-05T14:48:00.000Z",
  "issuanceDate": "2021-10-05T14:48:00.000Z",
  "issuerDid": "did:key:z6MkmM43K3x5xAgzkLRW9r6HCv5c4QKfD2wjfi6tiW3CuzjZ",
  "origin": "https://www.tbd.website",
  "verificationMethodId": "did:key:z6MkmM43K3x5xAgzkLRW9r6HCv5c4QKfD2wjfi6tiW3CuzjZ#z6MkmM43K3x5xAgzkLRW9r6HCv5c4QKfD2wjfi6tiW3CuzjZ"
}'
```

Upon success you will see a response such as...

```json
{
  "wellKnownLocation": "https://www.tbd.website/.well-known/did-configuration.json",
  "didConfiguration": {
    "@context": "https://identity.foundation/.well-known/did-configuration/v1",
    "linked_dids": [
      "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa21NNDNLM3g1eEFnemtMUlc5cjZIQ3Y1YzRRS2ZEMndqZmk2dGlXM0N1empaI3o2TWttTTQzSzN4NXhBZ3prTFJXOXI2SEN2NWM0UUtmRDJ3amZpNnRpVzNDdXpqWiIsInR5cCI6IkpXVCJ9.eyJleHAiOjI1ODAxMzAwODAsImlhdCI6MTYzMzQ0NTI4MCwiaXNzIjoiZGlkOmtleTp6Nk1rbU00M0szeDV4QWd6a0xSVzlyNkhDdjVjNFFLZkQyd2pmaTZ0aVczQ3V6aloiLCJuYmYiOjE2MzM0NDUyODAsIm5vbmNlIjoiNzljN2UzMTgtMDEzMS00ODQ4LWJmOTMtODNiZGI1MmQ2YjZmIiwic3ViIjoiZGlkOmtleTp6Nk1rbU00M0szeDV4QWd6a0xSVzlyNkhDdjVjNFFLZkQyd2pmaTZ0aVczQ3V6aloiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vaWRlbnRpdHkuZm91bmRhdGlvbi8ud2VsbC1rbm93bi9kaWQtY29uZmlndXJhdGlvbi92MSJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJvcmlnaW4iOiJodHRwczovL3d3dy50YmQud2Vic2l0ZSJ9LCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiRG9tYWluTGlua2FnZUNyZWRlbnRpYWwiXX19.9oeN5rGzCaAMttOic47LOxIsjqpgH2DojGzsLiENy0UOKPdX66GJaEUEZSllWoGYOLqBnr6VWMnFgSk381jcAQ"
    ]
  }
}
```

This contains two properties. `wellKnownLocation` describes where you should be hosting content. The content that you host is the value of the property `didConfiguration`.

### 2. Host the created DID Configuration

This next step is up to you. You have to ensure that the value of `wellKnownLocation` resolves to a json file. The contents of the file should be the value of `didConfiguration`. In our example, we would have to make sure that the URL https://www.tbd.website/.well-known/did-configuration.json returns the JSON object described below. 

```json
{
  "@context": "https://identity.foundation/.well-known/did-configuration/v1",
  "linked_dids": [
    "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa21NNDNLM3g1eEFnemtMUlc5cjZIQ3Y1YzRRS2ZEMndqZmk2dGlXM0N1empaI3o2TWttTTQzSzN4NXhBZ3prTFJXOXI2SEN2NWM0UUtmRDJ3amZpNnRpVzNDdXpqWiIsInR5cCI6IkpXVCJ9.eyJleHAiOjI1ODAxMzAwODAsImlhdCI6MTYzMzQ0NTI4MCwiaXNzIjoiZGlkOmtleTp6Nk1rbU00M0szeDV4QWd6a0xSVzlyNkhDdjVjNFFLZkQyd2pmaTZ0aVczQ3V6aloiLCJuYmYiOjE2MzM0NDUyODAsIm5vbmNlIjoiNzljN2UzMTgtMDEzMS00ODQ4LWJmOTMtODNiZGI1MmQ2YjZmIiwic3ViIjoiZGlkOmtleTp6Nk1rbU00M0szeDV4QWd6a0xSVzlyNkhDdjVjNFFLZkQyd2pmaTZ0aVczQ3V6aloiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vaWRlbnRpdHkuZm91bmRhdGlvbi8ud2VsbC1rbm93bi9kaWQtY29uZmlndXJhdGlvbi92MSJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJvcmlnaW4iOiJodHRwczovL3d3dy50YmQud2Vic2l0ZSJ9LCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiRG9tYWluTGlua2FnZUNyZWRlbnRpYWwiXX19.9oeN5rGzCaAMttOic47LOxIsjqpgH2DojGzsLiENy0UOKPdX66GJaEUEZSllWoGYOLqBnr6VWMnFgSk381jcAQ"
  ]
}
```

### 3. Verify your setup

Once you've done the steps above, you can also use SSI Service to verify that the DID configuration is correct!

`PUT` to `/v1/did-configurations/verification`

```json
{
  "origin": "https://www.tbd.website"
}
```

... or in curl

```shell
curl -X PUT 'localhost:3000/v1/did-configurations/verification' -d '{
  "origin": "https://www.tbd.website"
}'
```

The result will look similar to the response below

```json
{
  "verified": false,
  "didConfiguration": "{\n    \"@context\":\"https://identity.foundation/.well-known/did-configuration/v1\",\n    \"linked_dids\":[\n       \"eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa2g0QTZRVE5DQUZpNE5aZm5XdDhxTlNHWERHbk5YaHhYV2V3Y3BCcnpTMTl2IiwidHlwIjoiSldUIn0.eyJleHAiOjI1ODAxMzAwODAsImlzcyI6ImRpZDprZXk6ejZNa2g0QTZRVE5DQUZpNE5aZm5XdDhxTlNHWERHbk5YaHhYV2V3Y3BCcnpTMTl2IiwibmJmIjoxNjc2NTcyMDkzLCJzdWIiOiJkaWQ6a2V5Ono2TWtoNEE2UVROQ0FGaTROWmZuV3Q4cU5TR1hER25OWGh4WFdld2NwQnJ6UzE5diIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly9pZGVudGl0eS5mb3VuZGF0aW9uLy53ZWxsLWtub3duL2RpZC1jb25maWd1cmF0aW9uL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJEb21haW5MaW5rYWdlQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOiJkaWQ6a2V5Ono2TWtoNEE2UVROQ0FGaTROWmZuV3Q4cU5TR1hER25OWGh4WFdld2NwQnJ6UzE5diIsImlzc3VhbmNlRGF0ZSI6IjIwMjMtMDItMTZUMTI6Mjg6MTMtMDY6MDAiLCJleHBpcmF0aW9uRGF0ZSI6IjIwNTEtMTAtMDVUMTQ6NDg6MDAuMDAwWiIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmtleTp6Nk1raDRBNlFUTkNBRmk0Tlpmbld0OHFOU0dYREduTlhoeFhXZXdjcEJyelMxOXYiLCJvcmlnaW4iOiJodHRwczovL3d3dy50YmQud2Vic2l0ZS8ifX19.szn9o_JhCLqYMH_SNtwFaJWViueg-pvrZW4G88cegh2Airh9ziQ7fYvSY4Hts2FlF6at8fMfAzrsnhJ-Fb0_Dw\",\n       \"eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWI6dGJkLndlYnNpdGUiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjI1ODAxMzAwODAsImlzcyI6ImRpZDp3ZWI6dGJkLndlYnNpdGUiLCJuYmYiOjE2NzY1NzIwOTUsInN1YiI6ImRpZDp3ZWI6dGJkLndlYnNpdGUiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vaWRlbnRpdHkuZm91bmRhdGlvbi8ud2VsbC1rbm93bi9kaWQtY29uZmlndXJhdGlvbi92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiRG9tYWluTGlua2FnZUNyZWRlbnRpYWwiXSwiaXNzdWVyIjoiZGlkOndlYjp0YmQud2Vic2l0ZSIsImlzc3VhbmNlRGF0ZSI6IjIwMjMtMDItMTZUMTI6Mjg6MTUtMDY6MDAiLCJleHBpcmF0aW9uRGF0ZSI6IjIwNTEtMTAtMDVUMTQ6NDg6MDAuMDAwWiIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOndlYjp0YmQud2Vic2l0ZSIsIm9yaWdpbiI6Imh0dHBzOi8vd3d3LnRiZC53ZWJzaXRlLyJ9fX0.bweamOE6q-K1jQ64cfqk-vhhuugSpLvcit3Q6REBM2z0CpvvTX4SttHF533oUIDovtOSqmAAOOUFCbrTJYQfDw\"\n    ]\n }",
  "reason": "verifying JWT credential: error getting key to verify credential<>: did<did:key:z6Mkh4A6QTNCAFi4NZfnWt8qNSGXDGnNXhxXWewcpBrzS19v> has no verification methods with kid: did:key:z6Mkh4A6QTNCAFi4NZfnWt8qNSGXDGnNXhxXWewcpBrzS19v"
}
```

In this case, `verified` is `false`, so the `reason` property is populated, explaining where verification went wrong. Note that the `didConfiguration` value is a string. It represents the exact response that was received from the origin.