# How To: Create a did:web

## Background

The [did:web Method Specification](https://w3c-ccg.github.io/did-method-web/) describes a DID method that uses an existing web domain to host and establish trust for a DID Document.

It relies on the controller of an existing domain to host a custom file with the contents of the DID Document they want to expose. The SSI Service facilitates creation of a `did:web`, which you then must update on the domain you control.

## Steps

### Prerequisites

* You control an existing domain  (e.g. like https://www.tbd.website).
* You are able to host files in a path within that origin (e.g. you can host the file returned by https://www.tbd.website/.well-known/did.json).

## 1. Create a `did:web` DID

Make a `PUT` request to `/v1/dids/web`, with a request body as follows:

```json
{
  "keyType": "Ed25519",
  "options": {
    "didWebId": "did:web:tbd.website"
  }
}
```

Or if you like CURLing:

```shell
curl -X PUT 'localhost:3000/v1/dids/web' -d '{
  "keyType": "Ed25519",
  "options": {
    "didWebId": "did:web:tbd.website"
  }
}'
```

Upon success, the contents of the response should look as follows...

```json
{
  "did": {
    "@context": "https://www.w3.org/ns/did/v1",
    "id": "did:web:tbd.website",
    "verificationMethod": [
      {
        "id": "did:web:tbd.website",
        "type": "JsonWebKey2020",
        "controller": "did:web:tbd.website#owner",
        "publicKeyJwk": {
          "kty": "OKP",
          "crv": "Ed25519",
          "x": "TuAM4Ro4q5_cFMarCHmOm-1c7NaxBxvoEe7-x7K7xhw",
          "alg": "EdDSA",
          "kid": "did:web:tbd.website#owner"
        }
      }
    ],
    "authentication": [
      [
        "did:web:tbd.website#owner"
      ]
    ],
    "assertionMethod": [
      [
        "did:web:tbd.website#owner"
      ]
    ]
  }
}
```

This response is an object containing a `did` property, whose value is a DID Document. This value is what needs to be hosted on your domain.

### 2. Host the created DID Document

This next step is for you to do outside of the service. You have to ensure that the URL `<domain_name>/.well-known/did.json` resolves to the content of the value of the `did` property from the response. In our example, we would have to make sure that the URL `https://tbd.website/.well-known/did.json` returns the JSON object described below:

```json
{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:web:tbd.website",
  "verificationMethod": [
    {
      "id": "did:web:tbd.website",
      "type": "JsonWebKey2020",
      "controller": "did:web:tbd.website#owner",
      "publicKeyJwk": {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "TuAM4Ro4q5_cFMarCHmOm-1c7NaxBxvoEe7-x7K7xhw",
        "alg": "EdDSA",
        "kid": "did:web:tbd.website#owner"
      }
    }
  ],
  "authentication": [
    [
      "did:web:tbd.website#owner"
    ]
  ],
  "assertionMethod": [
    [
      "did:web:tbd.website#owner"
    ]
  ]
}
```

### 3. Verify the `did:web` hosted

This last step ensures that SSI Service considers the created `did:web` to be valid.

Make a `GET` request to `v1/dids/resolver/<your_did_web>`

Using CURL:

```shell
curl 'localhost:3000/v1/dids/resolver/did:web:tbd.website'
```

Upon success you will see a response such as...

```json
{
  "didResolutionMetadata": {
    "ContentType": "application/json"
  },
  "didDocument": {
    "@context": "https://www.w3.org/ns/did/v1",
    "id": "did:web:tbd.website",
    "verificationMethod": [
      {
        "id": "did:web:tbd.website",
        "type": "JsonWebKey2020",
        "controller": "did:web:tbd.website#owner",
        "publicKeyJwk": {
          "kty": "OKP",
          "crv": "Ed25519",
          "x": "TuAM4Ro4q5_cFMarCHmOm-1c7NaxBxvoEe7-x7K7xhw",
          "alg": "EdDSA",
          "kid": "did:web:tbd.website#owner"
        }
      }
    ],
    "authentication": [
      [
        "did:web:tbd.website#owner"
      ]
    ],
    "assertionMethod": [
      [
        "did:web:tbd.website#owner"
      ]
    ]
  },
  "didDocumentMetadata": {}
}
```

In this case the JSON object contains a [DID Resolution Result](https://www.w3.org/TR/did-core/#did-resolution), in which the `didDocument` property has the value that was created in step 1.
