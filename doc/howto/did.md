# How To: Create a DID

## Background

A [DID (Decentralized Identifier)](https://www.w3.org/TR/did-core/) is a unique identifier that can be used to identify a person, organization, or thing. DIDs are associated with documents called DID Documents. These documents contain
cryptographic key material, service endpoints, and other useful information.

DIDs are a core component of SSI (Self-Sovereign Identity) systems. DIDs are specified according to "methods" which
define how the DID is created and how it can be used. A list of existing [DID methods can be found here](https://www.w3.org/TR/did-spec-registries/#did-methods).

Importantly, DIDs in the SSI Service are _fully custodial_. This means the private keys associated with DID Documents are managed by the service and never leave its boundaries. For some DID methods, such as `did:web` it's possible to add multiple keys to the DID document, and it's possible for these additional keys to be added outside the service. This is a more advanced concept that the service may support in the future.

## What DID Methods are There?

The SSI Service supports a number of DID methods, including...

* [DID Key](https://w3c-ccg.github.io/did-method-key/) a self-resolving method great for testing
* [DID Web](https://w3c-ccg.github.io/did-method-web/) a method designed to be hosted on your own domain
* [DID ION](https://identity.foundation/sidetree/spec/#value-locking) a Layer 2 Bitcoin method based on the Sidetree protocol.

At runtime, the you can enable and disable which methods the service supports. Learn more about this by reading our [documentation on configuration](../README.md).

Once the service is running you can see which DID methods are enabled by sending a `GET` request to `/v1/dids`.

Upon a successful request you should see a response such as:

```json
{
  "method": [
    "key",
    "web"
  ]
}
```

## Creating A DID

You can create a DID by sending a `PUT` request to the `/v1/dids/{method}` endpoint. The request body needs two pieces of information: a method and a key type. The method must be supported by the service, and the key type must be supported by the method. You can find out more specifics about what each method supports [by looking at the SDK](https://github.com/TBD54566975/ssi-sdk/tree/main/did). Certain methods may support additional properties in an optional `options` fields.

For now let's keep things simple and create a new `did:key` with the key type [`Ed25519`](https://ed25519.cr.yp.to/), a widely respected key type using [ellicptic curve cryptography](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography).

**Create DID Key Request**

`PUT` to `/v1/dids/key`

```json
{
  "keyType": "Ed25519"
}
```

Or if you like curling:
```shell
curl -X PUT 'localhost:3000/v1/dids/key' -d '{
  "keyType": "Ed25519"
}'
```

If successful, you should see a response such as...

```json
{
  "did": {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/jws-2020/v1"
    ],
    "id": "did:key:z6MkvRnaDoRv4qn6scLAE2RVAv1Yj42S9HZkkJTYB8Lm2U5g",
    "verificationMethod": [
      {
        "id": "did:key:z6MkvRnaDoRv4qn6scLAE2RVAv1Yj42S9HZkkJTYB8Lm2U5g#z6MkvRnaDoRv4qn6scLAE2RVAv1Yj42S9HZkkJTYB8Lm2U5g",
        "type": "JsonWebKey2020",
        "controller": "did:key:z6MkvRnaDoRv4qn6scLAE2RVAv1Yj42S9HZkkJTYB8Lm2U5g",
        "publicKeyJwk": {
          "kty": "OKP",
          "crv": "Ed25519",
          "x": "7VpY8ilUvfIgUVf9DOO58BD1kQKPN_NDrNvr8qyK-2M",
          "alg": "EdDSA",
          "kid": "did:key:z6MkvRnaDoRv4qn6scLAE2RVAv1Yj42S9HZkkJTYB8Lm2U5g"
        }
      },
      {
        "id": "did:key:z6MkvRnaDoRv4qn6scLAE2RVAv1Yj42S9HZkkJTYB8Lm2U5g#z6LSgpucz3mqZYRRzBpx8zGtWQAKSkyLqfQMEpxr2PVaRX8V",
        "type": "JsonWebKey2020",
        "controller": "did:key:z6MkvRnaDoRv4qn6scLAE2RVAv1Yj42S9HZkkJTYB8Lm2U5g",
        "publicKeyJwk": {
          "kty": "OKP",
          "crv": "X25519",
          "x": "TIcWJZVD0_TUHYzm9eyc1s5bD3EmrjTlVQfaHDfrazo",
          "alg": "X25519",
          "kid": "did:key:z6MkvRnaDoRv4qn6scLAE2RVAv1Yj42S9HZkkJTYB8Lm2U5g"
        }
      }
    ],
    "authentication": [
      "did:key:z6MkvRnaDoRv4qn6scLAE2RVAv1Yj42S9HZkkJTYB8Lm2U5g#z6MkvRnaDoRv4qn6scLAE2RVAv1Yj42S9HZkkJTYB8Lm2U5g"
    ],
    "assertionMethod": [
      "did:key:z6MkvRnaDoRv4qn6scLAE2RVAv1Yj42S9HZkkJTYB8Lm2U5g#z6MkvRnaDoRv4qn6scLAE2RVAv1Yj42S9HZkkJTYB8Lm2U5g"
    ],
    "keyAgreement": [
      "did:key:z6MkvRnaDoRv4qn6scLAE2RVAv1Yj42S9HZkkJTYB8Lm2U5g#z6LSgpucz3mqZYRRzBpx8zGtWQAKSkyLqfQMEpxr2PVaRX8V"
    ],
    "capabilityInvocation": [
      "did:key:z6MkvRnaDoRv4qn6scLAE2RVAv1Yj42S9HZkkJTYB8Lm2U5g#z6MkvRnaDoRv4qn6scLAE2RVAv1Yj42S9HZkkJTYB8Lm2U5g"
    ],
    "capabilityDelegation": [
      "did:key:z6MkvRnaDoRv4qn6scLAE2RVAv1Yj42S9HZkkJTYB8Lm2U5g#z6MkvRnaDoRv4qn6scLAE2RVAv1Yj42S9HZkkJTYB8Lm2U5g"
    ]
  }
}
```

which is a fully complaint `did:key` document [according to its specification](https://w3c-ccg.github.io/did-method-key/).

Now that you have a DID you can begin to use it with other pieces of the service, such as by [issuing a credential](credential.md).

## Getting DIDs

Once you've created muliple DIDs, you can view all DIDs under a given method by making a `GET` request to the method's endpoint, such as `/v1/dids/key`.

You can get a specific DID's document by making a `GET` request to the method's endpoint, such as `/v1/dids/key/{did}`.

## DIDs Outside the Service

The [universal resolver](https://github.com/decentralized-identity/universal-resolver) is a project at the [Decentralized Identity Foundation](https://identity.foundation/) aiming to enable the resolution of _any_ DID Document. The service, when run with [Docker Compose, runs a select number of these drivers (and more can be configured). It's possible to leverage the resolution of DIDs not supported by the service by making `GET` requests to `/v1/dids/resolver/{did}`.



