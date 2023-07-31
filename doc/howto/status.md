# How To: Revoke/Suspend a Credential

## Background

Though [Verifiable Credentials](https://www.w3.org/TR/vc-data-model/) are designed to give the holder a large degree of freedom in using their data, credential issuers are able to retain some control over the data they attest to after issuance. One of the mechanisms by which they retain this control is through the usage of credential status. Credential status can be implemented through any valid JSON-LD type, to specify any status such as whether a credential is suspended or revoked. The most prominently used type is through the [Status List](https://w3c.github.io/vc-status-list-2021/) type, a work item in the [VC Working Group](https://www.w3.org/groups/wg/vc).

To make use of credential status, issuers must follow the rules outlined in the [Status List specification](https://w3c.github.io/vc-status-list-2021/#statuslist2021credential) to build a status list credential, and then include the requisite values in the `credentialStatus` property of any Verifiable Credential they issue according to the [Status List Entry](https://w3c.github.io/vc-status-list-2021/#statuslist2021entry) portion of the specification.

## How does the Status List work?

The Status List specification is designed to provide issuers a mechanism to express the status of a given credential, verifiers a mechanism to check the status of a given credential, and holders a set of privacy guarantees about status checks for credentials they hold. The way this works is by issuers creating a new credential that represents credential status. In our implementation credential status credentials are unique for each <issuer, credential schema> pair. The construction of this status credential uses something called a [bitstring](https://w3c.github.io/vc-status-list-2021/#security-considerations) which can provide something called _herd privacy_ for credential holders — in simpler terms this means that many credentials can be represented in a single bitstream, so it is not clear which credential/holder a verifier is requesting information about — this is great for holder privacy!

Then, for each new credential an issuer creates for a given schema, a new credential status credential is created or an existing credential status credential is used. Each credential an issuer creates now contains a reference to the status list credential contained in the credential's `credentialStatus` property, which can be used by verifiers to check the status of the credential.

**Example Credential Status Credential**

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/vc/status-list/2021/v1"
  ],
  "id": "https://example.com/credentials/status/3",
  "type": ["VerifiableCredential", "StatusList2021Credential"],
  "issuer": "did:example:12345",
  "issued": "2021-04-05T14:27:40Z",
  "credentialSubject": {
    "id": "https://example.com/status/3#list",
    "type": "StatusList2021",
    "statusPurpose": "revocation",
    "encodedList": "H4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA"
  },
  "proof": { ... }
}
```

**Example Credential with Credential Status**

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/vc/status-list/2021/v1"
  ],
  "id": "https://example.com/credentials/23894672394",
  "type": ["VerifiableCredential"],
  "issuer": "did:example:12345",
  "issued": "2021-04-05T14:27:42Z",
  "credentialStatus": {
    "id": "https://example.com/credentials/status/3#94567",
    "type": "StatusList2021Entry",
    "statusPurpose": "revocation",
    "statusListIndex": "94567",
    "statusListCredential": "https://example.com/credentials/status/3"
  },
  "credentialSubject": {
    "id": "did:example:6789",
    "type": "Person"
  },
  "proof": { ... }
}
```

In the first example above we can see a _status list credential_ which is used for many credentials issued by the issuer identified by the DID `did:example:12345`. In the second example above we can see a credential that `did:example:12345` issued to `did:example:6789`. The second example also shows a reference to the above status list credential in the given `credentialStatus` block. We see that the credential has a `statusListIndex` of `94567` which is needed by any verifier of the holder's credential to check its status. The verification process would be as follows:

1. Holder `did:example:6789` presents their credential to a verifier.
2. Verifier makes a request to resolve the credential status credential identified by `https://example.com/credentials/status/3`.
3. Upon resolution the verifier checks the value of the bit string at index `94567`.
4. If present, the credential has the associated status (revoked), if absent, the credential does not have the associated status (not revoked).

## Status in the SSI Service

By now you should be familiar with [creating a credential](credential.md). Notably, that upon forming a request to create a credential there are a number of possible request values, two of which are `revocable` and `suspendable`. These options are exposed to give issuers the ability to specify status for credentials they create in the service. If either (or both) of the status values are set in the credential creation request then an associated status list credential will be created (if it does not yet exist) and a `credentialStatus` entry will be added to the newly created credential.

We will assume you've followed the aforementioned guide on creating a credential, so you already have an issuer DID and person schema. Let's jump right into creating a revocable credential:

### 1. Create a revocable credential

Create a `PUT` request to `/v1/credentials` making sure the request body has the value `revocable` set to `true`.

```json
curl -X PUT localhost:3000/v1/credentials -d '{
  "issuer": "did:key:z6Mkm1TmRWRPK6n21QncUZnk1tdYkje896mYCzhMfQ67assD",
  "verificationMethodId": "did:key:z6Mkm1TmRWRPK6n21QncUZnk1tdYkje896mYCzhMfQ67assD#z6Mkm1TmRWRPK6n21QncUZnk1tdYkje896mYCzhMfQ67assD",
  "subject": "did:key:z6MkmNnvnfzW3nLiePweN3niGLnvp2BjKx3NM186vJ2yRg2z",
  "schemaId": "aed6f4f0-5ed7-4d7a-a3df-56430e1b2a88",
  "data": {
    "firstName": "Satoshi",
    "lastName": "Nakamoto"
  },
  "revocable": true
}'
```

Upon success we see a response such as:

```json
{
  "id": "8f9d58b2-c978-4317-96bd-35949ce76121",
  "fullyQualifiedVerificationMethodId": "did:key:z6Mkm1TmRWRPK6n21QncUZnk1tdYkje896mYCzhMfQ67assD#z6Mkm1TmRWRPK6n21QncUZnk1tdYkje896mYCzhMfQ67assD",
  "credential": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "id": "http://localhost:3000/v1/credentials/8f9d58b2-c978-4317-96bd-35949ce76121",
    "type": ["VerifiableCredential"],
    "issuer": "did:key:z6Mkm1TmRWRPK6n21QncUZnk1tdYkje896mYCzhMfQ67assD",
    "issuanceDate": "2023-07-31T11:18:26-07:00",
    "credentialStatus": {
      "id": "http://localhost:3000/v1/credentials/8f9d58b2-c978-4317-96bd-35949ce76121/status",
      "statusListCredential": "http://localhost:3000/v1/credentials/status/b7a8bd19-f20d-4132-ac2e-137ff4d1511a",
      "statusListIndex": "106493",
      "statusPurpose": "revocation",
      "type": "StatusList2021Entry"
    },
    "credentialSubject": {
      "firstName": "Satoshi",
      "id": "did:key:z6MkmNnvnfzW3nLiePweN3niGLnvp2BjKx3NM186vJ2yRg2z",
      "lastName": "Nakamoto"
    },
    "credentialSchema": {
      "id": "aed6f4f0-5ed7-4d7a-a3df-56430e1b2a88",
      "type": "JsonSchema2023"
    }
  },
  "credentialJwt": "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa20xVG1SV1JQSzZuMjFRbmNVWm5rMXRkWWtqZTg5Nm1ZQ3poTWZRNjdhc3NEI3o2TWttMVRtUldSUEs2bjIxUW5jVVpuazF0ZFlramU4OTZtWUN6aE1mUTY3YXNzRCIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2OTA4Mjc1MDYsImlzcyI6ImRpZDprZXk6ejZNa20xVG1SV1JQSzZuMjFRbmNVWm5rMXRkWWtqZTg5Nm1ZQ3poTWZRNjdhc3NEIiwianRpIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwL3YxL2NyZWRlbnRpYWxzLzhmOWQ1OGIyLWM5NzgtNDMxNy05NmJkLTM1OTQ5Y2U3NjEyMSIsIm5iZiI6MTY5MDgyNzUwNiwibm9uY2UiOiI0ZGQyYzg1YS02NTFjLTQ3MDAtOTZhZC1hM2VlNTU1YTFmZTMiLCJzdWIiOiJkaWQ6a2V5Ono2TWttTm52bmZ6VzNuTGllUHdlTjNuaUdMbnZwMkJqS3gzTk0xODZ2SjJ5UmcyeiIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN0YXR1cyI6eyJpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMC92MS9jcmVkZW50aWFscy84ZjlkNThiMi1jOTc4LTQzMTctOTZiZC0zNTk0OWNlNzYxMjEvc3RhdHVzIiwic3RhdHVzTGlzdENyZWRlbnRpYWwiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAvdjEvY3JlZGVudGlhbHMvc3RhdHVzL2I3YThiZDE5LWYyMGQtNDEzMi1hYzJlLTEzN2ZmNGQxNTExYSIsInN0YXR1c0xpc3RJbmRleCI6IjEwNjQ5MyIsInN0YXR1c1B1cnBvc2UiOiJyZXZvY2F0aW9uIiwidHlwZSI6IlN0YXR1c0xpc3QyMDIxRW50cnkifSwiY3JlZGVudGlhbFN1YmplY3QiOnsiZmlyc3ROYW1lIjoiU2F0b3NoaSIsImxhc3ROYW1lIjoiTmFrYW1vdG8ifSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6ImFlZDZmNGYwLTVlZDctNGQ3YS1hM2RmLTU2NDMwZTFiMmE4OCIsInR5cGUiOiJKc29uU2NoZW1hMjAyMyJ9fX0.7mkFcjRXkFcVTB888NO1Ty85yTJz8dEdt8dHViE7iuQZvXwED9bfIMMSHU9mmqkokZtSldnaKcoPwO0WCuVwAQ"
}
```

Notably we see the `credentialStatus` entry in the credential we've created, with id `http://localhost:3000/v1/credentials/8f9d58b2-c978-4317-96bd-35949ce76121/status` and the status list credential that has been created, with id `http://localhost:3000/v1/credentials/status/b7a8bd19-f20d-4132-ac2e-137ff4d1511a`.

### 2. Get a status list credential

Next, let's get the crednetial's associated status list credential. We make a request to `/v1/credentials/status/{id}` to get the status list credential.

```bash
curl http://localhost:3000/v1/credentials/status/b7a8bd19-f20d-4132-ac2e-137ff4d1511a
```

Upon success we see a response such as:

```json
{
  "id": "b7a8bd19-f20d-4132-ac2e-137ff4d1511a",
  "credential": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://w3id.org/vc/status-list/2021/v1"
    ],
    "id": "http://localhost:3000/v1/credentials/status/b7a8bd19-f20d-4132-ac2e-137ff4d1511a",
    "type": [
      "VerifiableCredential",
      "StatusList2021Credential"
    ],
    "issuer": "did:key:z6Mkm1TmRWRPK6n21QncUZnk1tdYkje896mYCzhMfQ67assD",
    "issuanceDate": "2023-07-31T18:18:26Z",
    "credentialSubject": {
      "encodedList": "H4sIAAAAAAAA/2IAAweGUTAKRsEoGAWjYBSMPAAIAAD//9BoYmEICAAA",
      "id": "http://localhost:3000/v1/credentials/status/b7a8bd19-f20d-4132-ac2e-137ff4d1511a",
      "statusPurpose": "revocation",
      "type": "StatusList2021"
    }
  },
  "credentialJwt": "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa20xVG1SV1JQSzZuMjFRbmNVWm5rMXRkWWtqZTg5Nm1ZQ3poTWZRNjdhc3NEI3o2TWttMVRtUldSUEs2bjIxUW5jVVpuazF0ZFlramU4OTZtWUN6aE1mUTY3YXNzRCIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2OTA4Mjc1MDYsImlzcyI6ImRpZDprZXk6ejZNa20xVG1SV1JQSzZuMjFRbmNVWm5rMXRkWWtqZTg5Nm1ZQ3poTWZRNjdhc3NEIiwianRpIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwL3YxL2NyZWRlbnRpYWxzL3N0YXR1cy9iN2E4YmQxOS1mMjBkLTQxMzItYWMyZS0xMzdmZjRkMTUxMWEiLCJuYmYiOjE2OTA4Mjc1MDYsIm5vbmNlIjoiNzZmMjI5MzEtMjU5Mi00MDY1LTllODktMTM3ZGRkOTEyNGY5Iiwic3ViIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwL3YxL2NyZWRlbnRpYWxzL3N0YXR1cy9iN2E4YmQxOS1mMjBkLTQxMzItYWMyZS0xMzdmZjRkMTUxMWEiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vdzNpZC5vcmcvdmMvc3RhdHVzLWxpc3QvMjAyMS92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiU3RhdHVzTGlzdDIwMjFDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImVuY29kZWRMaXN0IjoiSDRzSUFBQUFBQUFBLzJJQUF3ZUdVVEFLUnNFb0dBV2pZQlNNUEFBSUFBRC8vOUJvWW1FSUNBQUEiLCJzdGF0dXNQdXJwb3NlIjoicmV2b2NhdGlvbiIsInR5cGUiOiJTdGF0dXNMaXN0MjAyMSJ9fX0.eZMzdNib_QrfSni7i74vXR73X6knIsOIeTNm32j26mQsQlk9em5fKLN0dqlVK9o0v_zDZI2UzvaE2p5PRH3BDA"
}
```

With this status list credential we're able to check the status for the credential we created, which is identified by its id `8f9d58b2-c978-4317-96bd-35949ce76121` and status list index `106493`. To check the status you have a few options:

1. Run the [verification algorithm](https://w3c.github.io/vc-status-list-2021/#validate-algorithm) yourself using the specification.
2. Use the [utility in the SSI SDK](https://github.com/TBD54566975/ssi-sdk/blob/d5c302a1d9b9d04c1636a0c8dfda015f61bb0f6b/credential/status/statuslist2021.go#L254) to check the status.
3. Use the SSI Service's endpoint for status validation.

### 3. Verify a credential's status

Let's go with option 3 since it's simplest. The service has an endpoint which you can make `GET` requests to at `/v1/credentials/{id}/status` to check the status for any credential.

Making a request for our credential's id, `8f9d58b2-c978-4317-96bd-35949ce76121`, we make a request:

```bash
curl localhost:3000/v1/credentials/8f9d58b2-c978-4317-96bd-35949ce76121/status
```

Upon success we see a response such as:

```json
{
  "revoked": false,
  "suspended": false
}
```

We can see that the credential is neither revoked nor suspended, as expected.

### 4. Revoke a credential

As the creator of the credential we're able to change the status of the credential we've created. To do so, we make a request to the Update Credential Status endpoint which is a `PUT` request to `/v1/credentials/{id}/status`. At present, the endpoint accepts boolean values for the status(es) the credential supports. Let's update the credential's status to revoked:

```bash
curl -X PUT localhost:3000/v1/credentials/8f9d58b2-c978-4317-96bd-35949ce76121/status -d '{ "revoked": true }'
```

Upon success we see a response such as:

```json
{ 
  "revoked": true,
  "suspended": false
}
```

Making a request as we did in step 3 should now show the same response. The credential is now revoked.

**Note:** It is possible to reverse the status of a credential. To do so, make the same request mentioned above, but setting the value of `revoked` to `false`.
