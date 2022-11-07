
# SIP 7 Credential Revocation

  

GitHub Link: https://github.com/TBD54566975/ssi-service/tree/main/sip/sips/sip7

Status: Draft

 

# SIP 7: Credential Revocation

  

```yaml

SIP: 7
Title: Credential Revocation
Author(s): Neal Roessler
Status: Draft
Created: November 4, 2022
Updated: November 4, 2022
Discussion: Link to a forum post e.g. https://forums.tbd.website/c/self-sovereign-identity-developers/7

```

  

# Abstract

  

As verifiable credentials are issued one needs a way to track if these have been revoked and are thus no longer valid. This strategy described here allows anyone to check if a verifiable credential has been revoked in an efficient and privacy preserving way.

  

This SIP outlines a mechanism for the revocation of Verifiable Credentials through a new **`StatusList2021Entry`** credential status on an issued verifiable credential and a **`StatusList2021Credential`** which is a ****is a verifiable credential that encapsulates the status list of all Verifiable Credentials issued on the platform.

  

## Background

  

At the most basic level, status information for all [verifiable credentials](https://w3c-ccg.github.io/vc-status-list-2021/#dfn-verifiable-credentials) issued by an [issuer](https://w3c-ccg.github.io/vc-status-list-2021/#dfn-issuers) are expressed as simple binary values. The [issuer](https://w3c-ccg.github.io/vc-status-list-2021/#dfn-issuers) keeps a bitstring list of all [verifiable credentials](https://w3c-ccg.github.io/vc-status-list-2021/#dfn-verifiable-credentials) it has issued. Each [verifiable credential](https://w3c-ccg.github.io/vc-status-list-2021/#dfn-verifiable-credentials) is associated with a position in the list. If the binary value of the position in the list is 1 (one), the [verifiable credential](https://w3c-ccg.github.io/vc-status-list-2021/#dfn-verifiable-credentials) is revoked, if it is 0 (zero) it is not revoked. This bitstring will be represented inside of the **`StatusList2021Credential`** encodedList property

  

**More specifically this sip expands upon the implementation of the following:**

  

Adding an optional **`credentialStatus`** to issued credentials - [https://w3c-ccg.github.io/vc-status-list-2021/#statuslist2021entry](https://w3c-ccg.github.io/vc-status-list-2021/#statuslist2021entry)

  

```json
{
   "@context":[
      "https://www.w3.org/2018/credentials/v1",
      "https://w3id.org/vc/status-list/2021/v1"
   ],
   "id":"https://example.com/credentials/23894672394",
   "type":[
      "VerifiableCredential"
   ],
   "issuer":"did:example:12345",
   "issued":"2021-04-05T14:27:42Z",
   "credentialStatus":{
      "id":"https://example.com/credentials/status/3#94567",
      "type":"StatusList2021Entry",
      "statusPurpose":"revocation",
      "statusListIndex":"94567",
      "statusListCredential":"https://example.com/credentials/status/3"
   },
   "credentialSubject":{
      "id":"did:example:6789",
      "type":"Person"
   },
   "proof":{
      
   }
}

```

  

Adding the ability to create and update a **`StatusList2021Credential`** that describes in one credential all the credentials on the based on <issuer,schema> that are revoked or not - [https://w3c-ccg.github.io/vc-status-list-2021/#statuslist2021credential](https://w3c-ccg.github.io/vc-status-list-2021/#statuslist2021credential)

  

```jsx

{
   "@context":[
      "https://www.w3.org/2018/credentials/v1",
      "https://w3id.org/vc/status-list/2021/v1"
   ],
   "id":"https://example.com/credentials/status/3",
   "type":[
      "VerifiableCredential",
      "StatusList2021Credential"
   ],
   "issuer":"did:example:12345",
   "issued":"2021-04-05T14:27:40Z",
   "credentialSubject":{
      "id":"https://example.com/status/3#list",
      "type":"StatusList2021",
      "statusPurpose":"revocation",
      "encodedList":"H4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA"
   },
   "proof":{
      
   }
}

```

  

## Goals

  

- Add **`credentialStatus`** field to verifiable credentials issued by the ssi-service if the **"revokable" : true** flag is set

- Have a **`StatusList2021Credential`** verifiable credential be dynamically generated that has encoded list of revoked credentials. There will be multiple lists based on 2 dimensions: schema and issuer.

- Create endpoints to facilitate credential revocation and status checking

- GET {{baseUrl}}/v1/credentials/?issuer=issuerId&schema=schemaId/status

- will return the **`StatusList2021Credential`** for this <issuer,  schema> pair

- GET {{baseUrl}}/v1/credentials/status/:id

- will return a saved **`StatusList2021Credential`** with the id

- GET {{baseUrl}}/v1/credentials/:id/status

- returns revoked: {true or false}

- PUT {{baseUrl}}/v1/credentials/:id/status

```json

{
	"revoked":true,
}

```

- updates revocation status, regenerates the corresponding <issuer,  schema>  **`StatusList2021Credential,`** and ****returns true or false

- (Optional) PUT {{baseUrl}}/v1/credentials/status/

```json

{
	"issuerId":"issuerId",
	"schemaId":"schemaId"
}

```

- will regenerate the **`StatusList2021Credential`** for the issuer and schema provided

- returns the regenerated **`StatusList2021Credential`** with the updated issued time

  

  

# Specification

  

## Updates to Verifiable Credential Creation

  

When creating VCs there will be a new optional field added to the VC payload called "**revokable**". If this VC is to have the revocation **`credentialStatus`** property

  

PUT {{baseUrl}}/v1/credentials

  

```json

{
   "data":{
      "givenName":"ricky bobby",
      "additionalName":"hank hill",
      "familyName":"simpson"
   },
   "issuer":"did:key:z6MkjRuMGZ6bSiAL8GPHD51AM4DN3NM9S83oLu9gBbUb4kH5",
   "subject":"did:key:z6MkjRuMGZ6bSiAL8GPHD51AM4DN3NM9S83oLu9gBbUb4kH5",
   "@context":"https://www.w3.org/2018/credentials/v1",
   "expiry":"2051-10-05T14:48:00.000Z",
   "schema":"13eef179-273a-4743-abf1-64eaa60c883b",
   "revokable":true
}

```

  

If revokable is true the verifiable credential will have the a new property **`credentialStatus`**

  

```jsx

{
   "credential":{
      "@context":[
         "https://www.w3.org/2018/credentials/v1"
      ],
      "id":"b7962149-a301-4bca-9de7-753abfc13f39",
      "type":[
         "VerifiableCredential"
      ],
      "issuer":"did:key:z6MkjRuMGZ6bSiAL8GPHD51AM4DN3NM9S83oLu9gBbUb4kH5",
      "issuanceDate":"2022-11-02T17:51:00Z",
      "expirationDate":"2051-10-05T14:48:00.000Z",
      "credentialSubject":{
         "givenName":"ricky bobby",
         "additionalName":"hank hill",
         "familyName":"simpson"
      },
      "credentialSchema":{
         "id":"13eef179-273a-4743-abf1-64eaa60c883b",
         "type":"JsonSchemaValidator2018"
      },
      "credentialStatus":{
         "id":"http://{{baseUrl}}/v1/credentials/:id/status",
         "type":"StatusList2021Entry",
         "statusPurpose":"revocation",
         "statusListIndex":"123",
         "statusListCredential":"https://{{baseUrl}}/v1/credentials/?issuer=issuerId&schema=schemaId/status/:id"
      }
   },
   "credentialJwt":"..."
}
```

  

From now on when a VC is created there will be a new internal property in our credential model which will default to false which will be saved to our database

  

```go

type  Container  struct {
	// Credential ID
	ID string
	Revoked bool
	Credential *credential.VerifiableCredential
	CredentialJWT *keyaccess.JWT
}

```

  

## Revocation Status and Updating Revocation

  

- GET {{baseUrl}}/v1/credentials/:id/status → returns true or false

  

```json

{
	"revoked":true
}

```

  

- PUT {{baseUrl}}/v1/credentials/:id/status → updates revocation status, regenerates the corresponding <issuer,  schema>, returns true or false

  

Input and output:

  

```jsx
{
	"revoked":true
}

```

  

## Generation of the StatusList2021Credential

  

A new route will be created which gives a StatusList2021Credential type

  

- GET {{baseUrl}}/v1/credentials/status/ → returns the **`StatusList2021Credential`**

  

StatusList2021Credential Example

  

```jsx

{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/vc/status-list/2021/v1"
  ],
  "id": "https://{{baseUrl}}/v1/credentials/?issuer=issuerId&schema=schemaId/status/a3962149-a301-4bca-9de7-753abfc13f37",
  "type": ["VerifiableCredential", "StatusList2021Credential"],
  "issuer": "did:example:12345",
  "issued": "2021-04-05T14:27:40Z",
  "credentialSubject": {
    "id": "http://{{baseUrl}}/v1/credentials/revocation/"
    "type": "StatusList2021",
    "statusPurpose": "revocation",
    "encodedList": "H4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA"
  },
  "proof": { ... }
}

```

  

A new route will be created which will regenerate a StatusList2021Credential type for the given issuer and schema. This route can be a heavy and long running process. This will not need to be called normally or often but can be run to regenerate the **`StatusList2021Credential`** and update the issued time, verifying that this is the latest state of the world for this <issuer,  schema>  **`StatusList2021Credential`**

  

- PUT {{baseUrl}}/v1/credentials/status/ → returns the regenerated **`StatusList2021Credential`**

  

```json

{
	"issuerId":"issuerId",
	"schemaId":"schemaId"
}

```

  

This StatusList2021Credential credential will be dynamically created when the endpoint is hit.

  

The endpoint will

  
- Go through each VC in our database
- Find the VCs that have a **revokable** property set to true inside of the vc object itself

- For each VC that is **revokable** create a new list of these objects, this is `statusListIndex`

- Follow the **Bitstring Generation Algorithm** detailed below to create ****`encodedList` for the StatusList2021Credential object

- Create a **`StatusList2021Credential`** object and add the generated ****encodedList to it

- Return the signed **`StatusList2021Credential`**

  

**Bitstring Generation Algorithm**

  

The following process, or one generating the exact output, *MUST* be followed when generating a status list bitstring. The algorithm takes a **issuedCredentials** list as input and returns a **compressed bitstring** as output.

  

1. Let **bitstring** be a list of bits with a minimum size of 16KB, where each bit is initialized to 0 (zero).

2. For each bit in **bitstring**, if there is a corresponding `statusListIndex` value in a revoked credential in **issuedCredentials**, set the bit to 1 (one), otherwise set the bit to 0 (zero).

3. Generate a **compressed bitstring** by using the GZIP compression algorithm [] on the **bitstring** and then base64-encoding [] the result. [RFC1952](https://w3c-ccg.github.io/vc-status-list-2021/#bib-rfc1952) [RFC4648](https://w3c-ccg.github.io/vc-status-list-2021/#bib-rfc4648)

4. Return the **compressed bitstring**.

  

---

  

# Considerations

  

## Failure Modes & Mitigations

  

For a very large number of verifiable credentials it may not be practical to store them in a list all at once to iterate over them. We could implement batching and only do 1000 vcs at a time to build the bitstring or implement a rolling encodedList that updates with each new VC that is created.

  

## Security & Privacy

  

This document specifies a minimum revocation bitstring length of 131,072, or 16KB uncompressed. This is enough to give [holders](https://w3c-ccg.github.io/vc-status-list-2021/#dfn-holders) an adequate amount of herd privacy if the number of verifiable credentials issued is large enough. However, if the number of issued verifiable credentials is a small population, the ability to correlate an individual increases because the number of allocated slots in the bitstring is small.

  

---

  

# Release

  

## Success Criteria

  

- End to end integration test

  

## Rollout

  

- This can be rolled out immediately and have no impact and be backwards compatible

  

---

  

# References

  

- [https://w3c-ccg.github.io/vc-status-list-2021/#statuslist2021entry](https://w3c-ccg.github.io/vc-status-list-2021/#statuslist2021entry)