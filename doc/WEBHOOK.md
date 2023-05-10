# Webhooks
The webhook module in the SSI-Service allows users to create webhooks that trigger upon certain events. These events are defined by a combination of a "noun" and a "verb". When the noun and verb criteria is met the SSI-Service does a POST to the specified URL.

# Endpoint
To create a webhook, make a POST request to the following endpoint:

````bash
http://localhost:8080/v1/webhooks
````


# Request Body
The request body should include a JSON object with the following fields:

* **noun**: The object of the event that will trigger the webhook.
* **verb**: The action on the object that will trigger the webhook.
* **url**: The URL that the webhook will make a POST request to when the event happens.
Here is an example of a request body:
````json
{
    "noun": "DID",
    "verb": "Create",
    "url": "http://my-service-that-recieves-webhooks.com/webhook"
}
````

In this example, the webhook will trigger when a new DID is created.

# Supported Nouns
The SSI service supports the following nouns:

Credential
* `DID`
* `Manifest`
* `SchemaID`
* `Presentation`
* `Application`
* `Submission`

# Supported Verbs
The SSI service supports the following verbs:

* `Create`
* `Delete`

# Simple Webhook Example
Here is an example of how to setup a webhook to fire when a new DID is created:

First create a webhook by doing a POST to:

````json
POST - http://localhost:8080/v1/webhooks
{
    "noun": "DID",
    "verb": "Create",
    "url": "http://my-service-that-recieves-webhooks.com/webhook"
}
````

This command creates a webhook inside of the SSI-Service. It basically tells the SSI-Service that when a did is created post a notification to the specified URL (http://my-service-that-recieves-webhooks.com/webhook)

When a new did is created the service that is listening to the webhook will recieve this data:

````json
{
  "noun": "DID",
  "verb": "Create",
  "url": "http://host.docker.internal:8081/webhook",
  "data": {
    "did": {
      "@context": "https://www.w3.org/ns/did/v1",
      "id": "did:key:z6MkqE3sxyrKYS2UaHn7tpQz66NHaSfcuLrBuVtiWHeRoMtB",
      "verificationMethod": [
        {
          "id": "#z6MkqE3sxyrKYS2UaHn7tpQz66NHaSfcuLrBuVtiWHeRoMtB",
          "type": "Ed25519VerificationKey2018",
          "controller": "did:key:z6MkqE3sxyrKYS2UaHn7tpQz66NHaSfcuLrBuVtiWHeRoMtB",
          "publicKeyBase58": "BmnqNjbtCtY1TnwRDFT9EzpHksPmVTbqDUyng1gQt96o"
        }
      ],
      "authentication": [
        [
          "#z6MkqE3sxyrKYS2UaHn7tpQz66NHaSfcuLrBuVtiWHeRoMtB"
        ]
      ],
      "assertionMethod": [
        [
          "#z6MkqE3sxyrKYS2UaHn7tpQz66NHaSfcuLrBuVtiWHeRoMtB"
        ]
      ],
      "keyAgreement": [
        [
          "#z6MkqE3sxyrKYS2UaHn7tpQz66NHaSfcuLrBuVtiWHeRoMtB"
        ]
      ],
      "capabilityDelegation": [
        [
          "#z6MkqE3sxyrKYS2UaHn7tpQz66NHaSfcuLrBuVtiWHeRoMtB"
        ]
      ]
    }
  }
}
````

This response object has the Noun and Verb that happened that fired it, and the data attached to the response of the initial call


# Presentation Exchange Webhook Example
Here is an example of how to setup a webhook to fire when a new presentation submission is created:


First setup a webhook object in the SSI-Service that will POST to the given URL when a Submission is created
````json
POST - http://localhost:8080/v1/webhooks
{
    "noun": "Submission",
    "verb": "Create",
    "url": "http://my-service-that-recieves-webhooks.com/webhook"
}
````

Use the SSI Service to set up a Presentation Definition and corresponding Presentation Request to accept a KYC credential. We have the prerequisites for this in our steelthread integration test

When someone uses the SSI-Service to Create a submission:
````json
POST - http://localhost:8080/v1/presentations/submissions
{
  "submissionJwt": "..."
}
````

A new submission is created the service that is listening to the webhook will recieve this data:
````json
 {
  "noun": "Submission",
  "verb": "Create",
  "url": "http://my-service-that-recieves-webhooks.com/webhook",
  "data": {
    "id": "presentations/submissions/e875b34e-35fd-4ad9-8805-4f16bf98df71",
    "done": false,
    "result": {}
  }
} 
````

The external webhook service that received this notification can then get the required objects, do validation, and make a call to the SSI-Service to approve or to not approve.