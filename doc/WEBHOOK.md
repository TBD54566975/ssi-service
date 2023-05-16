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

First create a webhook by doing a PUT to:

````json
PUT - http://localhost:8080/v1/webhooks
{
    "noun": "DID",
    "verb": "Create",
    "url": "http://my-service-that-recieves-webhooks.com/webhook"
}
````

This command creates a webhook inside of the SSI-Service. It tells the SSI-Service to make a POST request to the specified URL (http://my-service-that-recieves-webhooks.com/webhook) after a DID is created (i.e. after the [Create DID Document](https://developer.tbd.website/docs/apis/ssi-service#tag/WebhookAPI) endpoint is called).

When a new DID is created the service that is listening for the webhook will receive this data:

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

This response object has the Noun and Verb that happened that fired it, and the data attached to the response of the initial call.


# Presentation Exchange Webhook Example
Here is an example of how to setup a webhook to fire when a new presentation submission is received by the service:


First setup a webhook object in the SSI-Service that will POST to the given URL when a Submission is received by the service:
````json
PUT - http://localhost:8080/v1/webhooks
{
    "noun": "Submission",
    "verb": "Create",
    "url": "http://my-service-that-recieves-webhooks.com/webhook"
}
````

Use the SSI Service to set up a Presentation Definition and corresponding Presentation Request to accept a KYC credential. We have the prerequisites for this in our [steelthread integration test](https://github.com/TBD54566975/ssi-service/blob/main/integration/steelthread_integration_test.go)

When someone uses the SSI-Service to Create a submission:
````json
PUT - http://localhost:8080/v1/presentations/submissions
{
  "submissionJwt": "..."
}
````

Upon receiving a new submission the service that is registered to listen for the webhook will receive this data:
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

The service that is examing this can find more information about this submission by doing:

````json
GET - http://localhost:8080/v1/presentations/submissions/e875b34e-35fd-4ad9-8805-4f16bf98df71
````

Example Presentation Submission Response:
````json
{
    "status": "pending",
    "verifiablePresentation": {
        "@context": [
            "https://www.w3.org/2018/credentials/v1"
        ],
        "holder": "did:key:z6MkiVxsSpuuZRw34mxBfZ8jzi18BagQoXJnLuNWNfM1YgYL",
        "type": [
            "VerifiablePresentation"
        ],
        "presentation_submission": {
            "definition_id": "dd561f5c-568b-422a-b2cc-3abf0cc494f7",
            "descriptor_map": [
                {
                    "format": "jwt_vp",
                    "id": "wa_driver_license",
                    "path": "$.verifiableCredential[0]"
                }
            ],
            "id": "291b766b-bbf6-4260-ae8f-7339e7ac6dcc"
        },
        "verifiableCredential": [
            "eyJhbGciOiJFZERTQSIsImtpZCI6IiN6Nk1rczg4QmROWEV3QVdYRjFIc2VhTG5rZTE4S0RLZFVoeW9YQ1lOREI5NlJuSmUiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjI1ODAxMzAwODAsImlhdCI6MTY4MzgyNDM5NCwiaXNzIjoiZGlkOmtleTp6Nk1rczg4QmROWEV3QVdYRjFIc2VhTG5rZTE4S0RLZFVoeW9YQ1lOREI5NlJuSmUiLCJqdGkiOiI0ZmM3YWFjNS00MTQ1LTQ1MWItYWM3My1mNDFmZTg1MWFhODkiLCJuYmYiOjE2ODM4MjQzOTQsIm5vbmNlIjoiZGQ3MjI2MzQtOTRlMC00MDJkLWEzMmMtYTU1ZTIyODE1Y2VjIiwic3ViIjoiZGlkOmtleTp6Nk1raVZ4c1NwdXVaUnczNG14QmZaOGp6aTE4QmFnUW9YSm5MdU5XTmZNMVlnWUwiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIl0sImlzc3VlciI6IiIsImlzc3VhbmNlRGF0ZSI6IiIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImFkZGl0aW9uYWxOYW1lIjoiTWNsb3ZpbiIsImRhdGVPZkJpcnRoIjoiMTk4Ny0wMS0wMiIsImZhbWlseU5hbWUiOiJBbmRyZXMiLCJnaXZlbk5hbWUiOiJVcmliZSJ9fX0.yN1OXIOGki0HTWyDtWqR1KWDHoqorIUEPuyYEA7l0dOud1ENf8nsdOTzAB3c2XMxk70KPwEalekDeiagr6A4DQ"
        ]
    }
}
````


If the presentation submission satisfies all requirements, it can be approved with the following:

````json
PUT- http://localhost:8080/v1/presentations/submissions/e875b34e-35fd-4ad9-8805-4f16bf98df71/review
{
    "approved": true,
    "reason": "my reason"
}
````

This will complete the flow for the presentation submission.