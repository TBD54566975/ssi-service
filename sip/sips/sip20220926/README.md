```yaml
SIP: TBD
Title: External Claims Verification
Author(s): Moe Jangda
Comments URI: TBD
Status: Draft
Created: September 26, 2022
Updated: September 26, 2022
Discussion: TBD
```

# Abstract
The proposal below describes a potential mechanism/process that enables issuing parties to integrate their claims verification process(es) as an independent service separated by a network boundary.

## Background
The current SSI Service credential issuance flow lacks a mechanism that allows an issuing party to verify the claims presented in an [`CredentialApplication`](https://identity.foundation/credential-manifest/#credential-application). Instead, the application is immediately fullfilled or denied depending upon whether the supplied [`CredentialApplication`](https://identity.foundation/credential-manifest/#credential-application) adheres to the structure defined in the [credential manifest specification](https://identity.foundation/credential-manifest/#credential-application). 

While this may deem suffice for a few use-cases, many use-cases will require a claims verification step that is **_specific_** to the desired credential and **_unique_** to the issuing party prior to credential issuance (e.g. KYC credentials). For example, let's assume that the application for a KYC credential requires the following fields:

| Field               | Description                                       |
| ------------------- | ------------------------------------------------- |
| Customer Name       | First Name, Last Name, Middle Name                |
| DOB                 | Universal Date Format: YYYY/MM/DD                 |
| Residential Address | Street Address, City, State, Country and Zip Code |
| TaxID               | USA this can include an SSN or ITIN               | 


An issuing party of this credential will need to verify the **_self issued_** claims provided in the application in addition to furnishing [evidence](https://www.w3.org/TR/vc-data-model/#evidence) to indicate the means exercised to verify said claims. 

## Goals
* Provide a mechanism/process through which issuing parties can integrate their claims verification process(es) as an independent service separated by a network boundary.
* Allow for credential issuance to be asynchronous

# Specification

![application-submission](https://i.imgur.com/NgSVx53.png)

![credential issuance](https://i.imgur.com/mHn8qa8.png)



The overall desired mechanism can be broken down into the following questions:
* How does is an Application Submitted?
  * Answered in the [Application Submission](https://hackmd.io/5tdrPaE_RzWgGoi1A2_iEg?view#Application-Submission) section of [Asynchronous Credential Issuance](https://hackmd.io/5tdrPaE_RzWgGoi1A2_iEg?view#Asynchronous-Credential-Issuance)
* How does the Applicant receive the `CredentialResponse`?
  * Answered in the [`CredentialResponse` Delivery](https://hackmd.io/5tdrPaE_RzWgGoi1A2_iEg?view#Application-Submission) section of [Asynchronous Credential Issuance](https://hackmd.io/5tdrPaE_RzWgGoi1A2_iEg?view#Asynchronous-Credential-Issuance)
* How does the Claims Verification Service receive an application (aka claims that need to be verified)
  * Answered in the [Event Webhook](https://hackmd.io/5tdrPaE_RzWgGoi1A2_iEg?view#Event-Webhook) section
* How does the Claims Verification Service inform the SSI service to issue a credential?
  * Answered in the 

## Asynchronous Credential Issuance

### Application Submission

#### Endpoint: `PUT /v1/manifests/applications`
This has already been implemented in the SSI Service as the [`SubmitApplication` Endpoint](https://github.com/TBD54566975/ssi-service/blob/main/pkg/server/router/manifest.go#L197-L227) 

#### Authz
Anyone

#### Request Body
The Request Body can remain unchanged

#### Response Body
The [current response](https://github.com/TBD54566975/ssi-service/blob/main/pkg/server/router/manifest.go#L192-L195) for this request contains a `CredentialResponse`. A `CredentialResponse` can only have two outcomes: `fulfilled` or `denied`. In order to support asynchronous issuance flows, we'll need to change the response to something that conveys the `status` of the current application submission (`ApplicationSubmission`)

**`ApplicationSubmissionResponse`**

| Field          | Type        | Description                                                          |
| -------------- | ----------- | -------------------------------------------------------------------- |
| `id`           | `string`    | application id                                                       |
| `manifest`     | `string`    | manifest id                                                          |
| `status`       | `string`    | status of the application. :warning: decide on all possible statuses |
| `date_created` | `timestamp` | ISO-8601 timestamp of creation date                                  |
| `date_updated` | `timestamp` | ISO-8601 timestamp of last updated date                              |


### `CredentialResponse` Delivery
In order to support asynchronous issuance, we'll need an endpoint that can be used by the applicant to poll for a credential response. 

#### Endpoint: `GET /v1/manifests/applications/:application_id`
This endpoint can be used to poll for status updates

#### Authz
only the applicant and admins should be allowed

#### Request Body
N/A

#### Response Body
Returns `ApplicationSubmissionResponse` defined in the Application Submission Section


#### Endpoint: `GET /v1/manifests/applications/:application_id/response`

#### Authz
only the applicant and admins should be allowed

#### Request Body
N/A

#### Response Body
* If a `CredentialsResponse` is available
  * A Verifiable Presentation with an embedded Credential Response as per the [specification](https://identity.foundation/credential-manifest/#credential-response)
* If no `CredentialsResponse` is available
  * `404: Not found`


## Event Webhook
We can leverage [webhooks](https://webhooks.fyi/docs/webhook-primer) to provide/notify the Claims Verification Service with an application whose claims need to be verified.

### Webhook Creation
Webhooks can be created by making a request to a SSI Service API Endpoint

#### **Endpoint** `POST /v1/webhooks/applications`

#### Authz
Internal Only

#### **Request Body**

| Field         | Type     | Description                                                                                                     | Required (Y/N) |
| ------------- | -------- | --------------------------------------------------------------------------------------------------------------- | -------------- |
| `url`         | `String` | The URL of the webhook endpoint.                                                                                | Y              |
| `manifest_id` | `String` | an optional manifest id that can be used to limit what triggers the webhooks. Not providing a value acts as `*` | N              | 


* :warning: **TODO**: consider a more generalized approach based on events like stripe
  * _Note: Seemed like a bit overkill to me, but definitely worth evaluating._


#### Security Considerations
:warning: **TODO**: decide on which security controls to use (if any). Well known controls are listed [here](https://webhooks.fyi/security/intro)

### Webhook Notification Request
The request sent from the SSI service to a webhook

#### Request Body
:warning: **TODO**: Decide on how much this should be generalized

| Field   | Type     | Description                                                       | Required (Y/N) |
| ------- | -------- | ----------------------------------------------------------------- | -------------- |
| `event` | `String` | The event type (e.g. `application`)                               | Y              |
| `data`  | `Object` | The resource related to the event. e.g. a `CredentialApplication` | N              | 


#### Retry Mechanism
* :warning: **TODO**: Decide on whether we want to introduce a retry mechanism. [Helpful resource](https://webhooks.fyi/ops-experience/resiliency)

## Credential Issuance

### `Claims Verification Service -> SSI Service`
The SSI Service needs to be informed about the result of claims verification so that it can construct a `CredentialsResponse` for the appropriate application submission. This can be done by adding an API endpoint to the SSI service that can be used by a downstream Claims Verification Service.

#### **Endpoint** `PUT /v1/manifests/applications/:application_id/response`

#### Authz
Internal Only

#### **Request Body** 

**`ClaimsVerificationResult`**
| Field      | Type          | Description                                                                                   | Required (Y/N) |
| ---------- | ------------- | --------------------------------------------------------------------------------------------- | -------------- |
| `fulfill`  | `Boolean`     | Boolean indicating whether to fulfill or reject the application                               | **Y**          |
| `evidence` | :warning: TBD | [Evidence](https://www.w3.org/TR/vc-data-model/#evidence) to include in the issued credential | **N**          |


#### **Response Body**
A Verifiable Presentation with an embedded Credential Response as per the specification


# Considerations

## Alternatives

### Intra-process Lifecycle Hooks
Creating lifecycle hooks within the SSI service that allow developers to attach handlers that execute when triggered

#### Tradeoffs

*What is lost with this approach? What is gained?*

### Server Sent Events (SSE)

#### Tradeoffs

## Failure Modes & Mitigations

*What can go wrong and why? How can it be mitigated?*

## Dependencies

*What dependencies exist between this and other pieces of work?*

## Future Work

*What work comes next/what does this enable?*

## Security & Privacy

*What security and/or privacy implications are relevant to the proposed change?*

---

# Release

## Success Criteria
Success can be gauged by a successful integration of an issuing party's Claims Verification Service and the SSI Service. More specifically:

- [ ] Webhook is sucessfully created
- [ ] Webhook is triggered when an application is submitted
- [ ] Claims Verification Service can inform the SSI service to issue a credential 
- [ ] SSI Service constructs and stores a Credential Response appropriately
- [ ] Applicant is able to poll for an application response

## Tasks
- Implement endpoint to Create Webhook based on [Webhook Creation]() section
  - Add Handler
  - Add Request Body Validation
  - Store Webhook in DB
- Implement Webhook triggering logic based on [Webhook Messages]() section
  - Create `Event` Data Model
  - Create and store `Event`s 
  - Trigger registered webhooks based on `Event` type
- Implement endpoint to create `CredentialResponse` for a specific application based on [Credential Issuance](https://hackmd.io/5tdrPaE_RzWgGoi1A2_iEg?view#Credential-Issuance) section
  - Add Handler
  - Add Request Body Validation
  - Write logic to generate `CredentialResponse` based on values provided in request body
- Implement endpoint to get `ApplicationSubmission` based on [`CredentialResponse` delivery](https://hackmd.io/5tdrPaE_RzWgGoi1A2_iEg?view#Application-Submission) section
  - Add Handler
- Implement endpoint to get `CredentialResponse` for a given application submission based on [`CredentialResponse` delivery](https://hackmd.io/5tdrPaE_RzWgGoi1A2_iEg?view#Application-Submission) section

- Refactor [`SubmitApplicationRequest`](https://github.com/TBD54566975/ssi-service/blob/main/pkg/server/router/manifest.go#L179-L183) based on [Application Submission](https://hackmd.io/5tdrPaE_RzWgGoi1A2_iEg?view#Application-Submission) section

## Rollout

Mid November

:warning: **TODO**: Decide on how we can roll this out in phases

---

# References

*Enumeration of content links used in this document*

* *Link 1*
* *Link 2*