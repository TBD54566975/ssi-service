# How To: Verify a Credential

## Background

Determining the validity of a [Verifiable Credential](https://www.w3.org/TR/vc-data-model/) can be a complex topic. The data model itself [has guidance on validity checks](https://www.w3.org/TR/vc-data-model/#validity-checks), and a [separate section on validation](https://www.w3.org/TR/vc-data-model/#validation), which provide useful information for implementers to consider.

There are many factors that can go into determining whether a credential is valid or not; ultimately it is up to each verifier to define their own criteria for what constitutes a valid credential from a broader set of possibilities which may include:

- Signature verification (i.e. is the credential signed by the issuer and has the signature been tampered with?)
- Credential status (i.e. not revoked or suspended)
- Credential validity (i.e. the credential is not expired)
- Credential issuer (i.e. is the issuer trusted for the claims they're attesting to?)
- Credential evidence (i.e. does the credential contain evidence that supports the claims being made?)
- Credential schema (i.e. does the credential conform to a schema defined in the `credentialSchema` property?)
- And more...

## Verification or Validation?

Both terms get thrown around and it can be confusing to determine what each means! Usually, when talking about digital signatures we talk about _signing_ and _verifying_ so _verification_ is a necessary part it making sure a given digitial signature is valid. Validation can be a more thorough process, containing any of the aforementioned validation steps, of which verification is a crucial step. Verification can be used in another sense too, since the name of the technology is "Verifiable Credential." Can a credential be verified without it being valid? Maybe, if by verified you mean the signature checks out. Can it be valid without being verified? Probably not.

For the sake of simplicity let's say that a verifiable credential undergoes a _verification process_, within which, there are a number of validity checks. After passing all validity checks the credential is both valid and verified ✅.

## Verifying a Credential

As a part of the service's credential API we expose an endpoint `/v1/credentials/verification` that can be used as a stateless utility to verify any credential. At present, the endpoint performs the following verification process:

* Make sure the credential is complaint with the VC Data Model
* Make sure the credential is not expired
* Make sure the signature of the credential is valid (currently supports both JWT and some Linked Data credentials)
* If the credential has a schema, makes sure its data complies with the schema (note: the schema must be hosted within the service)

In the future this endpoint can (and should!) be expanded to support status checks and external schema resolution, among other optional checks.

Building upon the credential we created in the [How To: Create a Credential](credential.md) guide, we'll take the credential we created, which is a JWT, and verify it.

We make a `PUT` request to the endpoint `/v1/credentials/verification` as follows:

```
curl -X PUT localhost:3000/v1/credentials/verification -d '{
    "credentialJwt": "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa20xVG1SV1JQSzZuMjFRbmNVWm5rMXRkWWtqZTg5Nm1ZQ3poTWZRNjdhc3NEI3o2TWttMVRtUldSUEs2bjIxUW5jVVpuazF0ZFlramU4OTZtWUN6aE1mUTY3YXNzRCIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2OTA1NzM1MTUsImlzcyI6ImRpZDprZXk6ejZNa20xVG1SV1JQSzZuMjFRbmNVWm5rMXRkWWtqZTg5Nm1ZQ3poTWZRNjdhc3NEIiwianRpIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwL3YxL2NyZWRlbnRpYWxzLzQ2YmMzZDI1LTZhYWYtNGY1MC05OWVkLTYxYzRiMzVmNjQxMSIsIm5iZiI6MTY5MDU3MzUxNSwibm9uY2UiOiIzMGMwNDYxZi1jMWUxLTQwNDctYWUwYS01NjgzMjdkMzY4YTYiLCJzdWIiOiJkaWQ6a2V5Ono2TWttTm52bmZ6VzNuTGllUHdlTjNuaUdMbnZwMkJqS3gzTk0xODZ2SjJ5UmcyeiIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiZmlyc3ROYW1lIjoiU2F0b3NoaSIsImxhc3ROYW1lIjoiTmFrYW1vdG8ifSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6ImFlZDZmNGYwLTVlZDctNGQ3YS1hM2RmLTU2NDMwZTFiMmE4OCIsInR5cGUiOiJKc29uU2NoZW1hMjAyMyJ9fX0.xwqpDuO6PDeEqYr6DflbeR6mhuwvVg0uR43i-7Zhy2DdaH1e3Jt4DuiMy09tZQ2jAXki0rjMNgLt7dPpzOl8BA"
}'
```

Upon success we see a response such as:

```json
{ 
  "verified": true
}
```

## Other Types of Verification

### Verifiable Presentations

The example we've gone through above verifies a credential from an _issuer_. But what about verifying the _presentation_ of a credential, or set of credentials, from a _holder_ to a _verifier_? To do this, a holder must construct what's called a [Verifiable Presentation](https://www.w3.org/TR/vc-data-model/#presentations-0), an object which is also defined by the VC Data Model, which allows a _holder_ of a verifiable credential to create an authenticated wrapper around a set of credentials it wishes to present to a _verifier_. Learn more in [our guide on presentations here](presentation.md).

### Presentation Exchange

What about applying more complex logic to the verification process? Like checking if a credential was issued from a known set of issuers? Or requesting two of one type of credential and three of another? Or checking that certain credential fields are present and have expected values? With [Presentation Exchange](https://identity.foundation/presentation-exchange/), a specification created in the [Decentralized Identity Foundation](https://identity.foundation/) this arbitarily-complex style of verification is made possible.

The SSI Service supports Presentation Exchange. Its usage will be covered in a separate how to guide.
