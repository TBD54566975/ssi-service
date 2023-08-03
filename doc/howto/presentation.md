# How To: Verify a Presentation

## Background

By now you should be familiar with [DIDs](did.md) and [Verifiable Credentials](credential.md). A next logical question, once you've started using the technologies, is "how do I make use of it?" To use Verifiable Credentials anywhere you need to present them—that is to share them with another party. There are a few pieces of sharing: creating a package that you share and transmitting the data to another party. Transmission, simliar to credential issuance, can be accomplished with a number of different mechanisms like [Web5](https://github.com/TBD54566975/dwn-sdk-js#readme) and [OpenID Connect](https://openid.net/sg/openid4vc/). Packaging a credential, or set of credentials, into a presentation is something that has been standardized at the W3C in the same specification that defines Verifiable Credentials, called [Verifiable Presentations](https://www.w3.org/TR/vc-data-model/#presentations-0).

Verifiable Presentations are a standard data container for sharing credentials that provide a number of benefits, namely:

1. A common data format designed to work with Verifiable Credentials, reusable in any number of use cases.
2. Guidance on constructing presentations that ensures integrity protection and guards against replay attacks.

Presentations impose no constraints on who can construct a presentation, or what may be presented. This means if you have multiple credentials issued to different DIDs, you can still construct a Verifiable Presentation to present those credentials at the same time. This is why you will see that the [`proof` property](https://www.w3.org/TR/vc-data-model/#example-basic-structure-of-a-presentation) can be an array. Verifiers must take care to make sure that the credentials in a given presentation _can be_ presented by the presenter, and that the credentials themselves are valid.

Verifiable Presentations are currently accepted in two main SSI Service flows: when verifying [Presentation Submissoins](https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-submission) when using [Presentation Exchange](https://identity.foundation/presentation-exchange/spec/v2.0.0), and verifying [Credential Applications](https://identity.foundation/credential-manifest/#credential-application) when using [Credential Manifest](https://identity.foundation/credential-manifest). As a utility, we've also exposed an endpoint to statelessly verify a presentation at `/v1/presentations/verification`.

## Constructing a Verifiable Presentation

Constructing a Verifiable Presentation is out of scope for the SSI Service, since the service acts as a utility for organizations managing their own credentials. However, the [SSI SDK](https://github.com/TBD54566975/ssi-sdk) provides a standards-based implementation of Verifiable Presentations using the [JWT representation](https://www.w3.org/TR/vc-data-model/#jwt-and-jws-considerations).

Library code for Verifiable Presentations can be found [here](https://github.com/TBD54566975/ssi-sdk/blob/d5c302a1d9b9d04c1636a0c8dfda015f61bb0f6b/credential/model.go#L110) with associated signing and verificatoin logic [here](https://github.com/TBD54566975/ssi-sdk/blob/d5c302a1d9b9d04c1636a0c8dfda015f61bb0f6b/credential/integrity/jwt.go#L208). An example of constructing a Verifiable Presentation using the SDK is provided below as a [runnable unit test here](presentation_test.go).

Upon running, we should see the test create a credential and a presentation for that credential as a JWT.

```plaintext
eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa29TNDhad0xLMzJtbW1kR1d6UjdndDJLOGJEdU1HeTk5SFBwM3RXa1BlNTg5I3o2TWtvUzQ4WndMSzMybW1tZEdXelI3Z3QySzhiRHVNR3k5OUhQcDN0V2tQZTU4OSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2OTExMDA4NDYsImlzcyI6ImRpZDprZXk6ejZNa29TNDhad0xLMzJtbW1kR1d6UjdndDJLOGJEdU1HeTk5SFBwM3RXa1BlNTg5IiwianRpIjoiM2U4N2MxZWQtZTIyZi00NDgxLTk2MzMtMzc0YzYxYTY4YmRmIiwibmJmIjoxNjkxMTAwODQ2LCJub25jZSI6Ijg1NDE4NDM2LWY3MjktNDBkYi04N2QxLTUxZWFmNmE2MWVmYiIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiJdLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6WyJleUpoYkdjaU9pSkZaRVJUUVNJc0ltdHBaQ0k2SW1ScFpEcHJaWGs2ZWpaTmEyOVRORGhhZDB4TE16SnRiVzFrUjFkNlVqZG5kREpMT0dKRWRVMUhlVGs1U0ZCd00zUlhhMUJsTlRnNUkzbzJUV3R2VXpRNFduZE1Tek15YlcxdFpFZFhlbEkzWjNReVN6aGlSSFZOUjNrNU9VaFFjRE4wVjJ0UVpUVTRPU0lzSW5SNWNDSTZJa3BYVkNKOS5leUpwWVhRaU9qRTJPVEV4TURBNE5EWXNJbWx6Y3lJNkltUnBaRHByWlhrNmVqWk5hMjlUTkRoYWQweExNekp0Ylcxa1IxZDZVamRuZERKTE9HSkVkVTFIZVRrNVNGQndNM1JYYTFCbE5UZzVJaXdpYW5ScElqb2laVEV5Wm1Gak16Z3RaREJsTmkwMFpXSTVMVGcxT1RVdE16WTNNVEptWTJZM1l6UmxJaXdpYm1KbUlqb3hOamt4TVRBd09EUTJMQ0p1YjI1alpTSTZJbU5rTnpVMU1ETTVMVEJoTnpFdE5HWmxaUzFoTVdZMUxUa3lObUZsTmpBME9USmlNU0lzSW5OMVlpSTZJbVJwWkRwclpYazZlalpOYTI5VE5EaGFkMHhMTXpKdGJXMWtSMWQ2VWpkbmRESkxPR0pFZFUxSGVUazVTRkJ3TTNSWGExQmxOVGc1SWl3aWRtTWlPbnNpUUdOdmJuUmxlSFFpT2xzaWFIUjBjSE02THk5M2QzY3Vkek11YjNKbkx6SXdNVGd2WTNKbFpHVnVkR2xoYkhNdmRqRWlYU3dpZEhsd1pTSTZXeUpXWlhKcFptbGhZbXhsUTNKbFpHVnVkR2xoYkNKZExDSmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUpsYlhCc2IzbGxjaUk2SWxSQ1JDSXNJbXB2WWxScGRHeGxJam9pVkhWMGIzSnBZV3dnUVhWMGFHOXlJbjE5ZlEucXpCNHp6WnNhVlRobF9EV2xFLTFNM1Z4WkN5eWlwT2FfWFdZV1cyRC1hYkJSWnFPNzVGalBNWkFBZGVORUNGbENPTENIVXlwaXlSbE5XSk1ISVNIQ3ciXX19.x7AJrwrhw3InIrcZlabQr71Fo3UL7oaMoCmX5GSnMopS7560GuO5yUSxzmZYa8UAgyUVYFRPr4Z3go-uf6c6Aw

```

Upon decoding, we can view the JWT as:

```json
{
  "alg": "EdDSA",
  "kid": "did:key:z6MkjvUwjB4ds3vRmKmfyQ3eBUFbkQ9iemgBkydqs8pSrwuA#z6MkjvUwjB4ds3vRmKmfyQ3eBUFbkQ9iemgBkydqs8pSrwuA",
  "typ": "JWT"
}
```

```json
{
  "iat": 1691100271,
  "jti": "e31f019f-48df-4b6c-8607-b72fd6716ba6",
  "nbf": 1691100271,
  "nonce": "4eea8c4d-0ad8-46b8-9dbe-2aa53e34c631",
  "vp": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiablePresentation"],
    "verifiableCredential": [
      "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa2p2VXdqQjRkczN2Um1LbWZ5UTNlQlVGYmtROWllbWdCa3lkcXM4cFNyd3VBI3o2TWtqdlV3akI0ZHMzdlJtS21meVEzZUJVRmJrUTlpZW1nQmt5ZHFzOHBTcnd1QSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2OTExMDAyNzEsImlzcyI6ImRpZDprZXk6ejZNa2p2VXdqQjRkczN2Um1LbWZ5UTNlQlVGYmtROWllbWdCa3lkcXM4cFNyd3VBIiwianRpIjoiNzljMjFjNzEtOTA3OC00M2Y5LTlhNjUtMTAyNjMyOGYyMmE5IiwibmJmIjoxNjkxMTAwMjcxLCJub25jZSI6ImFhOThkZjE2LTBjYzUtNDY0OC04YjZkLWMyZThiNWU0NmYwYSIsInN1YiI6ImRpZDprZXk6ejZNa2p2VXdqQjRkczN2Um1LbWZ5UTNlQlVGYmtROWllbWdCa3lkcXM4cFNyd3VBIiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJlbXBsb3llciI6IlRCRCIsImpvYlRpdGxlIjoiVHV0b3JpYWwgQXV0aG9yIn19fQ.njyudGydOhX1nTML5BEI95HUgKW2ejWQsS4AlQwpWBcW6oc2XXtaR8LW4FzI_cIpSU7MYefFam685S7YHsctBQ"
    ]
  }
}
```

We can also decode the JWT VC we are presenting as:

```json
{
  "alg": "EdDSA",
  "kid": "did:key:z6MkjvUwjB4ds3vRmKmfyQ3eBUFbkQ9iemgBkydqs8pSrwuA#z6MkjvUwjB4ds3vRmKmfyQ3eBUFbkQ9iemgBkydqs8pSrwuA",
  "typ": "JWT"
}
```

```json
{
  "iat": 1691100271,
  "iss": "did:key:z6MkjvUwjB4ds3vRmKmfyQ3eBUFbkQ9iemgBkydqs8pSrwuA",
  "jti": "79c21c71-9078-43f9-9a65-1026328f22a9",
  "nbf": 1691100271,
  "nonce": "aa98df16-0cc5-4648-8b6d-c2e8b5e46f0a",
  "sub": "did:key:z6MkjvUwjB4ds3vRmKmfyQ3eBUFbkQ9iemgBkydqs8pSrwuA",
  "vc": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1"
    ],
    "type": [
      "VerifiableCredential"
    ],
    "credentialSubject": {
      "employer": "TBD",
      "jobTitle": "Tutorial Author"
    }
  }
}
```

## Verifying a Presentation

Once we have a Verifiable Presentation we can use the service to verify it by making a `PUT` request to `/v1/presentations/verification`. A sample request is as follows:

```bash
curl -X PUT localhost:3000/v1/presentations/verification -d '{
    "presentationJwt": "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa29TNDhad0xLMzJtbW1kR1d6UjdndDJLOGJEdU1HeTk5SFBwM3RXa1BlNTg5I3o2TWtvUzQ4WndMSzMybW1tZEdXelI3Z3QySzhiRHVNR3k5OUhQcDN0V2tQZTU4OSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2OTExMDA4NDYsImlzcyI6ImRpZDprZXk6ejZNa29TNDhad0xLMzJtbW1kR1d6UjdndDJLOGJEdU1HeTk5SFBwM3RXa1BlNTg5IiwianRpIjoiM2U4N2MxZWQtZTIyZi00NDgxLTk2MzMtMzc0YzYxYTY4YmRmIiwibmJmIjoxNjkxMTAwODQ2LCJub25jZSI6Ijg1NDE4NDM2LWY3MjktNDBkYi04N2QxLTUxZWFmNmE2MWVmYiIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiJdLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6WyJleUpoYkdjaU9pSkZaRVJUUVNJc0ltdHBaQ0k2SW1ScFpEcHJaWGs2ZWpaTmEyOVRORGhhZDB4TE16SnRiVzFrUjFkNlVqZG5kREpMT0dKRWRVMUhlVGs1U0ZCd00zUlhhMUJsTlRnNUkzbzJUV3R2VXpRNFduZE1Tek15YlcxdFpFZFhlbEkzWjNReVN6aGlSSFZOUjNrNU9VaFFjRE4wVjJ0UVpUVTRPU0lzSW5SNWNDSTZJa3BYVkNKOS5leUpwWVhRaU9qRTJPVEV4TURBNE5EWXNJbWx6Y3lJNkltUnBaRHByWlhrNmVqWk5hMjlUTkRoYWQweExNekp0Ylcxa1IxZDZVamRuZERKTE9HSkVkVTFIZVRrNVNGQndNM1JYYTFCbE5UZzVJaXdpYW5ScElqb2laVEV5Wm1Gak16Z3RaREJsTmkwMFpXSTVMVGcxT1RVdE16WTNNVEptWTJZM1l6UmxJaXdpYm1KbUlqb3hOamt4TVRBd09EUTJMQ0p1YjI1alpTSTZJbU5rTnpVMU1ETTVMVEJoTnpFdE5HWmxaUzFoTVdZMUxUa3lObUZsTmpBME9USmlNU0lzSW5OMVlpSTZJbVJwWkRwclpYazZlalpOYTI5VE5EaGFkMHhMTXpKdGJXMWtSMWQ2VWpkbmRESkxPR0pFZFUxSGVUazVTRkJ3TTNSWGExQmxOVGc1SWl3aWRtTWlPbnNpUUdOdmJuUmxlSFFpT2xzaWFIUjBjSE02THk5M2QzY3Vkek11YjNKbkx6SXdNVGd2WTNKbFpHVnVkR2xoYkhNdmRqRWlYU3dpZEhsd1pTSTZXeUpXWlhKcFptbGhZbXhsUTNKbFpHVnVkR2xoYkNKZExDSmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUpsYlhCc2IzbGxjaUk2SWxSQ1JDSXNJbXB2WWxScGRHeGxJam9pVkhWMGIzSnBZV3dnUVhWMGFHOXlJbjE5ZlEucXpCNHp6WnNhVlRobF9EV2xFLTFNM1Z4WkN5eWlwT2FfWFdZV1cyRC1hYkJSWnFPNzVGalBNWkFBZGVORUNGbENPTENIVXlwaXlSbE5XSk1ISVNIQ3ciXX19.x7AJrwrhw3InIrcZlabQr71Fo3UL7oaMoCmX5GSnMopS7560GuO5yUSxzmZYa8UAgyUVYFRPr4Z3go-uf6c6Aw"
}'
```
