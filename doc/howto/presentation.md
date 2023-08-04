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
eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa21OMTI5NnVhcEhtTTZBMjhuR1pHZEFFbmlEMWFhNVJkRkNuOEpFdW5xVjlrI3o2TWttTjEyOTZ1YXBIbU02QTI4bkdaR2RBRW5pRDFhYTVSZEZDbjhKRXVucVY5ayIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2OTExNzU2MjQsImlzcyI6ImRpZDprZXk6ejZNa21OMTI5NnVhcEhtTTZBMjhuR1pHZEFFbmlEMWFhNVJkRkNuOEpFdW5xVjlrIiwianRpIjoiYjQ0OTI0ZWEtMDIwMi00ZTllLWJiMmEtOTg5YmQwNWQ1N2FlIiwibmJmIjoxNjkxMTc1NjI0LCJub25jZSI6IjVjNmFhZDc2LWUyZWYtNGNiNy1iMWE4LTI3MjZiMjRhM2Y0ZSIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiJdLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6WyJleUpoYkdjaU9pSkZaRVJUUVNJc0ltdHBaQ0k2SW1ScFpEcHJaWGs2ZWpaTmEyMU9NVEk1Tm5WaGNFaHRUVFpCTWpodVIxcEhaRUZGYm1sRU1XRmhOVkprUmtOdU9FcEZkVzV4VmpsckkzbzJUV3R0VGpFeU9UWjFZWEJJYlUwMlFUSTRia2RhUjJSQlJXNXBSREZoWVRWU1pFWkRiamhLUlhWdWNWWTVheUlzSW5SNWNDSTZJa3BYVkNKOS5leUpwWVhRaU9qRTJPVEV4TnpVMk1qUXNJbWx6Y3lJNkltUnBaRHByWlhrNmVqWk5hMjFPTVRJNU5uVmhjRWh0VFRaQk1qaHVSMXBIWkVGRmJtbEVNV0ZoTlZKa1JrTnVPRXBGZFc1eFZqbHJJaXdpYW5ScElqb2lPRFUyTnpRellURXRZamxsWWkwME56Z3lMV0kzTkRjdE5UbGtOekkzWVRGaVlXWTFJaXdpYm1KbUlqb3hOamt4TVRjMU5qSTBMQ0p1YjI1alpTSTZJamsyTkRkalltTmtMV0k0WkRndE5HVXhNeTFpTURKa0xURXpZelUxTm1RNVlqRTFPQ0lzSW5OMVlpSTZJbVJwWkRwclpYazZlalpOYTIxT01USTVOblZoY0VodFRUWkJNamh1UjFwSFpFRkZibWxFTVdGaE5WSmtSa051T0VwRmRXNXhWamxySWl3aWRtTWlPbnNpUUdOdmJuUmxlSFFpT2xzaWFIUjBjSE02THk5M2QzY3Vkek11YjNKbkx6SXdNVGd2WTNKbFpHVnVkR2xoYkhNdmRqRWlYU3dpZEhsd1pTSTZXeUpXWlhKcFptbGhZbXhsUTNKbFpHVnVkR2xoYkNKZExDSmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUpsYlhCc2IzbGxjaUk2SWxSQ1JDSXNJbXB2WWxScGRHeGxJam9pVkhWMGIzSnBZV3dnUVhWMGFHOXlJbjE5ZlEuWEJPbjBTd2RZZUMwN2dHM1VkT1ZLeHV2YXpfWVRpRkNmZ2tpZXJhZUZnVkEtT2tkWDM1SWl6T0NhdUtqdWlsQXJzZklvMkNYN1pYaDl3djRhUXZFRGciXX19.pJXQXSJcu4U752IE0IH21Yw26OsGMLrHE_-LpGLDHkfetQoJk56j9Fflg-P68xVgfNwZ4EBgGEJ88bXLRv1aDQ
```

Upon decoding, we can view the JWT as:

```json
{
  "alg": "EdDSA",
  "kid": "did:key:z6MkmN1296uapHmM6A28nGZGdAEniD1aa5RdFCn8JEunqV9k#z6MkmN1296uapHmM6A28nGZGdAEniD1aa5RdFCn8JEunqV9k",
  "typ": "JWT"
}
```

```json
{
  "iat": 1691175624,
  "iss": "did:key:z6MkmN1296uapHmM6A28nGZGdAEniD1aa5RdFCn8JEunqV9k",
  "jti": "b44924ea-0202-4e9e-bb2a-989bd05d57ae",
  "nbf": 1691175624,
  "nonce": "5c6aad76-e2ef-4cb7-b1a8-2726b24a3f4e",
  "vp": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiablePresentation"],
    "verifiableCredential": [
      "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa21OMTI5NnVhcEhtTTZBMjhuR1pHZEFFbmlEMWFhNVJkRkNuOEpFdW5xVjlrI3o2TWttTjEyOTZ1YXBIbU02QTI4bkdaR2RBRW5pRDFhYTVSZEZDbjhKRXVucVY5ayIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2OTExNzU2MjQsImlzcyI6ImRpZDprZXk6ejZNa21OMTI5NnVhcEhtTTZBMjhuR1pHZEFFbmlEMWFhNVJkRkNuOEpFdW5xVjlrIiwianRpIjoiODU2NzQzYTEtYjllYi00NzgyLWI3NDctNTlkNzI3YTFiYWY1IiwibmJmIjoxNjkxMTc1NjI0LCJub25jZSI6Ijk2NDdjYmNkLWI4ZDgtNGUxMy1iMDJkLTEzYzU1NmQ5YjE1OCIsInN1YiI6ImRpZDprZXk6ejZNa21OMTI5NnVhcEhtTTZBMjhuR1pHZEFFbmlEMWFhNVJkRkNuOEpFdW5xVjlrIiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJlbXBsb3llciI6IlRCRCIsImpvYlRpdGxlIjoiVHV0b3JpYWwgQXV0aG9yIn19fQ.XBOn0SwdYeC07gG3UdOVKxuvaz_YTiFCfgkieraeFgVA-OkdX35IizOCauKjuilArsfIo2CX7ZXh9wv4aQvEDg"
    ]
  }
}
```

We can also decode the JWT VC we are presenting as:

```json
{
  "alg": "EdDSA",
  "kid": "did:key:z6MkmN1296uapHmM6A28nGZGdAEniD1aa5RdFCn8JEunqV9k#z6MkmN1296uapHmM6A28nGZGdAEniD1aa5RdFCn8JEunqV9k",
  "typ": "JWT"
}
```

```json
{
  "iat": 1691175624,
  "iss": "did:key:z6MkmN1296uapHmM6A28nGZGdAEniD1aa5RdFCn8JEunqV9k",
  "jti": "856743a1-b9eb-4782-b747-59d727a1baf5",
  "nbf": 1691175624,
  "nonce": "9647cbcd-b8d8-4e13-b02d-13c556d9b158",
  "sub": "did:key:z6MkmN1296uapHmM6A28nGZGdAEniD1aa5RdFCn8JEunqV9k",
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
    "presentationJwt": "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa21OMTI5NnVhcEhtTTZBMjhuR1pHZEFFbmlEMWFhNVJkRkNuOEpFdW5xVjlrI3o2TWttTjEyOTZ1YXBIbU02QTI4bkdaR2RBRW5pRDFhYTVSZEZDbjhKRXVucVY5ayIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2OTExNzU2MjQsImlzcyI6ImRpZDprZXk6ejZNa21OMTI5NnVhcEhtTTZBMjhuR1pHZEFFbmlEMWFhNVJkRkNuOEpFdW5xVjlrIiwianRpIjoiYjQ0OTI0ZWEtMDIwMi00ZTllLWJiMmEtOTg5YmQwNWQ1N2FlIiwibmJmIjoxNjkxMTc1NjI0LCJub25jZSI6IjVjNmFhZDc2LWUyZWYtNGNiNy1iMWE4LTI3MjZiMjRhM2Y0ZSIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiJdLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6WyJleUpoYkdjaU9pSkZaRVJUUVNJc0ltdHBaQ0k2SW1ScFpEcHJaWGs2ZWpaTmEyMU9NVEk1Tm5WaGNFaHRUVFpCTWpodVIxcEhaRUZGYm1sRU1XRmhOVkprUmtOdU9FcEZkVzV4VmpsckkzbzJUV3R0VGpFeU9UWjFZWEJJYlUwMlFUSTRia2RhUjJSQlJXNXBSREZoWVRWU1pFWkRiamhLUlhWdWNWWTVheUlzSW5SNWNDSTZJa3BYVkNKOS5leUpwWVhRaU9qRTJPVEV4TnpVMk1qUXNJbWx6Y3lJNkltUnBaRHByWlhrNmVqWk5hMjFPTVRJNU5uVmhjRWh0VFRaQk1qaHVSMXBIWkVGRmJtbEVNV0ZoTlZKa1JrTnVPRXBGZFc1eFZqbHJJaXdpYW5ScElqb2lPRFUyTnpRellURXRZamxsWWkwME56Z3lMV0kzTkRjdE5UbGtOekkzWVRGaVlXWTFJaXdpYm1KbUlqb3hOamt4TVRjMU5qSTBMQ0p1YjI1alpTSTZJamsyTkRkalltTmtMV0k0WkRndE5HVXhNeTFpTURKa0xURXpZelUxTm1RNVlqRTFPQ0lzSW5OMVlpSTZJbVJwWkRwclpYazZlalpOYTIxT01USTVOblZoY0VodFRUWkJNamh1UjFwSFpFRkZibWxFTVdGaE5WSmtSa051T0VwRmRXNXhWamxySWl3aWRtTWlPbnNpUUdOdmJuUmxlSFFpT2xzaWFIUjBjSE02THk5M2QzY3Vkek11YjNKbkx6SXdNVGd2WTNKbFpHVnVkR2xoYkhNdmRqRWlYU3dpZEhsd1pTSTZXeUpXWlhKcFptbGhZbXhsUTNKbFpHVnVkR2xoYkNKZExDSmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUpsYlhCc2IzbGxjaUk2SWxSQ1JDSXNJbXB2WWxScGRHeGxJam9pVkhWMGIzSnBZV3dnUVhWMGFHOXlJbjE5ZlEuWEJPbjBTd2RZZUMwN2dHM1VkT1ZLeHV2YXpfWVRpRkNmZ2tpZXJhZUZnVkEtT2tkWDM1SWl6T0NhdUtqdWlsQXJzZklvMkNYN1pYaDl3djRhUXZFRGciXX19.pJXQXSJcu4U752IE0IH21Yw26OsGMLrHE_-LpGLDHkfetQoJk56j9Fflg-P68xVgfNwZ4EBgGEJ88bXLRv1aDQ"
}'
```

Upon success we see a response such as:

```json
{ 
  "verified": true
}
```
