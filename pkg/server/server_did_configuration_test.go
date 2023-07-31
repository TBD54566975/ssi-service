package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TBD54566975/ssi-sdk/credential/integrity"
	"github.com/TBD54566975/ssi-sdk/did/resolution"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
	wellknown "github.com/tbd54566975/ssi-service/pkg/service/well-known"
	"github.com/tbd54566975/ssi-service/pkg/testutil"
	"gopkg.in/h2non/gock.v1"
)

const w3cCredentialContext = `{
  "@context": {
    "@version": 1.1,
    "@protected": true,

    "id": "@id",
    "type": "@type",

    "VerifiableCredential": {
      "@id": "https://www.w3.org/2018/credentials#VerifiableCredential",
      "@context": {
        "@version": 1.1,
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "cred": "https://www.w3.org/2018/credentials#",
        "sec": "https://w3id.org/security#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",

        "credentialSchema": {
          "@id": "cred:credentialSchema",
          "@type": "@id",
          "@context": {
            "@version": 1.1,
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "cred": "https://www.w3.org/2018/credentials#",

            "JsonSchemaValidator2018": "cred:JsonSchemaValidator2018"
          }
        },
        "credentialStatus": {"@id": "cred:credentialStatus", "@type": "@id"},
        "credentialSubject": {"@id": "cred:credentialSubject", "@type": "@id"},
        "evidence": {"@id": "cred:evidence", "@type": "@id"},
        "expirationDate": {"@id": "cred:expirationDate", "@type": "xsd:dateTime"},
        "holder": {"@id": "cred:holder", "@type": "@id"},
        "issued": {"@id": "cred:issued", "@type": "xsd:dateTime"},
        "issuer": {"@id": "cred:issuer", "@type": "@id"},
        "issuanceDate": {"@id": "cred:issuanceDate", "@type": "xsd:dateTime"},
        "proof": {"@id": "sec:proof", "@type": "@id", "@container": "@graph"},
        "refreshService": {
          "@id": "cred:refreshService",
          "@type": "@id",
          "@context": {
            "@version": 1.1,
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "cred": "https://www.w3.org/2018/credentials#",

            "ManualRefreshService2018": "cred:ManualRefreshService2018"
          }
        },
        "termsOfUse": {"@id": "cred:termsOfUse", "@type": "@id"},
        "validFrom": {"@id": "cred:validFrom", "@type": "xsd:dateTime"},
        "validUntil": {"@id": "cred:validUntil", "@type": "xsd:dateTime"}
      }
    },

    "VerifiablePresentation": {
      "@id": "https://www.w3.org/2018/credentials#VerifiablePresentation",
      "@context": {
        "@version": 1.1,
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "cred": "https://www.w3.org/2018/credentials#",
        "sec": "https://w3id.org/security#",

        "holder": {"@id": "cred:holder", "@type": "@id"},
        "proof": {"@id": "sec:proof", "@type": "@id", "@container": "@graph"},
        "verifiableCredential": {"@id": "cred:verifiableCredential", "@type": "@id", "@container": "@graph"}
      }
    },

    "EcdsaSecp256k1Signature2019": {
      "@id": "https://w3id.org/security#EcdsaSecp256k1Signature2019",
      "@context": {
        "@version": 1.1,
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "sec": "https://w3id.org/security#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",

        "challenge": "sec:challenge",
        "created": {"@id": "http://purl.org/dc/terms/created", "@type": "xsd:dateTime"},
        "domain": "sec:domain",
        "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
        "jws": "sec:jws",
        "nonce": "sec:nonce",
        "proofPurpose": {
          "@id": "sec:proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@version": 1.1,
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "sec": "https://w3id.org/security#",

            "assertionMethod": {"@id": "sec:assertionMethod", "@type": "@id", "@container": "@set"},
            "authentication": {"@id": "sec:authenticationMethod", "@type": "@id", "@container": "@set"}
          }
        },
        "proofValue": "sec:proofValue",
        "verificationMethod": {"@id": "sec:verificationMethod", "@type": "@id"}
      }
    },

    "EcdsaSecp256r1Signature2019": {
      "@id": "https://w3id.org/security#EcdsaSecp256r1Signature2019",
      "@context": {
        "@version": 1.1,
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "sec": "https://w3id.org/security#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",

        "challenge": "sec:challenge",
        "created": {"@id": "http://purl.org/dc/terms/created", "@type": "xsd:dateTime"},
        "domain": "sec:domain",
        "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
        "jws": "sec:jws",
        "nonce": "sec:nonce",
        "proofPurpose": {
          "@id": "sec:proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@version": 1.1,
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "sec": "https://w3id.org/security#",

            "assertionMethod": {"@id": "sec:assertionMethod", "@type": "@id", "@container": "@set"},
            "authentication": {"@id": "sec:authenticationMethod", "@type": "@id", "@container": "@set"}
          }
        },
        "proofValue": "sec:proofValue",
        "verificationMethod": {"@id": "sec:verificationMethod", "@type": "@id"}
      }
    },

    "Ed25519Signature2018": {
      "@id": "https://w3id.org/security#Ed25519Signature2018",
      "@context": {
        "@version": 1.1,
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "sec": "https://w3id.org/security#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",

        "challenge": "sec:challenge",
        "created": {"@id": "http://purl.org/dc/terms/created", "@type": "xsd:dateTime"},
        "domain": "sec:domain",
        "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
        "jws": "sec:jws",
        "nonce": "sec:nonce",
        "proofPurpose": {
          "@id": "sec:proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@version": 1.1,
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "sec": "https://w3id.org/security#",

            "assertionMethod": {"@id": "sec:assertionMethod", "@type": "@id", "@container": "@set"},
            "authentication": {"@id": "sec:authenticationMethod", "@type": "@id", "@container": "@set"}
          }
        },
        "proofValue": "sec:proofValue",
        "verificationMethod": {"@id": "sec:verificationMethod", "@type": "@id"}
      }
    },

    "RsaSignature2018": {
      "@id": "https://w3id.org/security#RsaSignature2018",
      "@context": {
        "@version": 1.1,
        "@protected": true,

        "challenge": "sec:challenge",
        "created": {"@id": "http://purl.org/dc/terms/created", "@type": "xsd:dateTime"},
        "domain": "sec:domain",
        "expires": {"@id": "sec:expiration", "@type": "xsd:dateTime"},
        "jws": "sec:jws",
        "nonce": "sec:nonce",
        "proofPurpose": {
          "@id": "sec:proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@version": 1.1,
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "sec": "https://w3id.org/security#",

            "assertionMethod": {"@id": "sec:assertionMethod", "@type": "@id", "@container": "@set"},
            "authentication": {"@id": "sec:authenticationMethod", "@type": "@id", "@container": "@set"}
          }
        },
        "proofValue": "sec:proofValue",
        "verificationMethod": {"@id": "sec:verificationMethod", "@type": "@id"}
      }
    },

    "proof": {"@id": "https://w3id.org/security#proof", "@type": "@id", "@container": "@graph"}
  }
}`

const wellKnownDIDContext = `{
  "@context": [
    {
      "@version": 1.1,
      "@protected": true,
      "LinkedDomains": "https://identity.foundation/.well-known/resources/did-configuration/#LinkedDomains",
      "DomainLinkageCredential": "https://identity.foundation/.well-known/resources/did-configuration/#DomainLinkageCredential",
      "origin": "https://identity.foundation/.well-known/resources/did-configuration/#origin",
      "linked_dids": "https://identity.foundation/.well-known/resources/did-configuration/#linked_dids"
    }
  ]
}`

const vcJWS2020Context = `{
  "@context": {
    "privateKeyJwk": {
      "@id": "https://w3id.org/security#privateKeyJwk",
      "@type": "@json"
    },
    "JsonWebKey2020": {
      "@id": "https://w3id.org/security#JsonWebKey2020",
      "@context": {
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "publicKeyJwk": {
          "@id": "https://w3id.org/security#publicKeyJwk",
          "@type": "@json"
        }
      }
    },
    "JsonWebSignature2020": {
      "@id": "https://w3id.org/security#JsonWebSignature2020",
      "@context": {
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "challenge": "https://w3id.org/security#challenge",
        "created": {
          "@id": "http://purl.org/dc/terms/created",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "domain": "https://w3id.org/security#domain",
        "expires": {
          "@id": "https://w3id.org/security#expiration",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "jws": "https://w3id.org/security#jws",
        "nonce": "https://w3id.org/security#nonce",
        "proofPurpose": {
          "@id": "https://w3id.org/security#proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "assertionMethod": {
              "@id": "https://w3id.org/security#assertionMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "authentication": {
              "@id": "https://w3id.org/security#authenticationMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "capabilityInvocation": {
              "@id": "https://w3id.org/security#capabilityInvocationMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "capabilityDelegation": {
              "@id": "https://w3id.org/security#capabilityDelegationMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "keyAgreement": {
              "@id": "https://w3id.org/security#keyAgreementMethod",
              "@type": "@id",
              "@container": "@set"
            }
          }
        },
        "verificationMethod": {
          "@id": "https://w3id.org/security#verificationMethod",
          "@type": "@id"
        }
      }
    }
  }
}`

func TestDIDConfigurationAPI(t *testing.T) {
	t.Run("Create DID Configuration", func(t *testing.T) {
		for _, test := range testutil.TestDatabases {
			t.Run(test.Name, func(t *testing.T) {
				s := test.ServiceStorage(t)

				keyStoreService, keyStoreServiceFactory := testKeyStoreService(t, s)
				didService, _ := testDIDService(t, s, keyStoreService, keyStoreServiceFactory)
				schemaService := testSchemaService(t, s, keyStoreService, didService)

				didKey, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{Method: "key", KeyType: "Ed25519"})
				assert.NoError(t, err)
				assert.NotEmpty(t, didKey)
				dcRouter := setupDIDConfigurationRouter(t, keyStoreService, didService.GetResolver(), schemaService)

				request := router.CreateDIDConfigurationRequest{
					IssuerDID:            didKey.DID.ID,
					VerificationMethodID: didKey.DID.VerificationMethod[0].ID,
					Origin:               "https://www.tbd.website/",
					ExpirationDate:       "2051-10-05T14:48:00.000Z",
				}
				value := newRequestValue(t, request)
				req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/did-configurations", value)
				w := httptest.NewRecorder()
				c := newRequestContext(w, req)
				dcRouter.CreateDIDConfiguration(c)

				assert.True(t, util.Is2xxResponse(w.Code))
				var resp router.CreateDIDConfigurationResponse
				assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))

				_, _, vc, err := integrity.ParseVerifiableCredentialFromJWT(resp.DIDConfiguration.LinkedDIDs[0].(string))
				assert.NoError(t, err)
				assert.Equal(t, "DomainLinkageCredential", vc.Type.([]any)[1].(string))
				assert.Equal(t, "https://www.tbd.website/", vc.CredentialSubject["origin"])
				assert.Equal(t, didKey.DID.ID, vc.CredentialSubject["id"])
				assert.NotEmpty(t, vc.IssuanceDate)
				assert.NotEmpty(t, vc.ExpirationDate)
				assert.Empty(t, vc.ID)
				assert.Contains(t, resp.WellKnownLocation, "/.well-known/did-configuration.json")
			})
		}
	})

	t.Run("Verify DID Configuration", func(t *testing.T) {
		for _, test := range testutil.TestDatabases {
			t.Run(test.Name, func(t *testing.T) {
				s := test.ServiceStorage(t)

				keyStoreService, keyStoreServiceFactory := testKeyStoreService(t, s)
				didService, _ := testDIDService(t, s, keyStoreService, keyStoreServiceFactory)
				schemaService := testSchemaService(t, s, keyStoreService, didService)

				didKey, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{Method: "key", KeyType: "Ed25519"})
				assert.NoError(t, err)
				assert.NotEmpty(t, didKey)

				didConfigurationService := setupDIDConfigurationRouter(t, keyStoreService, didService.GetResolver(), schemaService)

				t.Run("passes for complex did configuration resource", func(t *testing.T) {
					defer gock.Off()
					client := didConfigurationService.Service.HTTPClient
					gock.InterceptClient(client)
					defer gock.RestoreClient(client)

					// mock all the contexts needed for json-ld canonicalization
					gock.New("https://www.w3.org").
						Get("/2018/credentials/v1").
						Reply(200).
						BodyString(w3cCredentialContext)
					gock.New("https://identity.foundation").Get("/.well-known/did-configuration/v1").Reply(200).BodyString(wellKnownDIDContext)
					gock.New("https://www.w3.org").
						Get("/2018/credentials/v1").
						Reply(200).
						BodyString(w3cCredentialContext)
					gock.New("https://identity.foundation").Get("/.well-known/did-configuration/v1").Reply(200).BodyString(wellKnownDIDContext)
					gock.New("https://w3id.org").Get("/security/suites/jws-2020/v1").Reply(200).BodyString(vcJWS2020Context)

					gock.New("https://identity.foundation").
						Get("/.well-known/did-configuration.json").
						Reply(200).
						BodyString(`{
  "@context": "https://identity.foundation/.well-known/did-configuration/v1",
  "linked_dids": [
    {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://identity.foundation/.well-known/did-configuration/v1"
      ],
      "issuer": "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM",
      "issuanceDate": "2020-12-04T14:08:28-06:00",
      "expirationDate": "2025-12-04T14:08:28-06:00",
      "type": ["VerifiableCredential", "DomainLinkageCredential"],
      "credentialSubject": {
        "id": "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM",
        "origin": "https://identity.foundation"
      },
      "proof": {
        "type": "Ed25519Signature2018",
        "created": "2020-12-04T20:08:28.540Z",
        "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..D0eDhglCMEjxDV9f_SNxsuU-r3ZB9GR4vaM9TYbyV7yzs1WfdUyYO8rFZdedHbwQafYy8YOpJ1iJlkSmB4JaDQ",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM#z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM"
      }
    },
    "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNI3o2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSJ9.eyJleHAiOjE3NjQ4NzkxMzksImlzcyI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNIiwibmJmIjoxNjA3MTEyNzM5LCJzdWIiOiJkaWQ6a2V5Ono2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly9pZGVudGl0eS5mb3VuZGF0aW9uLy53ZWxsLWtub3duL2RpZC1jb25maWd1cmF0aW9uL3YxIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmtleTp6Nk1rb1RIc2dOTnJieThKekNOUTFpUkx5VzVRUTZSOFh1dTZBQThpZ0dyTVZQVU0iLCJvcmlnaW4iOiJpZGVudGl0eS5mb3VuZGF0aW9uIn0sImV4cGlyYXRpb25EYXRlIjoiMjAyNS0xMi0wNFQxNDoxMjoxOS0wNjowMCIsImlzc3VhbmNlRGF0ZSI6IjIwMjAtMTItMDRUMTQ6MTI6MTktMDY6MDAiLCJpc3N1ZXIiOiJkaWQ6a2V5Ono2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJEb21haW5MaW5rYWdlQ3JlZGVudGlhbCJdfX0.aUFNReA4R5rcX_oYm3sPXqWtso_gjPHnWZsB6pWcGv6m3K8-4JIAvFov3ZTM8HxPOrOL17Qf4vBFdY9oK0HeCQ"
  ]
}`)

					request := wellknown.VerifyDIDConfigurationRequest{
						Origin: "https://identity.foundation",
					}
					value := newRequestValue(t, request)
					req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/did-configurations/verification", value)
					w := httptest.NewRecorder()
					c := newRequestContext(w, req)
					didConfigurationService.VerifyDIDConfiguration(c)

					var resp wellknown.VerifyDIDConfigurationResponse
					err := json.NewDecoder(w.Body).Decode(&resp)
					assert.NoError(t, err)

					assert.True(t, resp.Verified, resp.Reason)
					assert.NotEmpty(t, resp.DIDConfiguration)
					assert.Empty(t, resp.Reason)
				})

				t.Run("verification fails", func(t *testing.T) {
					defer gock.Off()

					gock.InterceptClient(didConfigurationService.Service.HTTPClient)
					gock.New("https://www.tbd.website").
						Get("/.well-known/did-configuration.json").
						Reply(200).
						BodyString(`{
    "@context":"https://identity.foundation/.well-known/did-configuration/v1",
    "linked_dids":[
       "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa2g0QTZRVE5DQUZpNE5aZm5XdDhxTlNHWERHbk5YaHhYV2V3Y3BCcnpTMTl2IiwidHlwIjoiSldUIn0.eyJleHAiOjI1ODAxMzAwODAsImlzcyI6ImRpZDprZXk6ejZNa2g0QTZRVE5DQUZpNE5aZm5XdDhxTlNHWERHbk5YaHhYV2V3Y3BCcnpTMTl2IiwibmJmIjoxNjc2NTcyMDkzLCJzdWIiOiJkaWQ6a2V5Ono2TWtoNEE2UVROQ0FGaTROWmZuV3Q4cU5TR1hER25OWGh4WFdld2NwQnJ6UzE5diIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly9pZGVudGl0eS5mb3VuZGF0aW9uLy53ZWxsLWtub3duL2RpZC1jb25maWd1cmF0aW9uL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJEb21haW5MaW5rYWdlQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOiJkaWQ6a2V5Ono2TWtoNEE2UVROQ0FGaTROWmZuV3Q4cU5TR1hER25OWGh4WFdld2NwQnJ6UzE5diIsImlzc3VhbmNlRGF0ZSI6IjIwMjMtMDItMTZUMTI6Mjg6MTMtMDY6MDAiLCJleHBpcmF0aW9uRGF0ZSI6IjIwNTEtMTAtMDVUMTQ6NDg6MDAuMDAwWiIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmtleTp6Nk1raDRBNlFUTkNBRmk0Tlpmbld0OHFOU0dYREduTlhoeFhXZXdjcEJyelMxOXYiLCJvcmlnaW4iOiJodHRwczovL3d3dy50YmQud2Vic2l0ZS8ifX19.szn9o_JhCLqYMH_SNtwFaJWViueg-pvrZW4G88cegh2Airh9ziQ7fYvSY4Hts2FlF6at8fMfAzrsnhJ-Fb0_Dw",
       "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWI6dGJkLndlYnNpdGUiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjI1ODAxMzAwODAsImlzcyI6ImRpZDp3ZWI6dGJkLndlYnNpdGUiLCJuYmYiOjE2NzY1NzIwOTUsInN1YiI6ImRpZDp3ZWI6dGJkLndlYnNpdGUiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vaWRlbnRpdHkuZm91bmRhdGlvbi8ud2VsbC1rbm93bi9kaWQtY29uZmlndXJhdGlvbi92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiRG9tYWluTGlua2FnZUNyZWRlbnRpYWwiXSwiaXNzdWVyIjoiZGlkOndlYjp0YmQud2Vic2l0ZSIsImlzc3VhbmNlRGF0ZSI6IjIwMjMtMDItMTZUMTI6Mjg6MTUtMDY6MDAiLCJleHBpcmF0aW9uRGF0ZSI6IjIwNTEtMTAtMDVUMTQ6NDg6MDAuMDAwWiIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOndlYjp0YmQud2Vic2l0ZSIsIm9yaWdpbiI6Imh0dHBzOi8vd3d3LnRiZC53ZWJzaXRlLyJ9fX0.bweamOE6q-K1jQ64cfqk-vhhuugSpLvcit3Q6REBM2z0CpvvTX4SttHF533oUIDovtOSqmAAOOUFCbrTJYQfDw"
    ]
 }`)

					request := wellknown.VerifyDIDConfigurationRequest{
						Origin: "https://www.tbd.website/",
					}
					value := newRequestValue(t, request)
					req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/did-configurations/verification", value)
					w := httptest.NewRecorder()
					c := newRequestContext(w, req)
					didConfigurationService.VerifyDIDConfiguration(c)

					var resp wellknown.VerifyDIDConfigurationResponse
					err := json.NewDecoder(w.Body).Decode(&resp)
					assert.NoError(t, err)

					assert.False(t, resp.Verified)
					assert.NotEmpty(t, resp.DIDConfiguration)
					assert.Contains(t, resp.Reason, "verifying JWT credential")
				})

				t.Run("returns error for non tls", func(t *testing.T) {
					request := wellknown.VerifyDIDConfigurationRequest{
						Origin: "http://www.tbd.website/",
					}
					value := newRequestValue(t, request)
					req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/did-configurations/verification", value)
					w := httptest.NewRecorder()
					c := newRequestContext(w, req)
					didConfigurationService.VerifyDIDConfiguration(c)

					assert.False(t, util.Is2xxResponse(w.Code))
					assert.Contains(t, w.Body.String(), "origin expected to be https")
				})
			})
		}
	})
}

func setupDIDConfigurationRouter(t *testing.T, keyStoreService *keystore.Service, didResolver resolution.Resolver, schemaService *schema.Service) *router.DIDConfigurationRouter {
	service, err := wellknown.NewDIDConfigurationService(keyStoreService, didResolver, schemaService)
	assert.NoError(t, err)

	dcRouter, err := router.NewDIDConfigurationsRouter(service)
	assert.NoError(t, err)
	return dcRouter
}
