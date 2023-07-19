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

				t.Run("passes for TBD", func(t *testing.T) {
					defer gock.Off()

					gock.InterceptClient(didConfigurationService.Service.HTTPClient)
					gock.New("https://www.tbd.website").
						Get("/.well-known/did-configuration.json").
						Reply(200).
						BodyString(`{
    "@context": "https://identity.foundation/.well-known/did-configuration/v1",
    "linked_dids": [
      "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa2hDcWNza2haU0V4NEZHbU5XNXNNcVVoZzJyZnc2YnMyWkNCZXBzTkZjQ3Y1I3o2TWtoQ3Fjc2toWlNFeDRGR21OVzVzTXFVaGcycmZ3NmJzMlpDQmVwc05GY0N2NSIsInR5cCI6IkpXVCJ9.eyJleHAiOjI1ODAxMzAwODAsImlhdCI6MTYzMzQ0NTI4MCwiaXNzIjoiZGlkOmtleTp6Nk1raENxY3NraFpTRXg0RkdtTlc1c01xVWhnMnJmdzZiczJaQ0JlcHNORmNDdjUiLCJuYmYiOjE2MzM0NDUyODAsIm5vbmNlIjoiOTU5MTczMDktYWJmMC00OWI0LTkzYTktMjQyYTg4NmFhYTBmIiwic3ViIjoiZGlkOmtleTp6Nk1raENxY3NraFpTRXg0RkdtTlc1c01xVWhnMnJmdzZiczJaQ0JlcHNORmNDdjUiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vaWRlbnRpdHkuZm91bmRhdGlvbi8ud2VsbC1rbm93bi9kaWQtY29uZmlndXJhdGlvbi92MSJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJvcmlnaW4iOiJodHRwczovL3d3dy50YmQud2Vic2l0ZSJ9LCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiRG9tYWluTGlua2FnZUNyZWRlbnRpYWwiXX19.OV56DeG2bp4Hd-kulCUgZCk4PgY51sEzw4REZeUfiS4Cqa9LnbK0fkiJ2jPAZoBzTSDq75Hxc2qX5Ey0JVCoBw"
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
