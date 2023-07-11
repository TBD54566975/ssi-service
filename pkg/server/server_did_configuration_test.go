package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TBD54566975/ssi-sdk/credential/integrity"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	wellknown "github.com/tbd54566975/ssi-service/pkg/service/well-known"
	"github.com/tbd54566975/ssi-service/pkg/testutil"
)

func TestDIDConfigurationAPI(t *testing.T) {
	t.Run("Create DID Configuration", func(tt *testing.T) {
		for _, test := range testutil.TestDatabases {
			tt.Run(test.Name, func(ttt *testing.T) {
				s := test.ServiceStorage(ttt)

				keyStoreService, keyStoreServiceFactory := testKeyStoreService(ttt, s)
				didService, _ := testDIDService(ttt, s, keyStoreService, keyStoreServiceFactory)

				didKey, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{Method: "key", KeyType: "Ed25519"})
				assert.NoError(ttt, err)
				assert.NotEmpty(ttt, didKey)
				dcRouter := setupDIDConfigurationRouter(ttt, keyStoreService)

				request := router.CreateDIDConfigurationRequest{
					IssuerDID:            didKey.DID.ID,
					VerificationMethodID: didKey.DID.VerificationMethod[0].ID,
					Origin:               "https://www.tbd.website/",
					ExpirationDate:       "2051-10-05T14:48:00.000Z",
				}
				value := newRequestValue(ttt, request)
				req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/did-configurations", value)
				w := httptest.NewRecorder()
				c := newRequestContext(w, req)
				dcRouter.CreateDIDConfiguration(c)

				assert.True(ttt, util.Is2xxResponse(w.Code))
				var resp router.CreateDIDConfigurationResponse
				assert.NoError(ttt, json.NewDecoder(w.Body).Decode(&resp))

				_, _, vc, err := integrity.ParseVerifiableCredentialFromJWT(resp.DIDConfiguration.LinkedDIDs[0].(string))
				assert.NoError(ttt, err)
				assert.Equal(ttt, "DomainLinkageCredential", vc.Type.([]any)[1].(string))
				assert.Equal(ttt, "https://www.tbd.website/", vc.CredentialSubject["origin"])
				assert.Equal(ttt, didKey.DID.ID, vc.CredentialSubject["id"])
				assert.NotEmpty(ttt, vc.IssuanceDate)
				assert.NotEmpty(ttt, vc.ExpirationDate)
				assert.Empty(ttt, vc.ID)
				assert.Contains(ttt, resp.WellKnownLocation, "/.well-known/did-configuration.json")
			})
		}
	})
}

func setupDIDConfigurationRouter(t *testing.T, keyStoreService *keystore.Service) *router.DIDConfigurationRouter {
	service := wellknown.NewDIDConfigurationService(keyStoreService)

	dcRouter, err := router.NewDIDConfigurationsRouter(service)
	assert.NoError(t, err)
	return dcRouter
}
