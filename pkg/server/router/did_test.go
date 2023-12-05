package router

import (
	"context"
	"strings"
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/stretchr/testify/assert"
	"github.com/tbd54566975/ssi-service/pkg/service/common"
	"github.com/tbd54566975/ssi-service/pkg/testutil"
	"gopkg.in/h2non/gock.v1"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
)

func TestDIDRouter(t *testing.T) {
	t.Run("Nil Service", func(t *testing.T) {
		didRouter, err := NewDIDRouter(nil)
		assert.Error(t, err)
		assert.Empty(t, didRouter)
		assert.Contains(t, err.Error(), "service cannot be nil")
	})

	t.Run("Bad Service", func(t *testing.T) {
		didRouter, err := NewDIDRouter(&testService{})
		assert.Error(t, err)
		assert.Empty(t, didRouter)
		assert.Contains(t, err.Error(), "could not create DID router with service type: test")
	})

	for _, test := range testutil.TestDatabases {
		t.Run(test.Name, func(t *testing.T) {
			// TODO: Fix pagesize issue on redis - https://github.com/TBD54566975/ssi-service/issues/538
			if !strings.Contains(test.Name, "Redis") {
				t.Run("List DIDs supports paging", func(t *testing.T) {
					db := test.ServiceStorage(t)
					assert.NotEmpty(t, db)
					keyStoreService := testKeyStoreService(t, db)
					methods := []string{didsdk.KeyMethod.String()}
					serviceConfig := config.DIDServiceConfig{Methods: methods, LocalResolutionMethods: methods}
					didService, err := did.NewDIDService(serviceConfig, db, keyStoreService, nil)
					assert.NoError(t, err)
					assert.NotEmpty(t, didService)
					createDID(t, didService)
					createDID(t, didService)

					one := 1
					listDIDsResponse1, err := didService.ListDIDsByMethod(context.Background(),
						did.ListDIDsRequest{
							Method: didsdk.KeyMethod,
							PageRequest: &common.Page{
								Size: one,
							},
						})

					assert.NoError(t, err)
					assert.Len(t, listDIDsResponse1.DIDs, 1)
					assert.NotEmpty(t, listDIDsResponse1.NextPageToken)

					listDIDsResponse2, err := didService.ListDIDsByMethod(context.Background(),
						did.ListDIDsRequest{
							Method: didsdk.KeyMethod,
							PageRequest: &common.Page{
								Size:  one,
								Token: listDIDsResponse1.NextPageToken,
							},
						})

					assert.NoError(t, err)
					assert.Len(t, listDIDsResponse2.DIDs, 1)
					assert.Empty(t, listDIDsResponse2.NextPageToken)

				})
			}

			t.Run("DID Service Test", func(t *testing.T) {
				db := test.ServiceStorage(t)
				assert.NotEmpty(t, db)

				keyStoreService := testKeyStoreService(t, db)
				methods := []string{didsdk.KeyMethod.String()}
				serviceConfig := config.DIDServiceConfig{Methods: methods, LocalResolutionMethods: methods}
				didService, err := did.NewDIDService(serviceConfig, db, keyStoreService, nil)
				assert.NoError(t, err)
				assert.NotEmpty(t, didService)

				// check type and status
				assert.Equal(t, framework.DID, didService.Type())
				assert.Equal(t, framework.StatusReady, didService.Status().Status)

				// get unknown handler
				_, err = didService.GetDIDByMethod(context.Background(), did.GetDIDRequest{Method: "bad"})
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "could not get handler for method<bad>")

				supported := didService.GetSupportedMethods()
				assert.NotEmpty(t, supported)
				assert.Len(t, supported.Methods, 1)
				assert.Equal(t, didsdk.KeyMethod, supported.Methods[0])

				// bad key type
				_, err = didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{Method: didsdk.KeyMethod, KeyType: "bad"})
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "unsupported did:key type: bad")

				// good key type
				createDIDResponse, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{Method: didsdk.KeyMethod, KeyType: crypto.Ed25519})
				assert.NoError(t, err)
				assert.NotEmpty(t, createDIDResponse)

				// check the DID is a did:key
				assert.Contains(t, createDIDResponse.DID.ID, "did:key")

				// get it back
				getDIDResponse, err := didService.GetDIDByMethod(context.Background(), did.GetDIDRequest{Method: didsdk.KeyMethod, ID: createDIDResponse.DID.ID})
				assert.NoError(t, err)
				assert.NotEmpty(t, getDIDResponse)

				// make sure it's the same value
				assert.Equal(t, createDIDResponse.DID.ID, getDIDResponse.DID.ID)

				// create a second DID
				createDIDResponse2, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{Method: didsdk.KeyMethod, KeyType: crypto.Ed25519})
				assert.NoError(t, err)
				assert.NotEmpty(t, createDIDResponse2)

				// get all DIDs back
				getDIDsResponse, err := didService.ListDIDsByMethod(context.Background(), did.ListDIDsRequest{Method: didsdk.KeyMethod})
				assert.NoError(t, err)
				assert.NotEmpty(t, getDIDsResponse)
				assert.Len(t, getDIDsResponse.DIDs, 2)

				knownDIDs := map[string]bool{createDIDResponse.DID.ID: true, createDIDResponse2.DID.ID: true}
				for _, gotDID := range getDIDsResponse.DIDs {
					if _, ok := knownDIDs[gotDID.ID]; !ok {
						t.Error("got unknown DID")
					} else {
						delete(knownDIDs, gotDID.ID)
					}
				}
				assert.Len(t, knownDIDs, 0)

				// delete dids
				err = didService.SoftDeleteDIDByMethod(context.Background(), did.DeleteDIDRequest{Method: didsdk.KeyMethod, ID: createDIDResponse.DID.ID})
				assert.NoError(t, err)

				err = didService.SoftDeleteDIDByMethod(context.Background(), did.DeleteDIDRequest{Method: didsdk.KeyMethod, ID: createDIDResponse2.DID.ID})
				assert.NoError(t, err)

				// get all DIDs back
				getDIDsResponse, err = didService.ListDIDsByMethod(context.Background(), did.ListDIDsRequest{Method: didsdk.KeyMethod})
				assert.NoError(t, err)
				assert.NotEmpty(t, getDIDsResponse)
				assert.Len(t, getDIDsResponse.DIDs, 0)

				// get deleted DIDs back
				getDIDsResponse, err = didService.ListDIDsByMethod(context.Background(), did.ListDIDsRequest{Method: didsdk.KeyMethod, Deleted: true})
				assert.NoError(t, err)
				assert.NotEmpty(t, getDIDsResponse)
				assert.Len(t, getDIDsResponse.DIDs, 2)
			})

			t.Run("DID Web Service Test", func(t *testing.T) {
				db := test.ServiceStorage(t)
				assert.NotEmpty(t, db)

				keyStoreService := testKeyStoreService(t, db)
				methods := []string{didsdk.KeyMethod.String(), didsdk.WebMethod.String()}
				serviceConfig := config.DIDServiceConfig{Methods: methods, LocalResolutionMethods: methods}
				didService, err := did.NewDIDService(serviceConfig, db, keyStoreService, nil)
				assert.NoError(t, err)
				assert.NotEmpty(t, didService)

				// check type and status
				assert.Equal(t, framework.DID, didService.Type())
				assert.Equal(t, framework.StatusReady, didService.Status().Status)

				// get unknown handler
				_, err = didService.GetDIDByMethod(context.Background(), did.GetDIDRequest{Method: "bad"})
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "could not get handler for method<bad>")

				supported := didService.GetSupportedMethods()
				assert.NotEmpty(t, supported)
				assert.Len(t, supported.Methods, 2)

				assert.ElementsMatch(t, supported.Methods, []didsdk.Method{didsdk.KeyMethod, didsdk.WebMethod})

				gock.Off()
				gock.New("https://example.com").
					Get("/.well-known/did.json").
					Reply(200).
					BodyString("")
				// bad key type
				createOpts := did.CreateWebDIDOptions{DIDWebID: "did:web:example.com"}
				_, err = didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{Method: didsdk.WebMethod, KeyType: "bad", Options: createOpts})
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "key type <bad> not supported")

				gock.Off()
				gock.New("https://example.com").
					Get("/.well-known/did.json").
					Reply(404)
				// good key type
				createDIDResponse, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{Method: didsdk.WebMethod, KeyType: crypto.Ed25519, Options: createOpts})
				assert.NoError(t, err)
				assert.NotEmpty(t, createDIDResponse)

				// check the DID is a did:key
				assert.Contains(t, createDIDResponse.DID.ID, "did:web")

				// get it back
				getDIDResponse, err := didService.GetDIDByMethod(context.Background(), did.GetDIDRequest{Method: didsdk.WebMethod, ID: createDIDResponse.DID.ID})
				assert.NoError(t, err)
				assert.NotEmpty(t, getDIDResponse)

				// make sure it's the same value
				assert.Equal(t, createDIDResponse.DID.ID, getDIDResponse.DID.ID)

				gock.Off()
				gock.New("https://tbd.website").
					Get("/.well-known/did.json").
					Reply(404)
				// create a second DID
				createOpts = did.CreateWebDIDOptions{DIDWebID: "did:web:tbd.website"}
				createDIDResponse2, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{Method: didsdk.WebMethod, KeyType: crypto.Ed25519, Options: createOpts})
				assert.NoError(t, err)
				assert.NotEmpty(t, createDIDResponse2)

				// get all DIDs back
				getDIDsResponse, err := didService.ListDIDsByMethod(context.Background(), did.ListDIDsRequest{Method: didsdk.WebMethod})
				assert.NoError(t, err)
				assert.NotEmpty(t, getDIDsResponse)
				assert.Len(t, getDIDsResponse.DIDs, 2)

				knownDIDs := map[string]bool{createDIDResponse.DID.ID: true, createDIDResponse2.DID.ID: true}
				for _, gotDID := range getDIDsResponse.DIDs {
					if _, ok := knownDIDs[gotDID.ID]; !ok {
						t.Error("got unknown DID")
					} else {
						delete(knownDIDs, gotDID.ID)
					}
				}
				assert.Len(t, knownDIDs, 0)

				// delete dids
				err = didService.SoftDeleteDIDByMethod(context.Background(), did.DeleteDIDRequest{Method: didsdk.WebMethod, ID: createDIDResponse.DID.ID})
				assert.NoError(t, err)

				err = didService.SoftDeleteDIDByMethod(context.Background(), did.DeleteDIDRequest{Method: didsdk.WebMethod, ID: createDIDResponse2.DID.ID})
				assert.NoError(t, err)

				// get all DIDs back
				getDIDsResponse, err = didService.ListDIDsByMethod(context.Background(), did.ListDIDsRequest{Method: didsdk.WebMethod})
				assert.NoError(t, err)
				assert.NotEmpty(t, getDIDsResponse)
				assert.Len(t, getDIDsResponse.DIDs, 0)
			})
		})
	}
}

func createDID(t *testing.T, didService *did.Service) {
	createDIDResponse, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{Method: didsdk.KeyMethod, KeyType: crypto.Ed25519})
	assert.NoError(t, err)
	assert.NotEmpty(t, createDIDResponse)
}
