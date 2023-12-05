package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	credsdk "github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/manifest"
	"github.com/TBD54566975/ssi-sdk/credential/parsing"
	"github.com/TBD54566975/ssi-sdk/crypto"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/key"
	"github.com/benbjohnson/clock"
	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	credmodel "github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/service/credential"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/issuance"
	manifestsvc "github.com/tbd54566975/ssi-service/pkg/service/manifest/model"
	"github.com/tbd54566975/ssi-service/pkg/service/operation/storage"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
	"github.com/tbd54566975/ssi-service/pkg/testutil"
)

func TestManifestAPI(t *testing.T) {
	for _, test := range testutil.TestDatabases {
		t.Run(test.Name, func(t *testing.T) {
			t.Run("Test Create Manifest", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				keyStoreService, _ := testKeyStoreService(t, db)
				didService, _ := testDIDService(t, db, keyStoreService, nil)
				schemaService := testSchemaService(t, db, keyStoreService, didService)
				credentialService := testCredentialService(t, db, keyStoreService, didService, schemaService)
				manifestRouter, manifestService := testManifest(t, db, keyStoreService, didService, credentialService)

				// missing required field: Manifest
				var badManifestRequest router.CreateManifestRequest
				badRequestValue := newRequestValue(t, badManifestRequest)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", badRequestValue)
				w := httptest.NewRecorder()

				c := newRequestContext(w, req)
				manifestRouter.CreateManifest(c)
				assert.Contains(t, w.Body.String(), "invalid create manifest request")

				// reset the http recorder
				w = httptest.NewRecorder()

				// create an issuer
				issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
					Method:  didsdk.KeyMethod,
					KeyType: crypto.Ed25519,
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, issuerDID)

				// create a schema for the creds to be issued against
				kid := issuerDID.DID.VerificationMethod[0].ID
				createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Issuer: issuerDID.DID.ID, FullyQualifiedVerificationMethodID: kid, Name: "license schema", Schema: getLicenseApplicationSchema()})
				assert.NoError(t, err)
				assert.NotEmpty(t, createdSchema)

				// good request
				createManifestRequest := getValidCreateManifestRequest(issuerDID.DID.ID, issuerDID.DID.VerificationMethod[0].ID, createdSchema.ID)

				requestValue := newRequestValue(t, createManifestRequest)
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
				c = newRequestContext(w, req)
				manifestRouter.CreateManifest(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var resp router.CreateManifestResponse
				err = json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(t, err)
				assert.NotEmpty(t, resp.Manifest)
				assert.Equal(t, resp.Manifest.Issuer.ID, issuerDID.DID.ID)

				// create a credential manifest request
				manifestRequestRequest := getValidManifestRequestRequest(issuerDID, kid, resp.Manifest)
				requestValue = newRequestValue(t, manifestRequestRequest)
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests/requests", requestValue)
				c = newRequestContext(w, req)
				manifestRouter.CreateRequest(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var reqResp router.CreateManifestRequestResponse
				err = json.NewDecoder(w.Body).Decode(&reqResp)
				assert.NoError(t, err)
				assert.NotEmpty(t, reqResp.Request)
				assert.Equal(t, "my_callback_url", reqResp.Request.CallbackURL)

				// verify the manifest
				verificationResponse, err := manifestService.VerifyManifest(context.Background(), manifestsvc.VerifyManifestRequest{ManifestJWT: reqResp.Request.CredentialManifestJWT})
				assert.NoError(t, err)
				assert.NotEmpty(t, verificationResponse)
				assert.True(t, verificationResponse.Verified)
			})

			t.Run("Test Get Manifest By ID", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				keyStoreService, _ := testKeyStoreService(t, db)
				didService, _ := testDIDService(t, db, keyStoreService, nil)
				schemaService := testSchemaService(t, db, keyStoreService, didService)
				credentialService := testCredentialService(t, db, keyStoreService, didService, schemaService)
				manifestRouter, _ := testManifest(t, db, keyStoreService, didService, credentialService)

				w := httptest.NewRecorder()

				// get a manifest that doesn't exit
				req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/manifests/bad", nil)
				c := newRequestContext(w, req)
				manifestRouter.GetManifest(c)
				assert.Contains(t, w.Body.String(), "cannot get manifest without ID parameter")

				// reset recorder between calls
				w = httptest.NewRecorder()

				// get a manifest with an invalid id parameter
				req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/manifests/bad", nil)
				c = newRequestContextWithParams(w, req, map[string]string{"id": "bad"})
				manifestRouter.GetManifest(c)
				assert.Contains(t, w.Body.String(), "could not get manifest with id: bad")

				// reset recorder between calls
				w = httptest.NewRecorder()

				// create an issuer
				issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
					Method:  didsdk.KeyMethod,
					KeyType: crypto.Ed25519,
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, issuerDID)

				// create a schema for the creds to be issued against
				kid := issuerDID.DID.VerificationMethod[0].ID
				createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Issuer: issuerDID.DID.ID, FullyQualifiedVerificationMethodID: kid, Name: "license schema", Schema: getLicenseApplicationSchema()})
				assert.NoError(t, err)
				assert.NotEmpty(t, createdSchema)

				// good request
				createManifestRequest := getValidCreateManifestRequest(issuerDID.DID.ID, issuerDID.DID.VerificationMethod[0].ID, createdSchema.ID)

				requestValue := newRequestValue(t, createManifestRequest)
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
				c = newRequestContext(w, req)
				manifestRouter.CreateManifest(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var resp router.CreateManifestResponse
				err = json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(t, err)

				// get manifest by id
				req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/manifests/%s", resp.Manifest.ID), nil)
				c = newRequestContextWithParams(w, req, map[string]string{"id": resp.Manifest.ID})
				manifestRouter.GetManifest(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var getManifestResp router.ListManifestResponse
				err = json.NewDecoder(w.Body).Decode(&getManifestResp)
				assert.NoError(t, err)
				assert.NotEmpty(t, getManifestResp)
				assert.Equal(t, resp.Manifest.ID, getManifestResp.ID)
			})

			t.Run("Test Get Manifests", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				keyStoreService, _ := testKeyStoreService(t, db)
				didService, _ := testDIDService(t, db, keyStoreService, nil)
				schemaService := testSchemaService(t, db, keyStoreService, didService)
				credentialService := testCredentialService(t, db, keyStoreService, didService, schemaService)
				manifestRouter, manifestService := testManifest(t, db, keyStoreService, didService, credentialService)

				w := httptest.NewRecorder()

				// create an issuer
				issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
					Method:  didsdk.KeyMethod,
					KeyType: crypto.Ed25519,
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, issuerDID)

				// create a schema for the creds to be issued against
				kid := issuerDID.DID.VerificationMethod[0].ID
				createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Issuer: issuerDID.DID.ID, FullyQualifiedVerificationMethodID: kid, Name: "license schema", Schema: getLicenseApplicationSchema()})
				assert.NoError(t, err)
				assert.NotEmpty(t, createdSchema)

				// good request
				createManifestRequest := getValidCreateManifestRequest(issuerDID.DID.ID, issuerDID.DID.VerificationMethod[0].ID, createdSchema.ID)

				requestValue := newRequestValue(t, createManifestRequest)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
				c := newRequestContext(w, req)
				manifestRouter.CreateManifest(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var resp router.CreateManifestResponse
				err = json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(t, err)

				// list all manifests
				req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/manifests", nil)
				c = newRequestContext(w, req)
				manifestRouter.ListManifests(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var getManifestsResp router.ListManifestsResponse
				err = json.NewDecoder(w.Body).Decode(&getManifestsResp)
				assert.NoError(t, err)
				assert.NotEmpty(t, getManifestsResp)
				assert.Len(t, getManifestsResp.Manifests, 1)
				assert.Equal(t, resp.Manifest.ID, getManifestsResp.Manifests[0].ID)

				// create a credential manifest request
				manifestRequestRequest := getValidManifestRequestRequest(issuerDID, kid, resp.Manifest)
				requestValue = newRequestValue(t, manifestRequestRequest)
				w = httptest.NewRecorder()
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests/requests", requestValue)
				c = newRequestContext(w, req)
				manifestRouter.CreateRequest(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var reqResp router.CreateManifestRequestResponse
				err = json.NewDecoder(w.Body).Decode(&reqResp)
				assert.NoError(t, err)
				assert.NotEmpty(t, reqResp.Request)

				// list the manifest requests
				req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/manifests/requests", nil)
				c = newRequestContext(w, req)
				manifestRouter.ListRequests(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var getManifestReqsResp router.ListManifestRequestsResponse
				err = json.NewDecoder(w.Body).Decode(&getManifestReqsResp)
				assert.NoError(t, err)
				assert.NotEmpty(t, getManifestReqsResp)
				assert.Len(t, getManifestReqsResp.Requests, 1)
				assert.Equal(t, reqResp.Request.ID, getManifestReqsResp.Requests[0].ID)

				// verify each manifest request
				for _, m := range getManifestReqsResp.Requests {
					verificationResponse, err := manifestService.VerifyManifest(context.Background(), manifestsvc.VerifyManifestRequest{ManifestJWT: m.CredentialManifestJWT})
					assert.NoError(t, err)
					assert.NotEmpty(t, verificationResponse)
					assert.True(t, verificationResponse.Verified)
				}
			})

			t.Run("Test Delete Manifest", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				keyStoreService, _ := testKeyStoreService(t, db)
				didService, _ := testDIDService(t, db, keyStoreService, nil)
				schemaService := testSchemaService(t, db, keyStoreService, didService)
				credentialService := testCredentialService(t, db, keyStoreService, didService, schemaService)
				manifestRouter, _ := testManifest(t, db, keyStoreService, didService, credentialService)

				// create an issuer
				issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
					Method:  didsdk.KeyMethod,
					KeyType: crypto.Ed25519,
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, issuerDID)

				// create a schema for the creds to be issued against
				kid := issuerDID.DID.VerificationMethod[0].ID
				createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Issuer: issuerDID.DID.ID, FullyQualifiedVerificationMethodID: kid, Name: "license schema", Schema: getLicenseApplicationSchema()})
				assert.NoError(t, err)
				assert.NotEmpty(t, createdSchema)

				// good request
				createManifestRequest := getValidCreateManifestRequest(issuerDID.DID.ID, issuerDID.DID.VerificationMethod[0].ID, createdSchema.ID)

				requestValue := newRequestValue(t, createManifestRequest)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
				w := httptest.NewRecorder()
				c := newRequestContext(w, req)
				manifestRouter.CreateManifest(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var resp router.CreateManifestResponse
				err = json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(t, err)

				w = httptest.NewRecorder()

				// get credential by id
				req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/manifests/%s", resp.Manifest.ID), nil)
				c = newRequestContextWithParams(w, req, map[string]string{"id": resp.Manifest.ID})
				manifestRouter.GetManifest(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var getManifestResp router.GetCredentialResponse
				err = json.NewDecoder(w.Body).Decode(&getManifestResp)
				assert.NoError(t, err)
				assert.NotEmpty(t, getManifestResp)
				assert.Equal(t, resp.Manifest.ID, getManifestResp.ID)

				w = httptest.NewRecorder()

				// delete it
				req = httptest.NewRequest(http.MethodDelete, fmt.Sprintf("https://ssi-service.com/v1/manifests/%s", resp.Manifest.ID), nil)
				c = newRequestContextWithParams(w, req, map[string]string{"id": resp.Manifest.ID})
				manifestRouter.DeleteManifest(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				w = httptest.NewRecorder()

				// get it back
				req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/manifests/%s", resp.Manifest.ID), nil)
				c = newRequestContextWithParams(w, req, map[string]string{"id": resp.Manifest.ID})
				manifestRouter.GetManifest(c)
				assert.Contains(t, w.Body.String(), fmt.Sprintf("could not get manifest with id: %s", resp.Manifest.ID))
			})

			t.Run("Submit Application With Issuance Template", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				keyStoreService, _ := testKeyStoreService(t, db)
				issuanceService := testIssuanceService(t, db)
				didService, _ := testDIDService(t, db, keyStoreService, nil)
				schemaService := testSchemaService(t, db, keyStoreService, didService)
				credentialService := testCredentialService(t, db, keyStoreService, didService, schemaService)
				manifestRouter, manifestSvc := testManifest(t, db, keyStoreService, didService, credentialService)

				// create an issuer
				issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
					Method:  didsdk.KeyMethod,
					KeyType: crypto.Ed25519,
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, issuerDID)

				// create an applicant
				applicantPrivKey, applicantDIDKey, err := key.GenerateDIDKey(crypto.Ed25519)
				assert.NoError(t, err)
				assert.NotEmpty(t, applicantPrivKey)
				assert.NotEmpty(t, applicantDIDKey)

				applicantDID, err := applicantDIDKey.Expand()
				assert.NoError(t, err)
				assert.NotEmpty(t, applicantDID)

				// create a schema for the creds to be issued against, needed for the application
				kid := issuerDID.DID.VerificationMethod[0].ID
				licenseApplicationSchema, err := schemaService.CreateSchema(
					context.Background(),
					schema.CreateSchemaRequest{Issuer: issuerDID.DID.ID, FullyQualifiedVerificationMethodID: kid, Name: "license application schema", Schema: getLicenseApplicationSchema()})
				assert.NoError(t, err)
				assert.NotEmpty(t, licenseApplicationSchema)

				// create a second schema for the creds to be issued after the application is approved
				licenseSchema, err := schemaService.CreateSchema(
					context.Background(),
					schema.CreateSchemaRequest{Issuer: issuerDID.DID.ID, FullyQualifiedVerificationMethodID: kid, Name: "license schema", Schema: getLicenseSchema()})
				assert.NoError(t, err)
				assert.NotEmpty(t, licenseSchema)

				// issue a credential against the schema to the subject, from the issuer
				createdCred, err := credentialService.CreateCredential(
					context.Background(),
					credential.CreateCredentialRequest{
						Issuer:                             issuerDID.DID.ID,
						FullyQualifiedVerificationMethodID: kid,
						Subject:                            applicantDID.ID,
						SchemaID:                           licenseApplicationSchema.ID,
						Data: map[string]any{
							"licenseType": "Class D",
							"firstName":   "Tester",
							"lastName":    "McTest",
						},
					})
				assert.NoError(t, err)
				assert.NotEmpty(t, createdCred)

				// create a manifest with the schema we'll be issuing against after reviewing applications
				createManifestRequest := getValidCreateManifestRequest(issuerDID.DID.ID, issuerDID.DID.VerificationMethod[0].ID, licenseSchema.ID)
				requestValue := newRequestValue(t, createManifestRequest)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
				w := httptest.NewRecorder()
				c := newRequestContext(w, req)
				manifestRouter.CreateManifest(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var resp router.CreateManifestResponse
				err = json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(t, err)

				m := resp.Manifest
				assert.NotEmpty(t, m)
				assert.Equal(t, m.Issuer.ID, issuerDID.DID.ID)

				// good application request
				container := []credmodel.Container{{CredentialJWT: createdCred.CredentialJWT}}
				applicationRequest := getValidApplicationRequest(m.ID, m.PresentationDefinition.ID, m.PresentationDefinition.InputDescriptors[0].ID, container)

				// sign application
				signer, err := keyaccess.NewJWKKeyAccess(applicantDID.ID, applicantDID.VerificationMethod[0].ID, applicantPrivKey)
				assert.NoError(t, err)
				signed, err := signer.SignJSON(applicationRequest)
				assert.NoError(t, err)

				expiryDateTime := time.Date(2022, 10, 31, 0, 0, 0, 0, time.UTC)
				mockClock := clock.NewMock()
				manifestSvc.Clock = mockClock
				mockClock.Set(expiryDateTime)
				expiryDuration := 5 * time.Second
				issuanceTemplate, err := issuanceService.CreateIssuanceTemplate(context.Background(),
					getValidIssuanceTemplateRequest(m, issuerDID, licenseSchema.ID, expiryDateTime, expiryDuration))
				assert.NoError(t, err)
				assert.NotEmpty(t, issuanceTemplate)

				applicationRequestValue := newRequestValue(t, router.SubmitApplicationRequest{ApplicationJWT: *signed})
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests/applications", applicationRequestValue)
				c = newRequestContext(w, req)
				manifestRouter.SubmitApplication(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var op router.Operation
				err = json.NewDecoder(w.Body).Decode(&op)
				assert.NoError(t, err)
				assert.True(t, op.Done)

				var appResp router.SubmitApplicationResponse
				respData, err := json.Marshal(op.Result.Response)
				assert.NoError(t, err)
				err = json.Unmarshal(respData, &appResp)
				assert.NoError(t, err)
				assert.Len(t, appResp.Credentials, 2, "each output_descriptor in the definition should result in a credential")

				_, _, vc, err := parsing.ToCredential(appResp.Credentials[0])
				assert.NoError(t, err)
				expectedSubject := credsdk.CredentialSubject{
					"id":        applicantDID.ID,
					"state":     "CA",
					"firstName": "Tester",
					"lastName":  "McTest",
				}
				assert.Equal(t, expectedSubject, vc.CredentialSubject)
				assert.Equal(t, time.Date(2022, 10, 31, 0, 0, 0, 0, time.UTC).Format(time.RFC3339), vc.ExpirationDate)
				assert.Equal(t, licenseSchema.ID, vc.CredentialSchema.ID)
				assert.Empty(t, vc.CredentialStatus)

				_, _, vc2, err := parsing.ToCredential(appResp.Credentials[1])
				assert.NoError(t, err)
				expectedSubject = credsdk.CredentialSubject{
					"id":        applicantDID.ID,
					"firstName": "Tester",
					"lastName":  "McTest",
					"state":     "NY",
					"someCrazyObject": map[string]any{
						"foo": 123.,
						"bar": false,
						"baz": []any{
							"yay", 123., nil,
						},
					},
				}
				assert.Equal(t, expectedSubject, vc2.CredentialSubject)
				assert.Equal(t,
					time.Date(2022, 10, 31, 0, 0, 5, 0, time.UTC).Format(time.RFC3339),
					vc2.ExpirationDate,
				)
				assert.Equal(t, licenseSchema.ID, vc2.CredentialSchema.ID)
				assert.NotEmpty(t, vc2.CredentialStatus)
			})

			t.Run("Test Submit Application with multiple outputs and overrides", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				keyStoreService, _ := testKeyStoreService(t, db)
				didService, _ := testDIDService(t, db, keyStoreService, nil)
				schemaService := testSchemaService(t, db, keyStoreService, didService)
				credentialService := testCredentialService(t, db, keyStoreService, didService, schemaService)
				manifestRouter, _ := testManifest(t, db, keyStoreService, didService, credentialService)

				// missing required field: Application
				badManifestRequest := router.SubmitApplicationRequest{ApplicationJWT: "bad"}
				badRequestValue := newRequestValue(t, badManifestRequest)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests/applications", badRequestValue)
				w := httptest.NewRecorder()

				c := newRequestContext(w, req)
				manifestRouter.SubmitApplication(c)
				assert.Contains(t, w.Body.String(), "invalid submit application request")

				// create an issuer
				issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
					Method:  didsdk.KeyMethod,
					KeyType: crypto.Ed25519,
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, issuerDID)

				// create an applicant
				applicantPrivKey, applicantDIDKey, err := key.GenerateDIDKey(crypto.Ed25519)
				assert.NoError(t, err)
				assert.NotEmpty(t, applicantPrivKey)
				assert.NotEmpty(t, applicantDIDKey)

				applicantDID, err := applicantDIDKey.Expand()
				assert.NoError(t, err)
				assert.NotEmpty(t, applicantDID)

				// create a schema for the creds to be issued against, needed for the application
				kid := issuerDID.DID.VerificationMethod[0].ID
				licenseApplicationSchema, err := schemaService.CreateSchema(
					context.Background(),
					schema.CreateSchemaRequest{Issuer: issuerDID.DID.ID, FullyQualifiedVerificationMethodID: kid, Name: "license application schema", Schema: getLicenseApplicationSchema()})
				assert.NoError(t, err)
				assert.NotEmpty(t, licenseApplicationSchema)

				// create a second schema for the creds to be issued after the application is approved
				licenseSchema, err := schemaService.CreateSchema(
					context.Background(),
					schema.CreateSchemaRequest{Issuer: issuerDID.DID.ID, FullyQualifiedVerificationMethodID: kid, Name: "license schema", Schema: getLicenseSchema()})
				assert.NoError(t, err)
				assert.NotEmpty(t, licenseSchema)

				// issue a credential against the schema to the subject, from the issuer
				createdCred, err := credentialService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:                             issuerDID.DID.ID,
					FullyQualifiedVerificationMethodID: kid,
					Subject:                            applicantDID.ID,
					SchemaID:                           licenseApplicationSchema.ID,
					Data:                               map[string]any{"licenseType": "Class D"},
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, createdCred)

				// good request to create a manifest
				createManifestRequest := getValidCreateManifestRequest(issuerDID.DID.ID, issuerDID.DID.VerificationMethod[0].ID, licenseSchema.ID)
				w = httptest.NewRecorder()
				requestValue := newRequestValue(t, createManifestRequest)
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
				c = newRequestContext(w, req)
				manifestRouter.CreateManifest(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var resp router.CreateManifestResponse
				err = json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(t, err)

				m := resp.Manifest
				assert.NotEmpty(t, m)
				assert.Equal(t, m.Issuer.ID, issuerDID.DID.ID)

				// good application request
				container := []credmodel.Container{{CredentialJWT: createdCred.CredentialJWT}}
				applicationRequest := getValidApplicationRequest(m.ID, m.PresentationDefinition.ID, m.PresentationDefinition.InputDescriptors[0].ID, container)

				// sign application
				signer, err := keyaccess.NewJWKKeyAccess(applicantDID.ID, applicantDID.VerificationMethod[0].ID, applicantPrivKey)
				assert.NoError(t, err)
				signed, err := signer.SignJSON(applicationRequest)
				assert.NoError(t, err)

				w = httptest.NewRecorder()

				applicationRequestValue := newRequestValue(t, router.SubmitApplicationRequest{ApplicationJWT: *signed})
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests/applications", applicationRequestValue)
				c = newRequestContext(w, req)
				manifestRouter.SubmitApplication(c)
				assert.NoError(t, err)

				var op router.Operation
				err = json.NewDecoder(w.Body).Decode(&op)
				assert.NoError(t, err)

				assert.False(t, op.Done)
				assert.Contains(t, op.ID, "credentials/responses/")

				// review application
				expireAt := time.Date(2025, 10, 32, 0, 0, 0, 0, time.UTC)
				reviewApplicationRequestValue := newRequestValue(t, router.ReviewApplicationRequest{
					Approved: true,
					Reason:   "I'm the almighty approver",
					CredentialOverrides: map[string]manifestsvc.CredentialOverride{
						"drivers-license-ca": {
							Data: map[string]any{
								"firstName": "John",
								"lastName":  "Doe",
								"state":     "CA",
								"looks":     "pretty darn handsome",
							},
							Expiry:    &expireAt,
							Revocable: true,
						},
						"drivers-license-ny": {
							Data: map[string]any{
								"firstName": "John",
								"lastName":  "Doe",
								"state":     "NY",
								"looks":     "even handsomer",
							},
							Expiry:    &expireAt,
							Revocable: true,
						},
					},
				})
				applicationID := storage.StatusObjectID(op.ID)
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests/applications/"+applicationID+"/review", reviewApplicationRequestValue)
				c = newRequestContextWithParams(w, req, map[string]string{"id": applicationID})
				manifestRouter.ReviewApplication(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var appResp router.SubmitApplicationResponse
				err = json.NewDecoder(w.Body).Decode(&appResp)
				assert.NoError(t, err)

				assert.NotEmpty(t, appResp.Response)
				assert.Equal(t, resp.Manifest.ID, appResp.Response.ManifestID)
				assert.NotEmpty(t, appResp.Response.Fulfillment)
				assert.Len(t, appResp.Response.Fulfillment.DescriptorMap, 2)
				assert.Len(t, appResp.Credentials, 2)
				assert.Empty(t, appResp.Response.Denial)

				_, _, vc, err := parsing.ToCredential(appResp.Credentials[0])
				assert.NoError(t, err)
				assert.Equal(t, credsdk.CredentialSubject{
					"id":        applicantDID.ID,
					"firstName": "John",
					"lastName":  "Doe",
					"state":     "CA",
					"looks":     "pretty darn handsome",
				}, vc.CredentialSubject)
				assert.Equal(t, expireAt.Format(time.RFC3339), vc.ExpirationDate)
				assert.NotEmpty(t, vc.CredentialStatus)
				assert.Equal(t, licenseSchema.ID, vc.CredentialSchema.ID)
			})

			t.Run("Test Denied Application", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				keyStoreService, _ := testKeyStoreService(t, db)
				didService, _ := testDIDService(t, db, keyStoreService, nil)
				schemaService := testSchemaService(t, db, keyStoreService, didService)
				credentialService := testCredentialService(t, db, keyStoreService, didService, schemaService)
				manifestRouter, _ := testManifest(t, db, keyStoreService, didService, credentialService)

				// missing required field: Application
				badManifestRequest := router.SubmitApplicationRequest{
					ApplicationJWT: "bad",
				}

				badRequestValue := newRequestValue(t, badManifestRequest)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests/applications", badRequestValue)
				w := httptest.NewRecorder()

				c := newRequestContext(w, req)
				manifestRouter.SubmitApplication(c)
				assert.Contains(t, w.Body.String(), "invalid submit application request")

				// create an issuer
				issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
					Method:  didsdk.KeyMethod,
					KeyType: crypto.Ed25519,
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, issuerDID)

				// create an applicant
				applicantPrivKey, applicantDIDKey, err := key.GenerateDIDKey(crypto.Ed25519)
				assert.NoError(t, err)
				assert.NotEmpty(t, applicantPrivKey)
				assert.NotEmpty(t, applicantDIDKey)

				applicantDID, err := applicantDIDKey.Expand()
				assert.NoError(t, err)
				assert.NotEmpty(t, applicantDID)

				// create a schema for the creds to be issued against
				kid := issuerDID.DID.VerificationMethod[0].ID
				licenseApplicationSchema, err := schemaService.CreateSchema(context.Background(),
					schema.CreateSchemaRequest{Issuer: issuerDID.DID.ID, FullyQualifiedVerificationMethodID: kid, Name: "license application schema", Schema: getLicenseApplicationSchema()})
				assert.NoError(t, err)
				assert.NotEmpty(t, licenseApplicationSchema)

				// issue a credential against the schema to the subject, from the issuer
				createdCred, err := credentialService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:                             issuerDID.DID.ID,
					FullyQualifiedVerificationMethodID: kid,
					Subject:                            applicantDID.ID,
					SchemaID:                           licenseApplicationSchema.ID,
					Data:                               map[string]any{"licenseType": "Class D"},
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, createdCred)

				w = httptest.NewRecorder()

				// good request
				createManifestRequest := getValidCreateManifestRequest(issuerDID.DID.ID, issuerDID.DID.VerificationMethod[0].ID, licenseApplicationSchema.ID)

				requestValue := newRequestValue(t, createManifestRequest)
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
				c = newRequestContext(w, req)
				manifestRouter.CreateManifest(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var resp router.CreateManifestResponse
				err = json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(t, err)

				m := resp.Manifest
				assert.NotEmpty(t, m)
				assert.Equal(t, m.Issuer.ID, issuerDID.DID.ID)

				// good application request
				container := []credmodel.Container{{CredentialJWT: createdCred.CredentialJWT}}
				applicationRequest := getValidApplicationRequest(m.ID, m.PresentationDefinition.ID, m.PresentationDefinition.InputDescriptors[0].ID, container)

				// remove the presentation to make this a bad request
				savedSubmission := applicationRequest.CredentialApplication.PresentationSubmission
				applicationRequest.CredentialApplication.PresentationSubmission = nil

				// sign application
				signer, err := keyaccess.NewJWKKeyAccess(applicantDID.ID, applicantDID.VerificationMethod[0].ID, applicantPrivKey)
				assert.NoError(t, err)
				signed, err := signer.SignJSON(applicationRequest)
				assert.NoError(t, err)

				w = httptest.NewRecorder()

				applicationRequestValue := newRequestValue(t, router.SubmitApplicationRequest{ApplicationJWT: *signed})
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests/applications", applicationRequestValue)

				c = newRequestContext(w, req)
				manifestRouter.SubmitApplication(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var op router.Operation
				err = json.NewDecoder(w.Body).Decode(&op)
				assert.NoError(t, err)

				var appResp router.SubmitApplicationResponse
				respData, err := json.Marshal(op.Result.Response)
				assert.NoError(t, err)
				err = json.Unmarshal(respData, &appResp)
				assert.NoError(t, err)

				assert.NotEmpty(t, appResp.Response)
				assert.Equal(t, resp.Manifest.ID, appResp.Response.ManifestID)
				assert.NotEmpty(t, appResp.Response.Denial)
				assert.Contains(t, appResp.Response.Denial.Reason, "no descriptors provided for application")
				assert.Len(t, appResp.Response.Denial.InputDescriptors, 0)

				// submit it again, with an unfulfilled descriptor
				savedSubmission.DescriptorMap[0].ID = "bad"
				applicationRequest.CredentialApplication.PresentationSubmission = savedSubmission

				w = httptest.NewRecorder()

				// sign application
				signed, err = signer.SignJSON(applicationRequest)
				assert.NoError(t, err)

				applicationRequestValue = newRequestValue(t, router.SubmitApplicationRequest{ApplicationJWT: *signed})
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests/applications", applicationRequestValue)
				c = newRequestContext(w, req)
				manifestRouter.SubmitApplication(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				err = json.NewDecoder(w.Body).Decode(&op)
				assert.NoError(t, err)

				respData, err = json.Marshal(op.Result.Response)
				assert.NoError(t, err)
				err = json.Unmarshal(respData, &appResp)
				assert.NoError(t, err)

				assert.NotEmpty(t, appResp.Response)
				assert.Equal(t, resp.Manifest.ID, appResp.Response.ManifestID)
				assert.NotEmpty(t, appResp.Response.Denial)
				assert.Contains(t, appResp.Response.Denial.Reason, "unfilled input descriptor(s): license-type: no submission descriptor found for input descriptor")
				assert.Len(t, appResp.Response.Denial.InputDescriptors, 1)
				assert.Equal(t, appResp.Response.Denial.InputDescriptors[0], "license-type")
			})

			t.Run("Test Get Application By ID and Get Applications", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				keyStoreService, _ := testKeyStoreService(t, db)
				didService, _ := testDIDService(t, db, keyStoreService, nil)
				schemaService := testSchemaService(t, db, keyStoreService, didService)
				credentialService := testCredentialService(t, db, keyStoreService, didService, schemaService)
				manifestRouter, _ := testManifest(t, db, keyStoreService, didService, credentialService)
				w := httptest.NewRecorder()

				// get a application that doesn't exit
				req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/manifests/applications/bad", nil)
				c := newRequestContext(w, req)
				manifestRouter.GetApplication(c)
				assert.Contains(t, w.Body.String(), "cannot get application without ID parameter")

				// reset recorder between calls
				w = httptest.NewRecorder()

				// create an issuer
				issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
					Method:  didsdk.KeyMethod,
					KeyType: crypto.Ed25519,
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, issuerDID)

				// create an applicant
				applicantPrivKey, applicantDIDKey, err := key.GenerateDIDKey(crypto.Ed25519)
				assert.NoError(t, err)
				assert.NotEmpty(t, applicantPrivKey)
				assert.NotEmpty(t, applicantDIDKey)

				applicantDID, err := applicantDIDKey.Expand()
				assert.NoError(t, err)
				assert.NotEmpty(t, applicantDID)

				// create a schema for the creds to be issued against
				kid := issuerDID.DID.VerificationMethod[0].ID
				licenseApplicationSchema, err := schemaService.CreateSchema(context.Background(),
					schema.CreateSchemaRequest{Issuer: issuerDID.DID.ID, FullyQualifiedVerificationMethodID: kid, Name: "license application schema", Schema: getLicenseApplicationSchema()})
				assert.NoError(t, err)
				assert.NotEmpty(t, licenseApplicationSchema)

				licenseSchema, err := schemaService.CreateSchema(
					context.Background(),
					schema.CreateSchemaRequest{Issuer: issuerDID.DID.ID, FullyQualifiedVerificationMethodID: kid, Name: "license schema", Schema: getLicenseSchema()})
				assert.NoError(t, err)
				assert.NotEmpty(t, licenseSchema)
				// issue a credential against the schema to the subject, from the issuer
				createdCred, err := credentialService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:                             issuerDID.DID.ID,
					FullyQualifiedVerificationMethodID: kid,
					Subject:                            applicantDID.ID,
					SchemaID:                           licenseApplicationSchema.ID,
					Data:                               map[string]any{"licenseType": "Class D"},
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, createdCred)

				// good request
				createManifestRequest := getValidCreateManifestRequest(issuerDID.DID.ID, issuerDID.DID.VerificationMethod[0].ID, licenseSchema.ID)

				requestValue := newRequestValue(t, createManifestRequest)
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
				c = newRequestContext(w, req)
				manifestRouter.CreateManifest(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var resp router.CreateManifestResponse
				err = json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(t, err)

				m := resp.Manifest
				assert.NotEmpty(t, m)
				assert.Equal(t, m.Issuer.ID, issuerDID.DID.ID)

				// good application request
				container := []credmodel.Container{{CredentialJWT: createdCred.CredentialJWT}}
				applicationRequest := getValidApplicationRequest(m.ID, m.PresentationDefinition.ID, m.PresentationDefinition.InputDescriptors[0].ID, container)

				// sign application
				signer, err := keyaccess.NewJWKKeyAccess(applicantDID.ID, applicantDID.VerificationMethod[0].ID, applicantPrivKey)
				assert.NoError(t, err)
				signed, err := signer.SignJSON(applicationRequest)
				assert.NoError(t, err)

				applicationRequestValue := newRequestValue(t, router.SubmitApplicationRequest{ApplicationJWT: *signed})
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests/applications", applicationRequestValue)
				c = newRequestContext(w, req)
				manifestRouter.SubmitApplication(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var op router.Operation
				err = json.NewDecoder(w.Body).Decode(&op)
				assert.NoError(t, err)

				// review application
				reviewApplicationRequestValue := newRequestValue(t, router.ReviewApplicationRequest{
					Approved: true,
					Reason:   "I'm the almighty approver",
					CredentialOverrides: map[string]manifestsvc.CredentialOverride{
						"drivers-license-ca": {
							Data: map[string]any{
								"firstName": "John",
								"lastName":  "Doe",
								"state":     "CA",
								"looks":     "pretty darn handsome",
							},
						},
						"drivers-license-ny": {
							Data: map[string]any{
								"firstName": "John",
								"lastName":  "Doe",
								"state":     "NY",
								"looks":     "even handsomer",
							},
						},
					},
				})
				applicationID := storage.StatusObjectID(op.ID)
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests/applications/"+applicationID+"/review", reviewApplicationRequestValue)
				c = newRequestContextWithParams(w, req, map[string]string{"id": applicationID})
				manifestRouter.ReviewApplication(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var appResp router.SubmitApplicationResponse
				err = json.NewDecoder(w.Body).Decode(&appResp)
				assert.NoError(t, err)

				assert.NotEmpty(t, appResp.Response.Fulfillment)
				assert.Empty(t, appResp.Response.Denial)

				// get response by id
				req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/manifests/responses/%s", appResp.Response.ID), nil)
				c = newRequestContextWithParams(w, req, map[string]string{"id": appResp.Response.ID})
				manifestRouter.GetResponse(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var getResponseResponse router.GetResponseResponse
				err = json.NewDecoder(w.Body).Decode(&getResponseResponse)
				assert.NoError(t, err)
				assert.NotEmpty(t, getResponseResponse)
				assert.Equal(t, appResp.Response.ID, getResponseResponse.Response.ID)

				// get all responses
				req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/manifests/responses", nil)
				c = newRequestContext(w, req)
				manifestRouter.ListResponses(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var getResponsesResp router.ListResponsesResponse
				err = json.NewDecoder(w.Body).Decode(&getResponsesResp)
				assert.NoError(t, err)
				assert.NotEmpty(t, getResponsesResp)

				assert.Len(t, getResponsesResp.Responses, 1)

				// get all applications
				req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/manifests/applications", applicationRequestValue)
				c = newRequestContext(w, req)
				manifestRouter.ListApplications(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var getApplicationsResp router.ListApplicationsResponse
				err = json.NewDecoder(w.Body).Decode(&getApplicationsResp)
				assert.NoError(t, err)
				assert.NotEmpty(t, getApplicationsResp)

				assert.Len(t, getApplicationsResp.Applications, 1)

				// get application by id
				req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/manifests/applications/%s", getApplicationsResp.Applications[0].ID), nil)
				c = newRequestContextWithParams(w, req, map[string]string{"id": getApplicationsResp.Applications[0].ID})
				manifestRouter.GetApplication(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var getApplicationResponse router.GetApplicationResponse
				err = json.NewDecoder(w.Body).Decode(&getApplicationResponse)
				assert.NoError(t, err)
				assert.NotEmpty(t, getApplicationResponse)
				assert.Equal(t, getApplicationsResp.Applications[0].ID, getApplicationResponse.ID)
			})

			t.Run("Test Delete Application", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				keyStoreService, _ := testKeyStoreService(t, db)
				didService, _ := testDIDService(t, db, keyStoreService, nil)
				schemaService := testSchemaService(t, db, keyStoreService, didService)
				credentialService := testCredentialService(t, db, keyStoreService, didService, schemaService)
				manifestRouter, _ := testManifest(t, db, keyStoreService, didService, credentialService)

				w := httptest.NewRecorder()

				// create an issuer
				issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
					Method:  didsdk.KeyMethod,
					KeyType: crypto.Ed25519,
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, issuerDID)

				// create an applicant
				applicantPrivKey, applicantDIDKey, err := key.GenerateDIDKey(crypto.Ed25519)
				assert.NoError(t, err)
				assert.NotEmpty(t, applicantPrivKey)
				assert.NotEmpty(t, applicantDIDKey)

				applicantDID, err := applicantDIDKey.Expand()
				assert.NoError(t, err)
				assert.NotEmpty(t, applicantDID)

				// create a schema for the creds to be issued against
				kid := issuerDID.DID.VerificationMethod[0].ID
				createdSchema, err := schemaService.CreateSchema(context.Background(),
					schema.CreateSchemaRequest{Issuer: issuerDID.DID.ID, FullyQualifiedVerificationMethodID: kid, Name: "license schema", Schema: getLicenseApplicationSchema()})
				assert.NoError(t, err)
				assert.NotEmpty(t, createdSchema)

				// issue a credential against the schema to the subject, from the issuer
				createdCred, err := credentialService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:                             issuerDID.DID.ID,
					FullyQualifiedVerificationMethodID: kid,
					Subject:                            applicantDID.ID,
					SchemaID:                           createdSchema.ID,
					Data:                               map[string]any{"licenseType": "WA-DL-CLASS-A"},
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, createdCred)

				// good request
				createManifestRequest := getValidCreateManifestRequest(issuerDID.DID.ID, issuerDID.DID.VerificationMethod[0].ID, createdSchema.ID)

				requestValue := newRequestValue(t, createManifestRequest)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
				c := newRequestContext(w, req)
				manifestRouter.CreateManifest(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var resp router.CreateManifestResponse
				err = json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(t, err)

				m := resp.Manifest
				assert.NotEmpty(t, m)
				assert.Equal(t, m.Issuer.ID, issuerDID.DID.ID)

				// good application request
				container := []credmodel.Container{{CredentialJWT: createdCred.CredentialJWT}}
				applicationRequest := getValidApplicationRequest(m.ID, m.PresentationDefinition.ID, m.PresentationDefinition.InputDescriptors[0].ID, container)

				// sign application
				signer, err := keyaccess.NewJWKKeyAccess(applicantDID.ID, applicantDID.VerificationMethod[0].ID, applicantPrivKey)
				assert.NoError(t, err)
				signed, err := signer.SignJSON(applicationRequest)
				assert.NoError(t, err)

				applicationRequestValue := newRequestValue(t, router.SubmitApplicationRequest{ApplicationJWT: *signed})
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests/applications", applicationRequestValue)
				c = newRequestContext(w, req)
				manifestRouter.SubmitApplication(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var appResp router.SubmitApplicationResponse
				err = json.NewDecoder(w.Body).Decode(&appResp)
				assert.NoError(t, err)

				// get all applications
				req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/manifests/applications", applicationRequestValue)
				c = newRequestContext(w, req)
				manifestRouter.ListApplications(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var getApplicationsResp router.ListApplicationsResponse
				err = json.NewDecoder(w.Body).Decode(&getApplicationsResp)
				assert.NoError(t, err)
				assert.NotEmpty(t, getApplicationsResp)
				assert.Len(t, getApplicationsResp.Applications, 1)

				// get the application
				req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/manifests/applications/%s", getApplicationsResp.Applications[0].ID), nil)
				c = newRequestContextWithParams(w, req, map[string]string{"id": getApplicationsResp.Applications[0].ID})
				manifestRouter.GetApplication(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var getApplicationResp router.GetApplicationResponse
				err = json.NewDecoder(w.Body).Decode(&getApplicationResp)
				assert.NoError(t, err)
				assert.NotEmpty(t, getApplicationResp)
				assert.Equal(t, resp.Manifest.ID, getApplicationResp.Application.ManifestID)

				// delete the application
				req = httptest.NewRequest(http.MethodDelete, fmt.Sprintf("https://ssi-service.com/v1/manifests/applications/%s", getApplicationResp.Application.ID), nil)
				c = newRequestContextWithParams(w, req, map[string]string{"id": getApplicationsResp.Applications[0].ID})
				manifestRouter.DeleteApplication(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				w = httptest.NewRecorder()

				// get it back
				req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/manifests/applications/%s", appResp.Response.ID), nil)
				c = newRequestContextWithParams(w, req, map[string]string{"id": getApplicationsResp.Applications[0].ID})
				manifestRouter.GetApplication(c)
				assert.Contains(t, w.Body.String(), fmt.Sprintf("could not get application with id: %s", appResp.Response.ID))
			})
		})
	}
}

func getValidManifestRequestRequest(issuerDID *did.CreateDIDResponse, kid string, credentialManifest manifest.CredentialManifest) router.CreateManifestRequestRequest {
	return router.CreateManifestRequestRequest{
		CommonCreateRequestRequest: &router.CommonCreateRequestRequest{
			Audience:             []string{"mario"},
			IssuerDID:            issuerDID.DID.ID,
			VerificationMethodID: kid,
			CallbackURL:          "my_callback_url",
		},
		CredentialManifestID: credentialManifest.ID,
	}
}

func getValidIssuanceTemplateRequest(m manifest.CredentialManifest, issuerDID *did.CreateDIDResponse,
	schemaID string, expiry1 time.Time, expiry2 time.Duration) *issuance.CreateIssuanceTemplateRequest {
	return &issuance.CreateIssuanceTemplateRequest{
		IssuanceTemplate: issuance.Template{
			ID:                   uuid.NewString(),
			CredentialManifest:   m.ID,
			Issuer:               issuerDID.DID.ID,
			VerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
			Credentials: []issuance.CredentialTemplate{
				{
					ID:                        "drivers-license-ca",
					Schema:                    schemaID,
					CredentialInputDescriptor: "license-type",
					Data: issuance.ClaimTemplates{
						"firstName": "$.credentialSubject.firstName",
						"lastName":  "$.credentialSubject.lastName",
						"state":     "CA",
					},
					Expiry: issuance.TimeLike{
						Time: &expiry1,
					},
				},
				{
					ID:                        "drivers-license-ny",
					Schema:                    schemaID,
					CredentialInputDescriptor: "license-type",
					Data: issuance.ClaimTemplates{
						"firstName": "$.credentialSubject.firstName",
						"lastName":  "$.credentialSubject.lastName",
						"state":     "NY",
						"someCrazyObject": map[string]any{
							"foo": 123,
							"bar": false,
							"baz": []any{
								"yay", 123, nil,
							},
						},
					},
					Expiry:    issuance.TimeLike{Duration: &expiry2},
					Revocable: true,
				},
			},
		},
	}
}

func getLicenseApplicationSchema() map[string]any {
	return map[string]any{
		"$schema": "https://json-schema.org/draft-07/schema",
		"type":    "object",
		"properties": map[string]any{
			"credentialSubject": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"licenseType": map[string]any{
						"type": "string",
					},
				},
				"required": []any{"licenseType"},
			},
		},
	}
}

func getLicenseSchema() map[string]any {
	return map[string]any{
		"$schema": "https://json-schema.org/draft-07/schema",
		"type":    "object",
		"properties": map[string]any{
			"credentialSubject": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"firstName": map[string]any{
						"type": "string",
					},
					"lastName": map[string]any{
						"type": "string",
					},
					"state": map[string]any{
						"type": "string",
					},
				},
				"required": []any{"firstName", "lastName", "state"},
			},
		},
	}
}
