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
)

func TestManifestAPI(t *testing.T) {
	t.Run("Test Create Manifest", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotEmpty(tt, bolt)

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credentialService := testCredentialService(tt, bolt, keyStoreService, didService, schemaService)
		manifestRouter, manifestService := testManifest(tt, bolt, keyStoreService, didService, credentialService)

		// missing required field: Manifest
		var badManifestRequest router.CreateManifestRequest
		badRequestValue := newRequestValue(tt, badManifestRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", badRequestValue)
		w := httptest.NewRecorder()

		c := newRequestContext(w, req)
		manifestRouter.CreateManifest(c)
		assert.Contains(tt, w.Body.String(), "invalid create manifest request")

		// reset the http recorder
		w = httptest.NewRecorder()

		// create an issuer
		issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		// create a schema for the creds to be issued against
		licenseSchema := map[string]any{
			"type": "object",
			"properties": map[string]any{
				"licenseType": map[string]any{
					"type": "string",
				},
			},
			"additionalProperties": true,
		}
		kid := issuerDID.DID.VerificationMethod[0].ID
		createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Author: issuerDID.DID.ID, AuthorKID: kid, Name: "license schema", Schema: licenseSchema, Sign: true})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdSchema)

		// good request
		createManifestRequest := getValidManifestRequest(issuerDID.DID.ID, issuerDID.DID.VerificationMethod[0].ID, createdSchema.ID)

		requestValue := newRequestValue(tt, createManifestRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
		c = newRequestContext(w, req)
		manifestRouter.CreateManifest(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var resp router.CreateManifestResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resp.Manifest)
		assert.Equal(tt, resp.Manifest.Issuer.ID, issuerDID.DID.ID)

		// create a credential manifest request
		manifestRequestRequest := getValidManifestRequestRequest(issuerDID, kid, resp.Manifest)
		requestValue = newRequestValue(tt, manifestRequestRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests/requests", requestValue)
		c = newRequestContext(w, req)
		manifestRouter.CreateRequest(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var reqResp router.CreateManifestRequestResponse
		err = json.NewDecoder(w.Body).Decode(&reqResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, reqResp.Request)

		// verify the manifest
		verificationResponse, err := manifestService.VerifyManifest(context.Background(), manifestsvc.VerifyManifestRequest{ManifestJWT: reqResp.Request.CredentialManifestJWT})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, verificationResponse)
		assert.True(tt, verificationResponse.Verified)
	})

	t.Run("Test Get Manifest By ID", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotEmpty(tt, bolt)

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credentialService := testCredentialService(tt, bolt, keyStoreService, didService, schemaService)
		manifestRouter, _ := testManifest(tt, bolt, keyStoreService, didService, credentialService)

		w := httptest.NewRecorder()

		// get a manifest that doesn't exit
		req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/manifests/bad", nil)
		c := newRequestContext(w, req)
		manifestRouter.GetManifest(c)
		assert.Contains(tt, w.Body.String(), "cannot get manifest without ID parameter")

		// reset recorder between calls
		w = httptest.NewRecorder()

		// get a manifest with an invalid id parameter
		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/manifests/bad", nil)
		c = newRequestContextWithParams(w, req, map[string]string{"id": "bad"})
		manifestRouter.GetManifest(c)
		assert.Contains(tt, w.Body.String(), "could not get manifest with id: bad")

		// reset recorder between calls
		w = httptest.NewRecorder()

		// create an issuer
		issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		// create a schema for the creds to be issued against
		licenseSchema := map[string]any{
			"type": "object",
			"properties": map[string]any{
				"licenseType": map[string]any{
					"type": "string",
				},
			},
			"additionalProperties": true,
		}
		kid := issuerDID.DID.VerificationMethod[0].ID
		createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Author: issuerDID.DID.ID, AuthorKID: kid, Name: "license schema", Schema: licenseSchema, Sign: true})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdSchema)

		// good request
		createManifestRequest := getValidManifestRequest(issuerDID.DID.ID, issuerDID.DID.VerificationMethod[0].ID, createdSchema.ID)

		requestValue := newRequestValue(tt, createManifestRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
		c = newRequestContext(w, req)
		manifestRouter.CreateManifest(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var resp router.CreateManifestResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		// get manifest by id
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/manifests/%s", resp.Manifest.ID), nil)
		c = newRequestContextWithParams(w, req, map[string]string{"id": resp.Manifest.ID})
		manifestRouter.GetManifest(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var getManifestResp router.ListManifestResponse
		err = json.NewDecoder(w.Body).Decode(&getManifestResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getManifestResp)
		assert.Equal(tt, resp.Manifest.ID, getManifestResp.ID)
	})

	t.Run("Test Get Manifests", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotEmpty(tt, bolt)

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credentialService := testCredentialService(tt, bolt, keyStoreService, didService, schemaService)
		manifestRouter, manifestService := testManifest(tt, bolt, keyStoreService, didService, credentialService)

		w := httptest.NewRecorder()

		// create an issuer
		issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		// create a schema for the creds to be issued against
		licenseSchema := map[string]any{
			"type": "object",
			"properties": map[string]any{
				"licenseType": map[string]any{
					"type": "string",
				},
			},
			"additionalProperties": true,
		}
		kid := issuerDID.DID.VerificationMethod[0].ID
		createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Author: issuerDID.DID.ID, AuthorKID: kid, Name: "license schema", Schema: licenseSchema, Sign: true})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdSchema)

		// good request
		createManifestRequest := getValidManifestRequest(issuerDID.DID.ID, issuerDID.DID.VerificationMethod[0].ID, createdSchema.ID)

		requestValue := newRequestValue(tt, createManifestRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
		c := newRequestContext(w, req)
		manifestRouter.CreateManifest(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var resp router.CreateManifestResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		// list all manifests
		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/manifests", nil)
		c = newRequestContext(w, req)
		manifestRouter.ListManifests(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var getManifestsResp router.ListManifestsResponse
		err = json.NewDecoder(w.Body).Decode(&getManifestsResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getManifestsResp)
		assert.Len(tt, getManifestsResp.Manifests, 1)
		assert.Equal(tt, resp.Manifest.ID, getManifestsResp.Manifests[0].ID)

		// create a credential manifest request
		manifestRequestRequest := getValidManifestRequestRequest(issuerDID, kid, resp.Manifest)
		requestValue = newRequestValue(tt, manifestRequestRequest)
		w = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests/requests", requestValue)
		c = newRequestContext(w, req)
		manifestRouter.CreateRequest(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var reqResp router.CreateManifestRequestResponse
		err = json.NewDecoder(w.Body).Decode(&reqResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, reqResp.Request)

		// list the manifest requests
		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/manifests/requests", nil)
		c = newRequestContext(w, req)
		manifestRouter.ListRequests(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var getManifestReqsResp router.ListManifestRequestsResponse
		err = json.NewDecoder(w.Body).Decode(&getManifestReqsResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getManifestReqsResp)
		assert.Len(tt, getManifestReqsResp.Requests, 1)
		assert.Equal(tt, reqResp.Request.ID, getManifestReqsResp.Requests[0].ID)

		// verify each manifest request
		for _, m := range getManifestReqsResp.Requests {
			verificationResponse, err := manifestService.VerifyManifest(context.Background(), manifestsvc.VerifyManifestRequest{ManifestJWT: m.CredentialManifestJWT})
			assert.NoError(tt, err)
			assert.NotEmpty(tt, verificationResponse)
			assert.True(tt, verificationResponse.Verified)
		}
	})

	t.Run("Test Delete Manifest", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotEmpty(tt, bolt)

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credentialService := testCredentialService(tt, bolt, keyStoreService, didService, schemaService)
		manifestRouter, _ := testManifest(tt, bolt, keyStoreService, didService, credentialService)

		// create an issuer
		issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		// create a schema for the creds to be issued against
		licenseSchema := map[string]any{
			"type": "object",
			"properties": map[string]any{
				"licenseType": map[string]any{
					"type": "string",
				},
			},
			"additionalProperties": true,
		}
		kid := issuerDID.DID.VerificationMethod[0].ID
		createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Author: issuerDID.DID.ID, AuthorKID: kid, Name: "license schema", Schema: licenseSchema, Sign: true})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdSchema)

		// good request
		createManifestRequest := getValidManifestRequest(issuerDID.DID.ID, issuerDID.DID.VerificationMethod[0].ID, createdSchema.ID)

		requestValue := newRequestValue(tt, createManifestRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
		w := httptest.NewRecorder()
		c := newRequestContext(w, req)
		manifestRouter.CreateManifest(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var resp router.CreateManifestResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		w = httptest.NewRecorder()

		// get credential by id
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/manifests/%s", resp.Manifest.ID), nil)
		c = newRequestContextWithParams(w, req, map[string]string{"id": resp.Manifest.ID})
		manifestRouter.GetManifest(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var getManifestResp router.GetCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&getManifestResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getManifestResp)
		assert.Equal(tt, resp.Manifest.ID, getManifestResp.ID)

		w = httptest.NewRecorder()

		// delete it
		req = httptest.NewRequest(http.MethodDelete, fmt.Sprintf("https://ssi-service.com/v1/manifests/%s", resp.Manifest.ID), nil)
		c = newRequestContextWithParams(w, req, map[string]string{"id": resp.Manifest.ID})
		manifestRouter.DeleteManifest(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		w = httptest.NewRecorder()

		// get it back
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/manifests/%s", resp.Manifest.ID), nil)
		c = newRequestContextWithParams(w, req, map[string]string{"id": resp.Manifest.ID})
		manifestRouter.GetManifest(c)
		assert.Contains(tt, w.Body.String(), fmt.Sprintf("could not get manifest with id: %s", resp.Manifest.ID))
	})

	t.Run("Submit Application With Issuance Template", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotEmpty(tt, bolt)

		keyStoreService := testKeyStoreService(tt, bolt)
		issuanceService := testIssuanceService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credentialService := testCredentialService(tt, bolt, keyStoreService, didService, schemaService)
		manifestRouter, manifestSvc := testManifest(tt, bolt, keyStoreService, didService, credentialService)

		// create an issuer
		issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		// create an applicant
		applicantPrivKey, applicantDIDKey, err := key.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, applicantPrivKey)
		assert.NotEmpty(tt, applicantDIDKey)

		applicantDID, err := applicantDIDKey.Expand()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, applicantDID)

		// create a schema for the creds to be issued against
		licenseSchema := map[string]any{
			"type": "object",
			"properties": map[string]any{
				"licenseType": map[string]any{
					"type": "string",
				},
			},
			"additionalProperties": true,
		}
		kid := issuerDID.DID.VerificationMethod[0].ID
		createdSchema, err := schemaService.CreateSchema(
			context.Background(),
			schema.CreateSchemaRequest{Author: issuerDID.DID.ID, AuthorKID: kid, Name: "license schema", Schema: licenseSchema, Sign: true})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdSchema)

		// issue a credential against the schema to the subject, from the issuer
		createdCred, err := credentialService.CreateCredential(
			context.Background(),
			credential.CreateCredentialRequest{
				Issuer:    issuerDID.DID.ID,
				IssuerKID: kid,
				Subject:   applicantDID.ID,
				SchemaID:  createdSchema.ID,
				Data: map[string]any{
					"licenseType": "WA-DL-CLASS-A",
					"firstName":   "Tester",
					"lastName":    "McTest",
				},
			})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdCred)

		// good request
		createManifestRequest := getValidManifestRequest(issuerDID.DID.ID, issuerDID.DID.VerificationMethod[0].ID, createdSchema.ID)

		requestValue := newRequestValue(tt, createManifestRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
		w := httptest.NewRecorder()
		c := newRequestContext(w, req)
		manifestRouter.CreateManifest(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var resp router.CreateManifestResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		m := resp.Manifest
		assert.NotEmpty(tt, m)
		assert.Equal(tt, m.Issuer.ID, issuerDID.DID.ID)

		// good application request
		container := []credmodel.Container{{CredentialJWT: createdCred.CredentialJWT}}
		applicationRequest := getValidApplicationRequest(m.ID, m.PresentationDefinition.ID, m.PresentationDefinition.InputDescriptors[0].ID, container)

		// sign application
		signer, err := keyaccess.NewJWKKeyAccess(applicantDID.ID, applicantDID.VerificationMethod[0].ID, applicantPrivKey)
		assert.NoError(tt, err)
		signed, err := signer.SignJSON(applicationRequest)
		assert.NoError(tt, err)

		expiryDateTime := time.Date(2022, 10, 31, 0, 0, 0, 0, time.UTC)
		mockClock := clock.NewMock()
		manifestSvc.Clock = mockClock
		mockClock.Set(expiryDateTime)
		expiryDuration := 5 * time.Second
		issuanceTemplate, err := issuanceService.CreateIssuanceTemplate(context.Background(),
			getValidIssuanceTemplateRequest(m, issuerDID, createdSchema, expiryDateTime, expiryDuration))
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuanceTemplate)

		applicationRequestValue := newRequestValue(tt, router.SubmitApplicationRequest{ApplicationJWT: *signed})
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests/applications", applicationRequestValue)
		c = newRequestContext(w, req)
		manifestRouter.SubmitApplication(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var op router.Operation
		err = json.NewDecoder(w.Body).Decode(&op)
		assert.NoError(tt, err)
		assert.True(tt, op.Done)

		var appResp router.SubmitApplicationResponse
		respData, err := json.Marshal(op.Result.Response)
		assert.NoError(tt, err)
		err = json.Unmarshal(respData, &appResp)
		assert.NoError(tt, err)
		assert.Len(tt, appResp.Credentials, 2, "each output_descriptor in the definition should result in a credential")

		_, _, vc, err := credsdk.ToCredential(appResp.Credentials[0])
		assert.NoError(tt, err)
		expectedSubject := credsdk.CredentialSubject{
			"id":        applicantDID.ID,
			"state":     "CA",
			"firstName": "Tester",
			"lastName":  "McTest",
		}
		assert.Equal(tt, expectedSubject, vc.CredentialSubject)
		assert.Equal(tt, time.Date(2022, 10, 31, 0, 0, 0, 0, time.UTC).Format(time.RFC3339), vc.ExpirationDate)
		assert.Equal(tt, createdSchema.ID, vc.CredentialSchema.ID)
		assert.Empty(tt, vc.CredentialStatus)

		_, _, vc2, err := credsdk.ToCredential(appResp.Credentials[1])
		assert.NoError(tt, err)
		expectedSubject = credsdk.CredentialSubject{
			"id": applicantDID.ID,
			"someCrazyObject": map[string]any{
				"foo": 123.,
				"bar": false,
				"baz": []any{
					"yay", 123., nil,
				},
			},
		}
		assert.Equal(tt, expectedSubject, vc2.CredentialSubject)
		assert.Equal(tt,
			time.Date(2022, 10, 31, 0, 0, 5, 0, time.UTC).Format(time.RFC3339),
			vc2.ExpirationDate,
		)
		assert.Equal(tt, createdSchema.ID, vc2.CredentialSchema.ID)
		assert.NotEmpty(tt, vc2.CredentialStatus)
	})

	t.Run("Test Submit Application", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotEmpty(tt, bolt)

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credentialService := testCredentialService(tt, bolt, keyStoreService, didService, schemaService)
		manifestRouter, _ := testManifest(tt, bolt, keyStoreService, didService, credentialService)

		// missing required field: Application
		badManifestRequest := router.SubmitApplicationRequest{ApplicationJWT: "bad"}
		badRequestValue := newRequestValue(tt, badManifestRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests/applications", badRequestValue)
		w := httptest.NewRecorder()

		c := newRequestContext(w, req)
		manifestRouter.SubmitApplication(c)
		assert.Contains(tt, w.Body.String(), "invalid submit application request")

		// create an issuer
		issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		// create an applicant
		applicantPrivKey, applicantDIDKey, err := key.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, applicantPrivKey)
		assert.NotEmpty(tt, applicantDIDKey)

		applicantDID, err := applicantDIDKey.Expand()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, applicantDID)

		// create a schema for the creds to be issued against
		licenseSchema := map[string]any{
			"type": "object",
			"properties": map[string]any{
				"licenseType": map[string]any{
					"type": "string",
				},
			},
			"additionalProperties": true,
		}
		kid := issuerDID.DID.VerificationMethod[0].ID
		createdSchema, err := schemaService.CreateSchema(context.Background(),
			schema.CreateSchemaRequest{Author: issuerDID.DID.ID, AuthorKID: kid, Name: "license schema", Schema: licenseSchema, Sign: true})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdSchema)

		// issue a credential against the schema to the subject, from the issuer
		createdCred, err := credentialService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
			Issuer:    issuerDID.DID.ID,
			IssuerKID: kid,
			Subject:   applicantDID.ID,
			SchemaID:  createdSchema.ID,
			Data:      map[string]any{"licenseType": "WA-DL-CLASS-A"},
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdCred)

		// good request
		createManifestRequest := getValidManifestRequest(issuerDID.DID.ID, issuerDID.DID.VerificationMethod[0].ID, createdSchema.ID)

		w = httptest.NewRecorder()

		requestValue := newRequestValue(tt, createManifestRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
		c = newRequestContext(w, req)
		manifestRouter.CreateManifest(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var resp router.CreateManifestResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		m := resp.Manifest
		assert.NotEmpty(tt, m)
		assert.Equal(tt, m.Issuer.ID, issuerDID.DID.ID)

		// good application request
		container := []credmodel.Container{{CredentialJWT: createdCred.CredentialJWT}}
		applicationRequest := getValidApplicationRequest(m.ID, m.PresentationDefinition.ID, m.PresentationDefinition.InputDescriptors[0].ID, container)

		// sign application
		signer, err := keyaccess.NewJWKKeyAccess(applicantDID.ID, applicantDID.VerificationMethod[0].ID, applicantPrivKey)
		assert.NoError(tt, err)
		signed, err := signer.SignJSON(applicationRequest)
		assert.NoError(tt, err)

		w = httptest.NewRecorder()

		applicationRequestValue := newRequestValue(tt, router.SubmitApplicationRequest{ApplicationJWT: *signed})
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests/applications", applicationRequestValue)
		c = newRequestContext(w, req)
		manifestRouter.SubmitApplication(c)
		assert.NoError(tt, err)

		var op router.Operation
		err = json.NewDecoder(w.Body).Decode(&op)
		assert.NoError(tt, err)

		assert.False(tt, op.Done)
		assert.Contains(tt, op.ID, "credentials/responses/")

		// review application
		expireAt := time.Date(2025, 10, 32, 0, 0, 0, 0, time.UTC)
		reviewApplicationRequestValue := newRequestValue(tt, router.ReviewApplicationRequest{
			Approved: true,
			Reason:   "I'm the almighty approver",
			CredentialOverrides: map[string]manifestsvc.CredentialOverride{
				"id1": {
					Data:      map[string]any{"looks": "pretty darn handsome"},
					Expiry:    &expireAt,
					Revocable: true,
				},
			},
		})
		applicationID := storage.StatusObjectID(op.ID)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests/applications/"+applicationID+"/review", reviewApplicationRequestValue)
		c = newRequestContextWithParams(w, req, map[string]string{"id": applicationID})
		manifestRouter.ReviewApplication(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var appResp router.SubmitApplicationResponse
		err = json.NewDecoder(w.Body).Decode(&appResp)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, appResp.Response)
		assert.Equal(tt, resp.Manifest.ID, appResp.Response.ManifestID)
		assert.NotEmpty(tt, appResp.Response.Fulfillment)
		assert.Len(tt, appResp.Response.Fulfillment.DescriptorMap, 2)
		assert.Len(tt, appResp.Credentials, 2)
		assert.Empty(tt, appResp.Response.Denial)

		_, _, vc, err := credsdk.ToCredential(appResp.Credentials[0])
		assert.NoError(tt, err)
		assert.Equal(tt, credsdk.CredentialSubject{
			"id":    applicantDID.ID,
			"looks": "pretty darn handsome",
		}, vc.CredentialSubject)
		assert.Equal(tt, expireAt.Format(time.RFC3339), vc.ExpirationDate)
		assert.NotEmpty(tt, vc.CredentialStatus)
		assert.Equal(tt, createdSchema.ID, vc.CredentialSchema.ID)
	})

	t.Run("Test Denied Application", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotEmpty(tt, bolt)

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credentialService := testCredentialService(tt, bolt, keyStoreService, didService, schemaService)
		manifestRouter, _ := testManifest(tt, bolt, keyStoreService, didService, credentialService)

		// missing required field: Application
		badManifestRequest := router.SubmitApplicationRequest{
			ApplicationJWT: "bad",
		}

		badRequestValue := newRequestValue(tt, badManifestRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests/applications", badRequestValue)
		w := httptest.NewRecorder()

		c := newRequestContext(w, req)
		manifestRouter.SubmitApplication(c)
		assert.Contains(tt, w.Body.String(), "invalid submit application request")

		// create an issuer
		issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		// create an applicant
		applicantPrivKey, applicantDIDKey, err := key.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, applicantPrivKey)
		assert.NotEmpty(tt, applicantDIDKey)

		applicantDID, err := applicantDIDKey.Expand()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, applicantDID)

		// create a schema for the creds to be issued against
		licenseSchema := map[string]any{
			"type": "object",
			"properties": map[string]any{
				"licenseType": map[string]any{
					"type": "string",
				},
			},
			"additionalProperties": true,
		}
		kid := issuerDID.DID.VerificationMethod[0].ID
		createdSchema, err := schemaService.CreateSchema(context.Background(),
			schema.CreateSchemaRequest{Author: issuerDID.DID.ID, AuthorKID: kid, Name: "license schema", Schema: licenseSchema, Sign: true})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdSchema)

		// issue a credential against the schema to the subject, from the issuer
		createdCred, err := credentialService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
			Issuer:    issuerDID.DID.ID,
			IssuerKID: kid,
			Subject:   applicantDID.ID,
			SchemaID:  createdSchema.ID,
			Data:      map[string]any{"licenseType": "WA-DL-CLASS-A"},
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdCred)

		w = httptest.NewRecorder()

		// good request
		createManifestRequest := getValidManifestRequest(issuerDID.DID.ID, issuerDID.DID.VerificationMethod[0].ID, createdSchema.ID)

		requestValue := newRequestValue(tt, createManifestRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
		c = newRequestContext(w, req)
		manifestRouter.CreateManifest(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var resp router.CreateManifestResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		m := resp.Manifest
		assert.NotEmpty(tt, m)
		assert.Equal(tt, m.Issuer.ID, issuerDID.DID.ID)

		// good application request
		container := []credmodel.Container{{CredentialJWT: createdCred.CredentialJWT}}
		applicationRequest := getValidApplicationRequest(m.ID, m.PresentationDefinition.ID, m.PresentationDefinition.InputDescriptors[0].ID, container)

		// remove the presentation to make this a bad request
		savedSubmission := applicationRequest.CredentialApplication.PresentationSubmission
		applicationRequest.CredentialApplication.PresentationSubmission = nil

		// sign application
		signer, err := keyaccess.NewJWKKeyAccess(applicantDID.ID, applicantDID.VerificationMethod[0].ID, applicantPrivKey)
		assert.NoError(tt, err)
		signed, err := signer.SignJSON(applicationRequest)
		assert.NoError(tt, err)

		w = httptest.NewRecorder()

		applicationRequestValue := newRequestValue(tt, router.SubmitApplicationRequest{ApplicationJWT: *signed})
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests/applications", applicationRequestValue)

		c = newRequestContext(w, req)
		manifestRouter.SubmitApplication(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var op router.Operation
		err = json.NewDecoder(w.Body).Decode(&op)
		assert.NoError(tt, err)

		var appResp router.SubmitApplicationResponse
		respData, err := json.Marshal(op.Result.Response)
		assert.NoError(tt, err)
		err = json.Unmarshal(respData, &appResp)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, appResp.Response)
		assert.Equal(tt, resp.Manifest.ID, appResp.Response.ManifestID)
		assert.NotEmpty(tt, appResp.Response.Denial)
		assert.Contains(tt, appResp.Response.Denial.Reason, "no descriptors provided for application")
		assert.Len(tt, appResp.Response.Denial.InputDescriptors, 0)

		// submit it again, with an unfulfilled descriptor
		savedSubmission.DescriptorMap[0].ID = "bad"
		applicationRequest.CredentialApplication.PresentationSubmission = savedSubmission

		w = httptest.NewRecorder()

		// sign application
		signed, err = signer.SignJSON(applicationRequest)
		assert.NoError(tt, err)

		applicationRequestValue = newRequestValue(tt, router.SubmitApplicationRequest{ApplicationJWT: *signed})
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests/applications", applicationRequestValue)
		c = newRequestContext(w, req)
		manifestRouter.SubmitApplication(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		err = json.NewDecoder(w.Body).Decode(&op)
		assert.NoError(tt, err)

		respData, err = json.Marshal(op.Result.Response)
		assert.NoError(tt, err)
		err = json.Unmarshal(respData, &appResp)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, appResp.Response)
		assert.Equal(tt, resp.Manifest.ID, appResp.Response.ManifestID)
		assert.NotEmpty(tt, appResp.Response.Denial)
		assert.Contains(tt, appResp.Response.Denial.Reason, "unfilled input descriptor(s): test-id: no submission descriptor found for input descriptor")
		assert.Len(tt, appResp.Response.Denial.InputDescriptors, 1)
		assert.Equal(tt, appResp.Response.Denial.InputDescriptors[0], "test-id")
	})

	t.Run("Test Get Application By ID and Get Applications", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotEmpty(tt, bolt)

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credentialService := testCredentialService(tt, bolt, keyStoreService, didService, schemaService)
		manifestRouter, _ := testManifest(tt, bolt, keyStoreService, didService, credentialService)
		w := httptest.NewRecorder()

		// get a application that doesn't exit
		req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/manifests/applications/bad", nil)
		c := newRequestContext(w, req)
		manifestRouter.GetApplication(c)
		assert.Contains(tt, w.Body.String(), "cannot get application without ID parameter")

		// reset recorder between calls
		w = httptest.NewRecorder()

		// create an issuer
		issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		// create an applicant
		applicantPrivKey, applicantDIDKey, err := key.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, applicantPrivKey)
		assert.NotEmpty(tt, applicantDIDKey)

		applicantDID, err := applicantDIDKey.Expand()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, applicantDID)

		// create a schema for the creds to be issued against
		licenseSchema := map[string]any{
			"type": "object",
			"properties": map[string]any{
				"licenseType": map[string]any{
					"type": "string",
				},
			},
			"additionalProperties": true,
		}
		kid := issuerDID.DID.VerificationMethod[0].ID
		createdSchema, err := schemaService.CreateSchema(context.Background(),
			schema.CreateSchemaRequest{Author: issuerDID.DID.ID, AuthorKID: kid, Name: "license schema", Schema: licenseSchema, Sign: true})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdSchema)

		// issue a credential against the schema to the subject, from the issuer
		createdCred, err := credentialService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
			Issuer:    issuerDID.DID.ID,
			IssuerKID: kid,
			Subject:   applicantDID.ID,
			SchemaID:  createdSchema.ID,
			Data:      map[string]any{"licenseType": "WA-DL-CLASS-A"},
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdCred)

		// good request
		createManifestRequest := getValidManifestRequest(issuerDID.DID.ID, issuerDID.DID.VerificationMethod[0].ID, createdSchema.ID)

		requestValue := newRequestValue(tt, createManifestRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
		c = newRequestContext(w, req)
		manifestRouter.CreateManifest(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var resp router.CreateManifestResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		m := resp.Manifest
		assert.NotEmpty(tt, m)
		assert.Equal(tt, m.Issuer.ID, issuerDID.DID.ID)

		// good application request
		container := []credmodel.Container{{CredentialJWT: createdCred.CredentialJWT}}
		applicationRequest := getValidApplicationRequest(m.ID, m.PresentationDefinition.ID, m.PresentationDefinition.InputDescriptors[0].ID, container)

		// sign application
		signer, err := keyaccess.NewJWKKeyAccess(applicantDID.ID, applicantDID.VerificationMethod[0].ID, applicantPrivKey)
		assert.NoError(tt, err)
		signed, err := signer.SignJSON(applicationRequest)
		assert.NoError(tt, err)

		applicationRequestValue := newRequestValue(tt, router.SubmitApplicationRequest{ApplicationJWT: *signed})
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests/applications", applicationRequestValue)
		c = newRequestContext(w, req)
		manifestRouter.SubmitApplication(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var op router.Operation
		err = json.NewDecoder(w.Body).Decode(&op)
		assert.NoError(tt, err)

		// review application
		reviewApplicationRequestValue := newRequestValue(tt, router.ReviewApplicationRequest{Approved: true, Reason: "I'm the almighty approver"})
		applicationID := storage.StatusObjectID(op.ID)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests/applications/"+applicationID+"/review", reviewApplicationRequestValue)
		c = newRequestContextWithParams(w, req, map[string]string{"id": applicationID})
		manifestRouter.ReviewApplication(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var appResp router.SubmitApplicationResponse
		err = json.NewDecoder(w.Body).Decode(&appResp)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, appResp.Response.Fulfillment)
		assert.Empty(tt, appResp.Response.Denial)

		// get response by id
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/manifests/responses/%s", appResp.Response.ID), nil)
		c = newRequestContextWithParams(w, req, map[string]string{"id": appResp.Response.ID})
		manifestRouter.GetResponse(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var getResponseResponse router.GetResponseResponse
		err = json.NewDecoder(w.Body).Decode(&getResponseResponse)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getResponseResponse)
		assert.Equal(tt, appResp.Response.ID, getResponseResponse.Response.ID)

		// get all responses
		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/manifests/responses", nil)
		c = newRequestContext(w, req)
		manifestRouter.ListResponses(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var getResponsesResp router.ListResponsesResponse
		err = json.NewDecoder(w.Body).Decode(&getResponsesResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getResponsesResp)

		assert.Len(tt, getResponsesResp.Responses, 1)

		// get all applications
		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/manifests/applications", applicationRequestValue)
		c = newRequestContext(w, req)
		manifestRouter.ListApplications(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var getApplicationsResp router.ListApplicationsResponse
		err = json.NewDecoder(w.Body).Decode(&getApplicationsResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getApplicationsResp)

		assert.Len(tt, getApplicationsResp.Applications, 1)

		// get application by id
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/manifests/applications/%s", getApplicationsResp.Applications[0].ID), nil)
		c = newRequestContextWithParams(w, req, map[string]string{"id": getApplicationsResp.Applications[0].ID})
		manifestRouter.GetApplication(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var getApplicationResponse router.GetApplicationResponse
		err = json.NewDecoder(w.Body).Decode(&getApplicationResponse)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getApplicationResponse)
		assert.Equal(tt, getApplicationsResp.Applications[0].ID, getApplicationResponse.ID)
	})

	t.Run("Test Delete Application", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotEmpty(tt, bolt)

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credentialService := testCredentialService(tt, bolt, keyStoreService, didService, schemaService)
		manifestRouter, _ := testManifest(tt, bolt, keyStoreService, didService, credentialService)

		w := httptest.NewRecorder()

		// create an issuer
		issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		// create an applicant
		applicantPrivKey, applicantDIDKey, err := key.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, applicantPrivKey)
		assert.NotEmpty(tt, applicantDIDKey)

		applicantDID, err := applicantDIDKey.Expand()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, applicantDID)

		// create a schema for the creds to be issued against
		licenseSchema := map[string]any{
			"type": "object",
			"properties": map[string]any{
				"licenseType": map[string]any{
					"type": "string",
				},
			},
			"additionalProperties": true,
		}
		kid := issuerDID.DID.VerificationMethod[0].ID
		createdSchema, err := schemaService.CreateSchema(context.Background(),
			schema.CreateSchemaRequest{Author: issuerDID.DID.ID, AuthorKID: kid, Name: "license schema", Schema: licenseSchema, Sign: true})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdSchema)

		// issue a credential against the schema to the subject, from the issuer
		createdCred, err := credentialService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
			Issuer:    issuerDID.DID.ID,
			IssuerKID: kid,
			Subject:   applicantDID.ID,
			SchemaID:  createdSchema.ID,
			Data:      map[string]any{"licenseType": "WA-DL-CLASS-A"},
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdCred)

		// good request
		createManifestRequest := getValidManifestRequest(issuerDID.DID.ID, issuerDID.DID.VerificationMethod[0].ID, createdSchema.ID)

		requestValue := newRequestValue(tt, createManifestRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
		c := newRequestContext(w, req)
		manifestRouter.CreateManifest(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var resp router.CreateManifestResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		m := resp.Manifest
		assert.NotEmpty(tt, m)
		assert.Equal(tt, m.Issuer.ID, issuerDID.DID.ID)

		// good application request
		container := []credmodel.Container{{CredentialJWT: createdCred.CredentialJWT}}
		applicationRequest := getValidApplicationRequest(m.ID, m.PresentationDefinition.ID, m.PresentationDefinition.InputDescriptors[0].ID, container)

		// sign application
		signer, err := keyaccess.NewJWKKeyAccess(applicantDID.ID, applicantDID.VerificationMethod[0].ID, applicantPrivKey)
		assert.NoError(tt, err)
		signed, err := signer.SignJSON(applicationRequest)
		assert.NoError(tt, err)

		applicationRequestValue := newRequestValue(tt, router.SubmitApplicationRequest{ApplicationJWT: *signed})
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests/applications", applicationRequestValue)
		c = newRequestContext(w, req)
		manifestRouter.SubmitApplication(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var appResp router.SubmitApplicationResponse
		err = json.NewDecoder(w.Body).Decode(&appResp)
		assert.NoError(tt, err)

		// get all applications
		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/manifests/applications", applicationRequestValue)
		c = newRequestContext(w, req)
		manifestRouter.ListApplications(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var getApplicationsResp router.ListApplicationsResponse
		err = json.NewDecoder(w.Body).Decode(&getApplicationsResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getApplicationsResp)
		assert.Len(tt, getApplicationsResp.Applications, 1)

		// get the application
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/manifests/applications/%s", getApplicationsResp.Applications[0].ID), nil)
		c = newRequestContextWithParams(w, req, map[string]string{"id": getApplicationsResp.Applications[0].ID})
		manifestRouter.GetApplication(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var getApplicationResp router.GetApplicationResponse
		err = json.NewDecoder(w.Body).Decode(&getApplicationResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getApplicationResp)
		assert.Equal(tt, resp.Manifest.ID, getApplicationResp.Application.ManifestID)

		// delete the application
		req = httptest.NewRequest(http.MethodDelete, fmt.Sprintf("https://ssi-service.com/v1/manifests/applications/%s", getApplicationResp.Application.ID), nil)
		c = newRequestContextWithParams(w, req, map[string]string{"id": getApplicationsResp.Applications[0].ID})
		manifestRouter.DeleteApplication(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		w = httptest.NewRecorder()

		// get it back
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/manifests/applications/%s", appResp.Response.ID), nil)
		c = newRequestContextWithParams(w, req, map[string]string{"id": getApplicationsResp.Applications[0].ID})
		manifestRouter.GetApplication(c)
		assert.Contains(tt, w.Body.String(), fmt.Sprintf("could not get application with id: %s", appResp.Response.ID))
	})
}

func getValidManifestRequestRequest(issuerDID *did.CreateDIDResponse, kid string, credentialManifest manifest.CredentialManifest) router.CreateManifestRequestRequest {
	return router.CreateManifestRequestRequest{
		CommonCreateRequestRequest: &router.CommonCreateRequestRequest{
			Audience:   []string{"mario"},
			IssuerDID:  issuerDID.DID.ID,
			IssuerKID:  kid,
			Expiration: "",
		},
		CredentialManifestID: credentialManifest.ID,
	}
}

func getValidIssuanceTemplateRequest(m manifest.CredentialManifest, issuerDID *did.CreateDIDResponse,
	createdSchema *schema.CreateSchemaResponse, expiry1 time.Time, expiry2 time.Duration) *issuance.CreateIssuanceTemplateRequest {
	return &issuance.CreateIssuanceTemplateRequest{
		IssuanceTemplate: issuance.Template{
			ID:                 uuid.NewString(),
			CredentialManifest: m.ID,
			Issuer:             issuerDID.DID.ID,
			IssuerKID:          issuerDID.DID.VerificationMethod[0].ID,
			Credentials: []issuance.CredentialTemplate{
				{
					ID:                        "id1",
					Schema:                    createdSchema.ID,
					CredentialInputDescriptor: "test-id",
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
					ID:                        "id2",
					Schema:                    createdSchema.ID,
					CredentialInputDescriptor: "test-id",
					Data: issuance.ClaimTemplates{
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
