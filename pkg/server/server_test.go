package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"

	"github.com/tbd54566975/ssi-service/pkg/service/dwn"

	manifestsdk "github.com/TBD54566975/ssi-sdk/credential/manifest"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/dimfeld/httptreemux/v5"
	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/service/credential"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	"github.com/tbd54566975/ssi-service/pkg/service/manifest"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

func TestHealthCheckAPI(t *testing.T) {
	// remove the db file after the test
	t.Cleanup(func() {
		_ = os.Remove(storage.DBFile)
	})

	shutdown := make(chan os.Signal, 1)
	serviceConfig, err := config.LoadConfig("")
	assert.NoError(t, err)
	server, err := NewSSIServer(shutdown, *serviceConfig)
	assert.NoError(t, err)
	assert.NotEmpty(t, server)

	req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/health", nil)
	w := httptest.NewRecorder()

	err = router.Health(context.TODO(), w, req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, w.Result().StatusCode)

	var resp router.GetHealthCheckResponse
	err = json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)

	assert.Equal(t, router.HealthOK, resp.Status)
}

func TestReadinessAPI(t *testing.T) {
	// remove the db file after the test
	t.Cleanup(func() {
		_ = os.Remove(storage.DBFile)
	})

	shutdown := make(chan os.Signal, 1)
	serviceConfig, err := config.LoadConfig("")
	assert.NoError(t, err)

	server, err := NewSSIServer(shutdown, *serviceConfig)
	assert.NoError(t, err)
	assert.NotEmpty(t, server)

	req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/readiness", nil)
	w := httptest.NewRecorder()

	handler := router.Readiness(nil)
	err = handler(newRequestContext(), w, req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, w.Result().StatusCode)

	var resp router.GetReadinessResponse
	err = json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)

	assert.Equal(t, svcframework.StatusReady, resp.Status.Status)
	assert.Len(t, resp.ServiceStatuses, 0)
}

func newRequestValue(t *testing.T, data interface{}) io.Reader {
	dataBytes, err := json.Marshal(data)
	require.NoError(t, err)
	require.NotEmpty(t, dataBytes)
	return bytes.NewReader(dataBytes)
}

// construct a context value as expected by our handler
func newRequestContext() context.Context {
	return context.WithValue(context.Background(), framework.KeyRequestState, &framework.RequestState{
		TraceID:    uuid.New().String(),
		Now:        time.Now(),
		StatusCode: 1,
	})
}

// as required by https://github.com/dimfeld/httptreemux's context handler
func newRequestContextWithParams(params map[string]string) context.Context {
	ctx := context.WithValue(context.Background(), framework.KeyRequestState, &framework.RequestState{
		TraceID:    uuid.New().String(),
		Now:        time.Now(),
		StatusCode: 1,
	})
	return httptreemux.AddParamsToContext(ctx, params)
}

func getValidManifestRequest(issuer string) manifest.CreateManifestRequest {
	createManifestRequest := manifest.CreateManifestRequest{
		Manifest: manifestsdk.CredentialManifest{
			ID:          "WA-DL-CLASS-A",
			SpecVersion: "https://identity.foundation/credential-manifest/spec/v1.0.0/",
			Issuer: manifestsdk.Issuer{
				ID: issuer,
			},
			PresentationDefinition: &exchange.PresentationDefinition{
				ID: "pres-def-id",
				InputDescriptors: []exchange.InputDescriptor{
					{
						ID: "test-id",
						Constraints: &exchange.Constraints{
							Fields: []exchange.Field{
								{
									Path: []string{".vc.id"},
								},
							},
						},
					},
				},
			},
			OutputDescriptors: []manifestsdk.OutputDescriptor{
				{
					ID:          "id1",
					Schema:      "https://test.com/schema",
					Name:        "good ID",
					Description: "it's all good",
				},
				{
					ID:          "id2",
					Schema:      "https://test.com/schema",
					Name:        "good ID",
					Description: "it's all good",
				},
			},
		},
	}

	return createManifestRequest
}

func getValidApplicationRequest(applicantDID, manifestID, submissionDescriptorID string) manifest.SubmitApplicationRequest {
	createApplication := manifestsdk.CredentialApplication{
		ID:          uuid.New().String(),
		SpecVersion: "https://identity.foundation/credential-manifest/spec/v1.0.0/",
		ManifestID:  manifestID,
		Format: &exchange.ClaimFormat{
			JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
		},
		PresentationSubmission: &exchange.PresentationSubmission{
			ID:           "psid",
			DefinitionID: "definitionId",
			DescriptorMap: []exchange.SubmissionDescriptor{
				{
					ID:     submissionDescriptorID,
					Format: "jwt",
					Path:   "path",
				},
			},
		},
	}

	createApplicationRequest := manifest.SubmitApplicationRequest{
		Application:  createApplication,
		ApplicantDID: applicantDID,
	}

	return createApplicationRequest
}

func testKeyStore(t *testing.T, bolt *storage.BoltDB) (*router.KeyStoreRouter, *keystore.Service) {
	keyStoreService := testKeyStoreService(t, bolt)

	// create router for service
	keyStoreRouter, err := router.NewKeyStoreRouter(keyStoreService)
	require.NoError(t, err)
	require.NotEmpty(t, keyStoreRouter)

	return keyStoreRouter, keyStoreService
}

func testKeyStoreService(t *testing.T, db *storage.BoltDB) *keystore.Service {
	serviceConfig := config.KeyStoreServiceConfig{
		BaseServiceConfig:  &config.BaseServiceConfig{Name: "test-keystore"},
		ServiceKeyPassword: "test-password",
	}

	// create a keystore service
	keystoreService, err := keystore.NewKeyStoreService(serviceConfig, db)
	require.NoError(t, err)
	require.NotEmpty(t, keystoreService)
	return keystoreService
}

func testDIDService(t *testing.T, bolt *storage.BoltDB, keyStore *keystore.Service) *did.Service {
	serviceConfig := config.DIDServiceConfig{
		BaseServiceConfig: &config.BaseServiceConfig{Name: "test-did"},
		Methods:           []string{"key"},
	}

	// create a did service
	didService, err := did.NewDIDService(serviceConfig, bolt, keyStore)
	require.NoError(t, err)
	require.NotEmpty(t, didService)
	return didService
}

func testDIDRouter(t *testing.T, bolt *storage.BoltDB, keyStore *keystore.Service) *router.DIDRouter {
	didService := testDIDService(t, bolt, keyStore)

	// create router for service
	didRouter, err := router.NewDIDRouter(didService)
	require.NoError(t, err)
	require.NotEmpty(t, didRouter)
	return didRouter
}

func testSchemaService(t *testing.T, bolt *storage.BoltDB, keyStore *keystore.Service) *schema.Service {
	schemaService, err := schema.NewSchemaService(config.SchemaServiceConfig{BaseServiceConfig: &config.BaseServiceConfig{Name: "test-schema"}}, bolt, keyStore)
	require.NoError(t, err)
	require.NotEmpty(t, schemaService)
	return schemaService
}

func testSchemaRouter(t *testing.T, bolt *storage.BoltDB, keyStore *keystore.Service) *router.SchemaRouter {
	schemaService := testSchemaService(t, bolt, keyStore)

	// create router for service
	schemaRouter, err := router.NewSchemaRouter(schemaService)
	require.NoError(t, err)
	require.NotEmpty(t, schemaRouter)
	return schemaRouter
}

func testCredentialService(t *testing.T, db *storage.BoltDB, keyStore *keystore.Service, did *did.Service) *credential.Service {
	serviceConfig := config.CredentialServiceConfig{BaseServiceConfig: &config.BaseServiceConfig{Name: "credential"}}

	// create a credential service
	credentialService, err := credential.NewCredentialService(serviceConfig, db, keyStore, did.GetResolver())
	require.NoError(t, err)
	require.NotEmpty(t, credentialService)
	return credentialService
}

func testCredentialRouter(t *testing.T, bolt *storage.BoltDB, keyStore *keystore.Service, did *did.Service) *router.CredentialRouter {
	credentialService := testCredentialService(t, bolt, keyStore, did)

	// create router for service
	credentialRouter, err := router.NewCredentialRouter(credentialService)
	require.NoError(t, err)
	require.NotEmpty(t, credentialRouter)

	return credentialRouter
}

func testManifest(t *testing.T, db *storage.BoltDB, keyStore *keystore.Service, credential *credential.Service) (*router.ManifestRouter, *manifest.Service) {
	serviceConfig := config.ManifestServiceConfig{BaseServiceConfig: &config.BaseServiceConfig{Name: "manifest"}}
	// create a manifest service
	manifestService, err := manifest.NewManifestService(serviceConfig, db, keyStore, credential)
	require.NoError(t, err)
	require.NotEmpty(t, manifestService)

	// create router for service
	manifestRouter, err := router.NewManifestRouter(manifestService)
	require.NoError(t, err)
	require.NotEmpty(t, manifestRouter)

	return manifestRouter, manifestService
}

func testDWNRouter(t *testing.T, bolt *storage.BoltDB, keyStore *keystore.Service, manifest *manifest.Service) *router.DWNRouter {
	dwnService, err := dwn.NewDWNService(config.DWNServiceConfig{BaseServiceConfig: &config.BaseServiceConfig{Name: "test-dwn"}, DWNEndpoint: "test-endpoint"}, bolt, keyStore, manifest)
	require.NoError(t, err)
	require.NotEmpty(t, dwnService)

	// create router for service
	dwnRouter, err := router.NewDWNRouter(dwnService)
	require.NoError(t, err)
	require.NotEmpty(t, dwnRouter)

	return dwnRouter
}
