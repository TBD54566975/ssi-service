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
	"github.com/tbd54566975/ssi-service/pkg/testutil"

	manifestsdk "github.com/TBD54566975/ssi-sdk/credential/manifest"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/dimfeld/httptreemux/v5"
	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	credmodel "github.com/tbd54566975/ssi-service/internal/credential"

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

func TestMain(t *testing.M) {
	testutil.EnableSchemaCaching()
	os.Exit(t.Run())
}

func TestHealthCheckAPI(t *testing.T) {
	shutdown := make(chan os.Signal, 1)
	serviceConfig, err := config.LoadConfig("/tmp/test_health_check")
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
	dbFile := "test_readiness_api.db"
	// remove the db file after the test
	t.Cleanup(func() {
		_ = os.Remove(dbFile)
	})

	shutdown := make(chan os.Signal, 1)
	serviceConfig, err := config.LoadConfig("/tmp/test_readiness_api")
	assert.NoError(t, err)
	serviceConfig.Services.StorageOption = dbFile

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

func newRequestValue(t *testing.T, data any) io.Reader {
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

func getValidManifestRequest(issuerDID, schemaID string) manifest.CreateManifestRequest {
	createManifestRequest := manifest.CreateManifestRequest{
		IssuerDID: issuerDID,
		ClaimFormat: &exchange.ClaimFormat{
			JWTVC: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
		},
		PresentationDefinition: &exchange.PresentationDefinition{
			ID: "id123",
			InputDescriptors: []exchange.InputDescriptor{
				{
					ID: "test-id",
					Constraints: &exchange.Constraints{
						Fields: []exchange.Field{
							{
								Path: []string{"$.credentialSubject.licenseType"},
							},
						},
					},
				},
			},
		},
		OutputDescriptors: []manifestsdk.OutputDescriptor{
			{
				ID:          "id1",
				Schema:      schemaID,
				Name:        "good ID",
				Description: "it's all good",
			},
			{
				ID:          "id2",
				Schema:      schemaID,
				Name:        "good ID",
				Description: "it's all good",
			},
		},
	}

	return createManifestRequest
}

func getValidApplicationRequest(manifestID, presDefID, submissionDescriptorID string, credentials []credmodel.Container) manifestsdk.CredentialApplicationWrapper {
	createApplication := manifestsdk.CredentialApplication{
		ID:          uuid.New().String(),
		SpecVersion: manifestsdk.SpecVersion,
		ManifestID:  manifestID,
		Format: &exchange.ClaimFormat{
			JWTVC: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
		},
		PresentationSubmission: &exchange.PresentationSubmission{
			ID:           "psid",
			DefinitionID: presDefID,
			DescriptorMap: []exchange.SubmissionDescriptor{
				{
					ID:     submissionDescriptorID,
					Format: exchange.JWTVC.String(),
					Path:   "$.verifiableCredentials[0]",
				},
			},
		},
	}

	creds := credmodel.ContainersToInterface(credentials)
	return manifestsdk.CredentialApplicationWrapper{
		CredentialApplication: createApplication,
		Credentials:           creds,
	}
}

func testKeyStore(t *testing.T, bolt storage.ServiceStorage) (*router.KeyStoreRouter, *keystore.Service) {
	keyStoreService := testKeyStoreService(t, bolt)

	// create router for service
	keyStoreRouter, err := router.NewKeyStoreRouter(keyStoreService)
	require.NoError(t, err)
	require.NotEmpty(t, keyStoreRouter)

	return keyStoreRouter, keyStoreService
}

func testKeyStoreService(t *testing.T, db storage.ServiceStorage) *keystore.Service {
	serviceConfig := config.KeyStoreServiceConfig{
		BaseServiceConfig:  config.BaseServiceConfig{Name: "test-keystore"},
		ServiceKeyPassword: "test-password",
	}

	// create a keystore service
	keystoreService, err := keystore.NewKeyStoreService(serviceConfig, db)
	require.NoError(t, err)
	require.NotEmpty(t, keystoreService)
	return keystoreService
}

func testDIDService(t *testing.T, bolt storage.ServiceStorage, keyStore *keystore.Service) *did.Service {
	serviceConfig := config.DIDServiceConfig{
		BaseServiceConfig: config.BaseServiceConfig{Name: "test-did"},
		Methods:           []string{"key"},
		ResolutionMethods: []string{"key"},
	}

	// create a did service
	didService, err := did.NewDIDService(serviceConfig, bolt, keyStore)
	require.NoError(t, err)
	require.NotEmpty(t, didService)
	return didService
}

func testDIDRouter(t *testing.T, bolt storage.ServiceStorage, keyStore *keystore.Service) *router.DIDRouter {
	didService := testDIDService(t, bolt, keyStore)

	// create router for service
	didRouter, err := router.NewDIDRouter(didService)
	require.NoError(t, err)
	require.NotEmpty(t, didRouter)
	return didRouter
}

func testSchemaService(t *testing.T, bolt storage.ServiceStorage, keyStore *keystore.Service, did *did.Service) *schema.Service {
	schemaService, err := schema.NewSchemaService(config.SchemaServiceConfig{BaseServiceConfig: config.BaseServiceConfig{Name: "test-schema"}}, bolt, keyStore, did.GetResolver())
	require.NoError(t, err)
	require.NotEmpty(t, schemaService)
	return schemaService
}

func testSchemaRouter(t *testing.T, bolt storage.ServiceStorage, keyStore *keystore.Service, did *did.Service) *router.SchemaRouter {
	schemaService := testSchemaService(t, bolt, keyStore, did)

	// create router for service
	schemaRouter, err := router.NewSchemaRouter(schemaService)
	require.NoError(t, err)
	require.NotEmpty(t, schemaRouter)
	return schemaRouter
}

func testCredentialService(t *testing.T, db storage.ServiceStorage, keyStore *keystore.Service, did *did.Service, schema *schema.Service) *credential.Service {
	serviceConfig := config.CredentialServiceConfig{BaseServiceConfig: config.BaseServiceConfig{Name: "credential"}}

	// create a credential service
	credentialService, err := credential.NewCredentialService(serviceConfig, db, keyStore, did.GetResolver(), schema)
	require.NoError(t, err)
	require.NotEmpty(t, credentialService)
	return credentialService
}

func testCredentialRouter(t *testing.T, bolt storage.ServiceStorage, keyStore *keystore.Service, did *did.Service, schema *schema.Service) *router.CredentialRouter {
	credentialService := testCredentialService(t, bolt, keyStore, did, schema)

	// create router for service
	credentialRouter, err := router.NewCredentialRouter(credentialService)
	require.NoError(t, err)
	require.NotEmpty(t, credentialRouter)

	return credentialRouter
}

func testManifest(t *testing.T, db storage.ServiceStorage, keyStore *keystore.Service, did *did.Service, credential *credential.Service) (*router.ManifestRouter, *manifest.Service) {
	serviceConfig := config.ManifestServiceConfig{BaseServiceConfig: config.BaseServiceConfig{Name: "manifest"}}
	// create a manifest service
	manifestService, err := manifest.NewManifestService(serviceConfig, db, keyStore, did.GetResolver(), credential)
	require.NoError(t, err)
	require.NotEmpty(t, manifestService)

	// create router for service
	manifestRouter, err := router.NewManifestRouter(manifestService)
	require.NoError(t, err)
	require.NotEmpty(t, manifestRouter)

	return manifestRouter, manifestService
}
