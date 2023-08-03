package server

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	manifestsdk "github.com/TBD54566975/ssi-sdk/credential/manifest"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/gin-gonic/gin"
	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tbd54566975/ssi-service/config"
	credmodel "github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/service/credential"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/issuance"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	"github.com/tbd54566975/ssi-service/pkg/service/manifest"
	"github.com/tbd54566975/ssi-service/pkg/service/manifest/model"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
	"github.com/tbd54566975/ssi-service/pkg/service/webhook"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"github.com/tbd54566975/ssi-service/pkg/testutil"
)

const (
	testIONResolverURL = "https://test-ion-resolver.com"
	testServerURL      = "https://ssi-service.com"
)

func TestMain(t *testing.M) {
	testutil.EnableSchemaCaching()
	config.SetAPIBase(testServerURL)
	os.Exit(t.Run())
}

func TestHealthCheckAPI(t *testing.T) {
	shutdown := make(chan os.Signal, 1)
	serviceConfig, err := config.LoadConfig("", nil)
	assert.NoError(t, err)
	server, err := NewSSIServer(shutdown, *serviceConfig)
	assert.NoError(t, err)
	assert.NotEmpty(t, server)

	req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/health", nil)
	w := httptest.NewRecorder()

	c := newRequestContext(w, req)
	router.Health(c)
	assert.True(t, util.Is2xxResponse(w.Code))

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
	serviceConfig, err := config.LoadConfig("", nil)
	assert.NoError(t, err)
	serviceConfig.Services.StorageOptions = []storage.Option{
		{
			ID:     storage.BoltDBFilePathOption,
			Option: dbFile,
		},
	}

	server, err := NewSSIServer(shutdown, *serviceConfig)
	assert.NoError(t, err)
	assert.NotEmpty(t, server)

	req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/readiness", nil)
	w := httptest.NewRecorder()

	handler := router.Readiness(nil)
	c := newRequestContext(w, req)
	handler(c)
	assert.True(t, util.Is2xxResponse(w.Code))

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
func newRequestContext(w http.ResponseWriter, req *http.Request) *gin.Context {
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	return c
}

// construct a context value with query params as expected by our handler
func newRequestContextWithParams(w http.ResponseWriter, req *http.Request, params map[string]string) *gin.Context {
	c := newRequestContext(w, req)
	for k, v := range params {
		c.AddParam(k, v)
	}
	return c
}

func getValidCreateManifestRequest(issuerDID, verificationMethodID, schemaID string) router.CreateManifestRequest {
	return router.CreateManifestRequest{
		IssuerDID:            issuerDID,
		VerificationMethodID: verificationMethodID,
		ClaimFormat: &exchange.ClaimFormat{
			JWTVC: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
		},
		PresentationDefinitionRef: &model.PresentationDefinitionRef{
			PresentationDefinition: &exchange.PresentationDefinition{
				ID: "valid-license-application",
				InputDescriptors: []exchange.InputDescriptor{
					{
						ID: "license-type",
						Constraints: &exchange.Constraints{
							Fields: []exchange.Field{
								{
									Path: []string{"$.vc.credentialSubject.licenseType"},
									Filter: &exchange.Filter{
										Type:    "string",
										Pattern: "Class D|Class M|Class V",
									},
								},
							},
						},
					},
				},
			},
		},
		OutputDescriptors: []manifestsdk.OutputDescriptor{
			{
				ID:          "drivers-license-ca",
				Schema:      schemaID,
				Name:        "drivers license CA",
				Description: "license for CA",
			},
			{
				ID:          "drivers-license-ny",
				Schema:      schemaID,
				Name:        "drivers license NY",
				Description: "license for NY",
			},
		},
	}
}

func getValidApplicationRequest(manifestID, presDefID, submissionDescriptorID string, credentials []credmodel.Container) manifestsdk.CredentialApplicationWrapper {
	createApplication := manifestsdk.CredentialApplication{
		ID:          uuid.New().String(),
		SpecVersion: manifestsdk.SpecVersion,
		Applicant:   "did:example:123",
		ManifestID:  manifestID,
		Format: &exchange.ClaimFormat{
			JWTVC: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
		},
		PresentationSubmission: &exchange.PresentationSubmission{
			ID:           "license-application-submission",
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

func testKeyStore(t *testing.T, bolt storage.ServiceStorage) (*router.KeyStoreRouter, *keystore.Service, keystore.ServiceFactory) {
	keyStoreService, keyStoreServiceFactory := testKeyStoreService(t, bolt)

	// create router for service
	keyStoreRouter, err := router.NewKeyStoreRouter(keyStoreService)
	require.NoError(t, err)
	require.NotEmpty(t, keyStoreRouter)

	return keyStoreRouter, keyStoreService, keyStoreServiceFactory
}

func testKeyStoreService(t *testing.T, db storage.ServiceStorage) (*keystore.Service, keystore.ServiceFactory) {
	serviceConfig := new(config.KeyStoreServiceConfig)

	// create a keystore service
	encrypter, decrypter, err := keystore.NewServiceEncryption(db, serviceConfig.EncryptionConfig, keystore.ServiceKeyEncryptionKey)
	require.NoError(t, err)
	factory := keystore.NewKeyStoreServiceFactory(*serviceConfig, db, encrypter, decrypter)
	keystoreService, err := factory(db)
	require.NoError(t, err)
	require.NotEmpty(t, keystoreService)
	return keystoreService, factory
}

func testIssuanceService(t *testing.T, db storage.ServiceStorage) *issuance.Service {
	s, err := issuance.NewIssuanceService(db)
	require.NoError(t, err)
	require.NotEmpty(t, s)
	return s
}

func testDIDService(t *testing.T, bolt storage.ServiceStorage, keyStore *keystore.Service, factory keystore.ServiceFactory, methods ...string) (*did.Service, *did.BatchService) {
	if methods == nil {
		methods = []string{"key"}
	}
	serviceConfig := config.DIDServiceConfig{
		Methods:                methods,
		LocalResolutionMethods: []string{"key", "web", "peer", "pkh"},
		IONResolverURL:         testIONResolverURL,
		BatchCreateMaxItems:    100,
	}

	// create a did service
	didService, err := did.NewDIDService(serviceConfig, bolt, keyStore, factory)
	require.NoError(t, err)
	require.NotEmpty(t, didService)

	batchDIDService, err := did.NewBatchDIDService(serviceConfig, bolt, factory)
	require.NoError(t, err)
	return didService, batchDIDService
}

func testDIDRouter(t *testing.T, bolt storage.ServiceStorage, keyStore *keystore.Service, methods []string, factory keystore.ServiceFactory) (*router.DIDRouter, *router.BatchDIDRouter) {
	didService, batchDIDService := testDIDService(t, bolt, keyStore, factory, methods...)

	// create router for service
	didRouter, err := router.NewDIDRouter(didService)
	require.NoError(t, err)
	require.NotEmpty(t, didRouter)

	batchDIDRouter := router.NewBatchDIDRouter(batchDIDService)
	return didRouter, batchDIDRouter
}

func testSchemaService(t *testing.T, bolt storage.ServiceStorage, keyStore *keystore.Service, did *did.Service) *schema.Service {
	schemaService, err := schema.NewSchemaService(bolt, keyStore, did.GetResolver())
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
	serviceConfig := config.CredentialServiceConfig{BatchCreateMaxItems: 1000}

	// create a credential service
	credentialService, err := credential.NewCredentialService(serviceConfig, db, keyStore, did.GetResolver(), schema)
	require.NoError(t, err)
	require.NotEmpty(t, credentialService)
	return credentialService
}

func testCredentialRouter(t *testing.T, bolt storage.ServiceStorage, keyStore *keystore.Service, did *did.Service, schema *schema.Service) *router.CredentialRouter {
	credentialService := testCredentialService(t, bolt, keyStore, did, schema)

	// set endpoint in service info
	config.SetServicePath(svcframework.Credential, CredentialsPrefix)

	// create router for service
	credentialRouter, err := router.NewCredentialRouter(credentialService)
	require.NoError(t, err)
	require.NotEmpty(t, credentialRouter)

	return credentialRouter
}

func testManifest(t *testing.T, db storage.ServiceStorage, keyStore *keystore.Service, did *did.Service, credential *credential.Service) (*router.ManifestRouter, *manifest.Service) {
	// create a manifest service
	manifestService, err := manifest.NewManifestService(db, keyStore, did.GetResolver(), credential, nil)
	require.NoError(t, err)
	require.NotEmpty(t, manifestService)

	// create router for service
	manifestRouter, err := router.NewManifestRouter(manifestService)
	require.NoError(t, err)
	require.NotEmpty(t, manifestRouter)

	return manifestRouter, manifestService
}

func testWebhookService(t *testing.T, bolt storage.ServiceStorage) *webhook.Service {
	serviceConfig := config.WebhookServiceConfig{WebhookTimeout: "10s"}

	// create a webhook service
	webhookService, err := webhook.NewWebhookService(serviceConfig, bolt)
	require.NoError(t, err)
	require.NotEmpty(t, webhookService)
	return webhookService
}

func testWebhookRouter(t *testing.T, bolt storage.ServiceStorage) *router.WebhookRouter {
	webhookService := testWebhookService(t, bolt)

	// create router for service
	webhookRouter, err := router.NewWebhookRouter(webhookService)
	require.NoError(t, err)
	require.NotEmpty(t, webhookRouter)

	return webhookRouter
}

func idFromURI(id string) string {
	return id[len(id)-36:]
}
