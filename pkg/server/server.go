// Package server contains the full set of handler functions and routes
// supported by the http api
package server

import (
	"io"
	"os"

	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/gin-gonic/gin"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	"github.com/tbd54566975/ssi-service/pkg/server/middleware"
	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/service"
	didsvc "github.com/tbd54566975/ssi-service/pkg/service/did"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/webhook"
)

const (
	HealthPrefix           = "/health"
	ReadinessPrefix        = "/readiness"
	SwaggerPrefix          = "/swagger/*any"
	V1Prefix               = "/v1"
	OperationPrefix        = "/operations"
	DIDsPrefix             = "/dids"
	ResolverPrefix         = "/resolver"
	SchemasPrefix          = "/schemas"
	CredentialsPrefix      = "/credentials"
	StatusPrefix           = "/status"
	PresentationsPrefix    = "/presentations"
	DefinitionsPrefix      = "/definitions"
	SubmissionsPrefix      = "/submissions"
	IssuanceTemplatePrefix = "/issuancetemplates"
	ManifestsPrefix        = "/manifests"
	ApplicationsPrefix     = "/applications"
	ResponsesPrefix        = "/responses"
	KeyStorePrefix         = "/keys"
	VerificationPath       = "/verification"
	WebhookPrefix          = "/webhooks"
)

// SSIServer exposes all dependencies needed to run a http server and all its services
type SSIServer struct {
	*config.ServerConfig
	*service.SSIService
	*framework.Server
}

// NewSSIServer does two things: instantiates all service and registers their HTTP bindings
func NewSSIServer(shutdown chan os.Signal, logFile *os.File, cfg config.SSIServiceConfig) (*SSIServer, error) {
	// creates an HTTP server from the framework, and wrap it to extend it for the SSIS
	engine := setUpEngine(cfg.Server, logFile, shutdown)
	httpServer := framework.NewServer(cfg.Server, engine, shutdown)
	ssi, err := service.InstantiateSSIService(cfg.Services)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "unable to instantiate ssi service")
	}

	// service-level routers
	engine.GET(HealthPrefix, router.Health)
	engine.GET(ReadinessPrefix, router.Readiness(ssi.GetServices()))
	engine.GET(SwaggerPrefix, router.Swagger)

	// register all v1 routers
	v1 := engine.Group(V1Prefix)
	if err = DecentralizedIdentityAPI(v1, ssi.DID, ssi.Webhook); err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "unable to instantiate DID API")
	}
	if err = SchemaAPI(v1, ssi.Schema, ssi.Webhook); err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "unable to instantiate Schema API")
	}
	if err = CredentialAPI(v1, ssi.Credential, ssi.Webhook); err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "unable to instantiate Credential API")
	}
	if err = PresentationAPI(v1, ssi.Presentation, ssi.Webhook); err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "unable to instantiate Presentation API")
	}
	if err = KeyStoreAPI(v1, ssi.KeyStore); err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "unable to instantiate KeyStore API")
	}
	if err = OperationAPI(v1, ssi.Operation); err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "unable to instantiate Operation API")
	}
	if err = ManifestAPI(v1, ssi.Manifest, ssi.Webhook); err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "unable to instantiate Manifest API")
	}
	if err = IssuanceAPI(v1, ssi.Issuance); err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "unable to instantiate Issuance API")
	}
	if err = WebhookAPI(v1, ssi.Webhook); err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "unable to instantiate Webhook API")
	}

	return &SSIServer{
		Server:       httpServer,
		SSIService:   ssi,
		ServerConfig: &cfg.Server,
	}, nil
}

// setUpEngine creates the gin engine and sets up the middleware based on config
func setUpEngine(cfg config.ServerConfig, logFile *os.File, shutdown chan os.Signal) *gin.Engine {
	gin.ForceConsoleColor()
	gin.DefaultWriter = io.MultiWriter(os.Stdout, logFile)
	middlewares := gin.HandlersChain{
		gin.Recovery(),
		middleware.Errors(shutdown),
		// middleware.Logger(logrus.StandardLogger()),
		middleware.Metrics(),
	}
	if cfg.EnableAllowAllCORS {
		middlewares = append(middlewares, middleware.CORS())
	}

	// set up engine and middleware
	engine := gin.New()
	engine.Use(middlewares...)
	switch cfg.Environment {
	case config.EnvironmentDev:
		gin.SetMode(gin.DebugMode)
	case config.EnvironmentTest:
		gin.SetMode(gin.TestMode)
	case config.EnvironmentProd:
		gin.SetMode(gin.ReleaseMode)
	}
	return engine
}

// DecentralizedIdentityAPI registers all HTTP handlers for the DID Service
func DecentralizedIdentityAPI(rg *gin.RouterGroup, service *didsvc.Service, webhookService *webhook.Service) (err error) {
	didRouter, err := router.NewDIDRouter(service)
	if err != nil {
		return sdkutil.LoggingErrorMsg(err, "creating DID router")
	}

	didAPI := rg.Group(DIDsPrefix)
	didAPI.GET("", didRouter.GetDIDMethods)
	didAPI.PUT("/:method", didRouter.CreateDIDByMethod, middleware.Webhook(webhookService, webhook.DID, webhook.Create))
	didAPI.GET("/:method", didRouter.GetDIDsByMethod)
	didAPI.GET("/:method/:id", didRouter.GetDIDByMethod)
	didAPI.DELETE("/:method/:id", didRouter.SoftDeleteDIDByMethod)
	didAPI.GET(ResolverPrefix+"/:id", didRouter.ResolveDID)
	return
}

// SchemaAPI registers all HTTP handlers for the Schema Service
func SchemaAPI(rg *gin.RouterGroup, service svcframework.Service, webhookService *webhook.Service) (err error) {
	schemaRouter, err := router.NewSchemaRouter(service)
	if err != nil {
		return sdkutil.LoggingErrorMsg(err, "creating schema router")
	}

	schemaAPI := rg.Group(SchemasPrefix)
	schemaAPI.PUT("", schemaRouter.CreateSchema, middleware.Webhook(webhookService, webhook.Schema, webhook.Create))
	schemaAPI.GET("/:id", schemaRouter.GetSchema)
	schemaAPI.GET("", schemaRouter.GetSchemas)
	schemaAPI.PUT(VerificationPath, schemaRouter.VerifySchema)
	schemaAPI.DELETE("/:id", schemaRouter.DeleteSchema, middleware.Webhook(webhookService, webhook.Schema, webhook.Delete))
	return
}

// CredentialAPI registers all HTTP handlers for the Credentials Service
func CredentialAPI(rg *gin.RouterGroup, service svcframework.Service, webhookService *webhook.Service) (err error) {
	credRouter, err := router.NewCredentialRouter(service)
	if err != nil {
		return sdkutil.LoggingErrorMsg(err, "creating credential router")
	}

	// Credentials
	credentialAPI := rg.Group(CredentialsPrefix)
	credentialAPI.PUT("", credRouter.CreateCredential, middleware.Webhook(webhookService, webhook.Credential, webhook.Create))
	credentialAPI.GET("", credRouter.GetCredentials)
	credentialAPI.GET("/:id", credRouter.GetCredential)
	credentialAPI.PUT(VerificationPath, credRouter.VerifyCredential)
	credentialAPI.DELETE("/:id", credRouter.DeleteCredential, middleware.Webhook(webhookService, webhook.Credential, webhook.Delete))

	// Credential Status
	credentialAPI.GET("/:id"+StatusPrefix, credRouter.GetCredentialStatus)
	credentialAPI.PUT("/:id"+StatusPrefix, credRouter.UpdateCredentialStatus)
	credentialAPI.GET(StatusPrefix+"/:id", credRouter.GetCredentialStatusList)
	return
}

// PresentationAPI registers all HTTP handlers for the Presentation Service
func PresentationAPI(rg *gin.RouterGroup, service svcframework.Service, webhookService *webhook.Service) (err error) {
	presRouter, err := router.NewPresentationRouter(service)
	if err != nil {
		return sdkutil.LoggingErrorMsg(err, "creating credential router")
	}

	presDefAPI := rg.Group(PresentationsPrefix + DefinitionsPrefix)
	presDefAPI.PUT("", presRouter.CreateDefinition)
	presDefAPI.GET("/:id", presRouter.GetDefinition)
	presDefAPI.GET("", presRouter.ListDefinitions)
	presDefAPI.DELETE("/:id", presRouter.DeleteDefinition)

	presSubAPI := rg.Group(PresentationsPrefix + SubmissionsPrefix)
	presSubAPI.PUT("", presRouter.CreateSubmission, middleware.Webhook(webhookService, webhook.Submission, webhook.Create))
	presSubAPI.GET("/:id", presRouter.GetSubmission)
	presSubAPI.GET("", presRouter.ListSubmissions)
	presSubAPI.PUT("/:id/review", presRouter.ReviewSubmission)
	return
}

// KeyStoreAPI registers all HTTP handlers for the Key Store Service
func KeyStoreAPI(rg *gin.RouterGroup, service svcframework.Service) (err error) {
	keyStoreRouter, err := router.NewKeyStoreRouter(service)
	if err != nil {
		return sdkutil.LoggingErrorMsg(err, "creating key store router")
	}

	keyStoreAPI := rg.Group(KeyStorePrefix)
	keyStoreAPI.PUT("", keyStoreRouter.StoreKey)
	keyStoreAPI.GET("/:id", keyStoreRouter.GetKeyDetails)
	return
}

// OperationAPI registers all HTTP handlers for the Operations Service
func OperationAPI(rg *gin.RouterGroup, service svcframework.Service) (err error) {
	operationRouter, err := router.NewOperationRouter(service)
	if err != nil {
		return sdkutil.LoggingErrorMsg(err, "creating operation router")
	}

	operationAPI := rg.Group(OperationPrefix)
	operationAPI.GET("", operationRouter.GetOperations)
	// In this case, it's used so that the operation id matches `presentations/submissions/{submission_id}` for the DIDWebID
	// path	`/v1/operations/cancel/presentations/submissions/{id}`
	operationAPI.PUT("/cancel/*id", operationRouter.CancelOperation)
	operationAPI.GET("/:id", operationRouter.GetOperation)
	return
}

// ManifestAPI registers all HTTP handlers for the Manifest Service
func ManifestAPI(rg *gin.RouterGroup, service svcframework.Service, webhookService *webhook.Service) (err error) {
	manifestRouter, err := router.NewManifestRouter(service)
	if err != nil {
		return sdkutil.LoggingErrorMsg(err, "creating manifest router")
	}

	manifestAPI := rg.Group(ManifestsPrefix)
	manifestAPI.PUT("", manifestRouter.CreateManifest, middleware.Webhook(webhookService, webhook.Manifest, webhook.Create))
	manifestAPI.GET("", manifestRouter.GetManifests)
	manifestAPI.GET("/:id", manifestRouter.GetManifest)
	manifestAPI.DELETE("/:id", manifestRouter.DeleteManifest, middleware.Webhook(webhookService, webhook.Manifest, webhook.Delete))

	applicationAPI := manifestAPI.Group(ApplicationsPrefix)
	applicationAPI.PUT("", manifestRouter.SubmitApplication, middleware.Webhook(webhookService, webhook.Application, webhook.Create))
	applicationAPI.GET("", manifestRouter.GetApplications)
	applicationAPI.GET("/:id", manifestRouter.GetApplication)
	applicationAPI.DELETE("/:id", manifestRouter.DeleteApplication, middleware.Webhook(webhookService, webhook.Application, webhook.Delete))
	applicationAPI.PUT("/:id/review", manifestRouter.ReviewApplication)

	responseAPI := manifestAPI.Group(ResponsesPrefix)
	responseAPI.GET("", manifestRouter.GetResponses)
	responseAPI.GET("/:id", manifestRouter.GetResponse)
	responseAPI.DELETE("/:id", manifestRouter.DeleteResponse)
	return
}

// IssuanceAPI registers all HTTP handlers for the Issuance Service
func IssuanceAPI(rg *gin.RouterGroup, service svcframework.Service) error {
	issuanceRouter, err := router.NewIssuanceRouter(service)
	if err != nil {
		return sdkutil.LoggingErrorMsg(err, "creating issuance router")
	}

	issuanceAPI := rg.Group(IssuanceTemplatePrefix)
	issuanceAPI.PUT("", issuanceRouter.CreateIssuanceTemplate)
	issuanceAPI.GET("", issuanceRouter.ListIssuanceTemplates)
	issuanceAPI.GET("/:id", issuanceRouter.GetIssuanceTemplate)
	issuanceAPI.DELETE("/:id", issuanceRouter.DeleteIssuanceTemplate)
	return nil
}

// WebhookAPI registers all HTTP handlers for the Webhook Service
func WebhookAPI(rg *gin.RouterGroup, service svcframework.Service) (err error) {
	webhookRouter, err := router.NewWebhookRouter(service)
	if err != nil {
		return sdkutil.LoggingErrorMsg(err, "creating webhook router")
	}

	webhookAPI := rg.Group(WebhookPrefix)
	webhookAPI.PUT("", webhookRouter.CreateWebhook)
	webhookAPI.GET("", webhookRouter.GetWebhooks)
	webhookAPI.GET("/:noun/:verb", webhookRouter.GetWebhook)
	webhookAPI.DELETE("/:noun/:verb", webhookRouter.DeleteWebhook)

	// TODO(gabe): consider refactoring this to a single get on /webhooks/info or similar
	webhookAPI.GET("nouns", webhookRouter.GetSupportedNouns)
	webhookAPI.GET("verbs", webhookRouter.GetSupportedVerbs)
	return
}
