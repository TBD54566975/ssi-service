// Package server contains the full set of handler functions and routes
// supported by the http api
package server

import (
	"net/http"
	"os"
	"path"

	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

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
func NewSSIServer(shutdown chan os.Signal, cfg config.SSIServiceConfig) (*SSIServer, error) {
	// creates an HTTP server from the framework, and wrap it to extend it for the SSIS
	middlewares := gin.HandlersChain{
		gin.Recovery(),
		middleware.Errors(),
		middleware.Logger(logrus.StandardLogger()),
		middleware.Metrics(),
	}
	if cfg.Server.EnableAllowAllCORS {
		middlewares = append(middlewares, middleware.CORS())
	}

	// set up engine and middleware
	engine := gin.New()
	engine.Use(middlewares...)

	switch cfg.Server.Environment {
	case config.EnvironmentDev:
		gin.SetMode(gin.DebugMode)
	case config.EnvironmentTest:
		gin.SetMode(gin.TestMode)
	case config.EnvironmentProd:
		gin.SetMode(gin.ReleaseMode)
	}

	httpServer := framework.NewHTTPServer(cfg.Server, engine, shutdown)
	ssi, err := service.InstantiateSSIService(cfg.Services)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "unable to instantiate ssi service")
	}

	// service-level routers
	engine.GET(HealthPrefix, router.Health)
	engine.GET(ReadinessPrefix, router.Readiness(ssi.GetServices()))
	httpServer.Handle(http.MethodGet, SwaggerPrefix, router.Swagger)

	// register all v1 routers
	v1 := engine.Group(V1Prefix)
	if err = DecentralizedIdentityAPI(v1, ssi.DID, ssi.Webhook); err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "unable to instantiate DID API")
	}

	return &SSIServer{
		Server:       httpServer,
		SSIService:   ssi,
		ServerConfig: &cfg.Server,
	}, nil
}

// DecentralizedIdentityAPI registers all HTTP router for the DID Service
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

// SchemaAPI registers all HTTP router for the SchemaID Service
func (s *SSIServer) SchemaAPI(service svcframework.Service, webhookService *webhook.Service) (err error) {
	schemaRouter, err := router.NewSchemaRouter(service)
	if err != nil {
		return sdkutil.LoggingErrorMsg(err, "creating schema router")
	}

	handlerPath := V1Prefix + SchemasPrefix

	s.Handle(http.MethodPut, handlerPath, schemaRouter.CreateSchema, middleware.Webhook(webhookService, webhook.Schema, webhook.Create))
	s.Handle(http.MethodGet, path.Join(handlerPath, "/:id"), schemaRouter.GetSchema)
	s.Handle(http.MethodGet, handlerPath, schemaRouter.GetSchemas)
	s.Handle(http.MethodPut, path.Join(handlerPath, VerificationPath), schemaRouter.VerifySchema)
	s.Handle(http.MethodDelete, path.Join(handlerPath, "/:id"), schemaRouter.DeleteSchema, middleware.Webhook(webhookService, webhook.Schema, webhook.Delete))
	return
}

func (s *SSIServer) CredentialAPI(service svcframework.Service, webhookService *webhook.Service) (err error) {
	credRouter, err := router.NewCredentialRouter(service)
	if err != nil {
		return sdkutil.LoggingErrorMsg(err, "creating credential router")
	}

	credentialHandlerPath := V1Prefix + CredentialsPrefix
	statusHandlerPath := V1Prefix + CredentialsPrefix + StatusPrefix

	// Credentials
	s.Handle(http.MethodPut, credentialHandlerPath, credRouter.CreateCredential, middleware.Webhook(webhookService, webhook.Credential, webhook.Create))
	s.Handle(http.MethodGet, credentialHandlerPath, credRouter.GetCredentials)
	s.Handle(http.MethodGet, path.Join(credentialHandlerPath, "/:id"), credRouter.GetCredential)
	s.Handle(http.MethodPut, path.Join(credentialHandlerPath, VerificationPath), credRouter.VerifyCredential)
	s.Handle(http.MethodDelete, path.Join(credentialHandlerPath, "/:id"), credRouter.DeleteCredential, middleware.Webhook(webhookService, webhook.Credential, webhook.Delete))

	// Credential Status
	s.Handle(http.MethodGet, path.Join(credentialHandlerPath, "/:id", StatusPrefix), credRouter.GetCredentialStatus)
	s.Handle(http.MethodPut, path.Join(credentialHandlerPath, "/:id", StatusPrefix), credRouter.UpdateCredentialStatus)
	s.Handle(http.MethodGet, path.Join(statusHandlerPath, "/:id"), credRouter.GetCredentialStatusList)
	return
}

func (s *SSIServer) PresentationAPI(service svcframework.Service, webhookService *webhook.Service) (err error) {
	pRouter, err := router.NewPresentationRouter(service)
	if err != nil {
		return sdkutil.LoggingErrorMsg(err, "creating credential router")
	}

	handlerPath := V1Prefix + PresentationsPrefix + DefinitionsPrefix

	s.Handle(http.MethodPut, handlerPath, pRouter.CreateDefinition)
	s.Handle(http.MethodGet, path.Join(handlerPath, "/:id"), pRouter.GetDefinition)
	s.Handle(http.MethodGet, handlerPath, pRouter.ListDefinitions)
	s.Handle(http.MethodDelete, path.Join(handlerPath, "/:id"), pRouter.DeleteDefinition)

	submissionHandlerPath := V1Prefix + PresentationsPrefix + SubmissionsPrefix

	s.Handle(http.MethodPut, submissionHandlerPath, pRouter.CreateSubmission, middleware.Webhook(webhookService, webhook.Submission, webhook.Create))
	s.Handle(http.MethodGet, path.Join(submissionHandlerPath, "/:id"), pRouter.GetSubmission)
	s.Handle(http.MethodGet, submissionHandlerPath, pRouter.ListSubmissions)
	s.Handle(http.MethodPut, path.Join(submissionHandlerPath, "/:id", "/review"), pRouter.ReviewSubmission)
	return
}

func (s *SSIServer) KeyStoreAPI(service svcframework.Service) (err error) {
	keyStoreRouter, err := router.NewKeyStoreRouter(service)
	if err != nil {
		return sdkutil.LoggingErrorMsg(err, "creating key store router")
	}

	handlerPath := V1Prefix + KeyStorePrefix

	s.Handle(http.MethodPut, handlerPath, keyStoreRouter.StoreKey)
	s.Handle(http.MethodGet, path.Join(handlerPath, "/:id"), keyStoreRouter.GetKeyDetails)
	return
}

func (s *SSIServer) OperationAPI(service svcframework.Service) (err error) {
	operationRouter, err := router.NewOperationRouter(service)
	if err != nil {
		return sdkutil.LoggingErrorMsg(err, "creating operation router")
	}

	handlerPath := V1Prefix + OperationPrefix

	s.Handle(http.MethodGet, handlerPath, operationRouter.GetOperations)
	// In this case, it's used so that the operation id matches `presentations/submissions/{submission_id}` for the DIDWebID
	// path	`/v1/operations/cancel/presentations/submissions/{id}`
	s.Handle(http.MethodPut, path.Join(handlerPath, "/cancel/*id"), operationRouter.CancelOperation)
	s.Handle(http.MethodGet, path.Join(handlerPath, "/*id"), operationRouter.GetOperation)

	return
}

func (s *SSIServer) ManifestAPI(service svcframework.Service, webhookService *webhook.Service) (err error) {
	manifestRouter, err := router.NewManifestRouter(service)
	if err != nil {
		return sdkutil.LoggingErrorMsg(err, "creating manifest router")
	}

	manifestHandlerPath := V1Prefix + ManifestsPrefix
	applicationsHandlerPath := V1Prefix + ManifestsPrefix + ApplicationsPrefix
	responsesHandlerPath := V1Prefix + ManifestsPrefix + ResponsesPrefix

	s.Handle(http.MethodPut, manifestHandlerPath, manifestRouter.CreateManifest, middleware.Webhook(webhookService, webhook.Manifest, webhook.Create))

	s.Handle(http.MethodGet, manifestHandlerPath, manifestRouter.GetManifests)
	s.Handle(http.MethodGet, path.Join(manifestHandlerPath, "/:id"), manifestRouter.GetManifest)
	s.Handle(http.MethodDelete, path.Join(manifestHandlerPath, "/:id"), manifestRouter.DeleteManifest, middleware.Webhook(webhookService, webhook.Manifest, webhook.Delete))

	s.Handle(http.MethodPut, applicationsHandlerPath, manifestRouter.SubmitApplication, middleware.Webhook(webhookService, webhook.Application, webhook.Create))
	s.Handle(http.MethodGet, applicationsHandlerPath, manifestRouter.GetApplications)
	s.Handle(http.MethodGet, path.Join(applicationsHandlerPath, "/:id"), manifestRouter.GetApplication)
	s.Handle(http.MethodDelete, path.Join(applicationsHandlerPath, "/:id"), manifestRouter.DeleteApplication, middleware.Webhook(webhookService, webhook.Application, webhook.Delete))
	s.Handle(http.MethodPut, path.Join(applicationsHandlerPath, "/:id", "/review"), manifestRouter.ReviewApplication)

	s.Handle(http.MethodGet, responsesHandlerPath, manifestRouter.GetResponses)
	s.Handle(http.MethodGet, path.Join(responsesHandlerPath, "/:id"), manifestRouter.GetResponse)
	s.Handle(http.MethodDelete, path.Join(responsesHandlerPath, "/:id"), manifestRouter.DeleteResponse)
	return
}

func (s *SSIServer) IssuanceAPI(service svcframework.Service) error {
	issuanceRouter, err := router.NewIssuanceRouter(service)
	if err != nil {
		return sdkutil.LoggingErrorMsg(err, "creating issuance router")
	}

	issuanceHandlerPath := V1Prefix + IssuanceTemplatePrefix
	s.Handle(http.MethodPut, issuanceHandlerPath, issuanceRouter.CreateIssuanceTemplate)
	s.Handle(http.MethodGet, issuanceHandlerPath, issuanceRouter.ListIssuanceTemplates)
	s.Handle(http.MethodGet, path.Join(issuanceHandlerPath, "/:id"), issuanceRouter.GetIssuanceTemplate)
	s.Handle(http.MethodDelete, path.Join(issuanceHandlerPath, "/:id"), issuanceRouter.DeleteIssuanceTemplate)
	return nil
}

func (s *SSIServer) WebhookAPI(service svcframework.Service) (err error) {
	webhookRouter, err := router.NewWebhookRouter(service)
	if err != nil {
		return sdkutil.LoggingErrorMsg(err, "creating webhook router")
	}

	handlerPath := V1Prefix + WebhookPrefix
	s.Handle(http.MethodPut, handlerPath, webhookRouter.CreateWebhook)
	s.Handle(http.MethodGet, path.Join(handlerPath, "/:noun/:verb"), webhookRouter.GetWebhook)
	s.Handle(http.MethodGet, handlerPath, webhookRouter.GetWebhooks)
	s.Handle(http.MethodDelete, handlerPath, webhookRouter.DeleteWebhook)

	s.Handle(http.MethodGet, path.Join(handlerPath, "nouns"), webhookRouter.GetSupportedNouns)
	s.Handle(http.MethodGet, path.Join(handlerPath, "verbs"), webhookRouter.GetSupportedVerbs)
	return
}
