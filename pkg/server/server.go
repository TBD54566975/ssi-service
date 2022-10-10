// Package server contains the full set of handler functions and routes
// supported by the http api
package server

import (
	"fmt"
	"net/http"
	"os"
	"path"

	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	"github.com/tbd54566975/ssi-service/pkg/server/middleware"
	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/service"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
)

const (
	HealthPrefix       = "/health"
	ReadinessPrefix    = "/readiness"
	V1Prefix           = "/v1"
	DIDsPrefix         = "/dids"
	SchemasPrefix      = "/schemas"
	CredentialsPrefix  = "/credentials"
	ManifestsPrefix    = "/manifests"
	ApplicationsPrefix = "/applications"
	ResponsesPrefix    = "/responses"
	KeyStorePrefix     = "/keys"
	DWNPrefix          = "/dwn"
	VerificationPath   = "/verification"
)

// SSIServer exposes all dependencies needed to run a http server and all its services
type SSIServer struct {
	*framework.Server
	*config.ServerConfig
	*service.SSIService
}

// NewSSIServer does two things: instantiates all service and registers their HTTP bindings
func NewSSIServer(shutdown chan os.Signal, config config.SSIServiceConfig) (*SSIServer, error) {
	// creates an HTTP server from the framework, and wrap it to extend it for the SSIS
	middlewares := []framework.Middleware{
		middleware.Logger(),
		middleware.Errors(),
		middleware.Metrics(),
		middleware.Panics(),
	}
	httpServer := framework.NewHTTPServer(config.Server, shutdown, middlewares...)
	ssi, err := service.InstantiateSSIService(config.Services)
	if err != nil {
		return nil, err
	}

	// get all instantiated services
	services := ssi.GetServices()

	// service-level routers
	httpServer.Handle(http.MethodGet, HealthPrefix, router.Health)
	httpServer.Handle(http.MethodGet, ReadinessPrefix, router.Readiness(services))

	// create the server instance to be returned
	server := SSIServer{
		Server:       httpServer,
		SSIService:   ssi,
		ServerConfig: &config.Server,
	}

	// start all services and their routers
	logrus.Infof("Starting [%d] service routers...\n", len(services))
	for _, s := range services {
		if err := server.instantiateRouter(s); err != nil {
			logrus.WithError(err).Fatalf("unable to instaniate service router<%s>", s.Type())
			return nil, err
		}
		logrus.Infof("Service router<%s> started successfully", s.Type())
	}

	return &server, nil
}

// instantiateRouter registers the HTTP router for a service with the HTTP server
// NOTE: all service API router must be registered here
func (s *SSIServer) instantiateRouter(service svcframework.Service) error {
	serviceType := service.Type()
	switch serviceType {
	case svcframework.DID:
		return s.DecentralizedIdentityAPI(service)
	case svcframework.Schema:
		return s.SchemaAPI(service)
	case svcframework.Credential:
		return s.CredentialAPI(service)
	case svcframework.KeyStore:
		return s.KeyStoreAPI(service)
	case svcframework.Manifest:
		return s.ManifestAPI(service)
	case svcframework.DWN:
		return s.DWNAPI(service)
	default:
		return fmt.Errorf("could not instantiate API for service: %s", serviceType)
	}
}

// DecentralizedIdentityAPI registers all HTTP router for the DID Service
func (s *SSIServer) DecentralizedIdentityAPI(service svcframework.Service) (err error) {
	didRouter, err := router.NewDIDRouter(service)
	if err != nil {
		return util.LoggingErrorMsg(err, "could not create DID router")
	}

	handlerPath := V1Prefix + DIDsPrefix

	s.Handle(http.MethodGet, handlerPath, didRouter.GetDIDMethods)
	s.Handle(http.MethodPut, path.Join(handlerPath, "/:method"), didRouter.CreateDIDByMethod)
	s.Handle(http.MethodGet, path.Join(handlerPath, "/:method"), didRouter.GetDIDsByMethod)
	s.Handle(http.MethodGet, path.Join(handlerPath, "/:method/:id"), didRouter.GetDIDByMethod)
	return
}

// SchemaAPI registers all HTTP router for the Schema Service
func (s *SSIServer) SchemaAPI(service svcframework.Service) (err error) {
	schemaRouter, err := router.NewSchemaRouter(service)
	if err != nil {
		return util.LoggingErrorMsg(err, "could not create schema router")
	}

	handlerPath := V1Prefix + SchemasPrefix

	s.Handle(http.MethodPut, handlerPath, schemaRouter.CreateSchema)
	s.Handle(http.MethodGet, path.Join(handlerPath, "/:id"), schemaRouter.GetSchema)
	s.Handle(http.MethodGet, handlerPath, schemaRouter.GetSchemas)
	s.Handle(http.MethodPut, path.Join(handlerPath, VerificationPath), schemaRouter.VerifySchema)
	s.Handle(http.MethodDelete, path.Join(handlerPath, "/:id"), schemaRouter.DeleteSchema)
	return
}

func (s *SSIServer) CredentialAPI(service svcframework.Service) (err error) {
	credRouter, err := router.NewCredentialRouter(service)
	if err != nil {
		return util.LoggingErrorMsg(err, "could not create credential router")
	}

	handlerPath := V1Prefix + CredentialsPrefix

	s.Handle(http.MethodPut, handlerPath, credRouter.CreateCredential)
	s.Handle(http.MethodGet, handlerPath, credRouter.GetCredentials)
	s.Handle(http.MethodGet, path.Join(handlerPath, "/:id"), credRouter.GetCredential)
	s.Handle(http.MethodPut, path.Join(handlerPath, VerificationPath), credRouter.VerifyCredential)
	s.Handle(http.MethodDelete, path.Join(handlerPath, "/:id"), credRouter.DeleteCredential)
	return
}

func (s *SSIServer) KeyStoreAPI(service svcframework.Service) (err error) {
	keyStoreRouter, err := router.NewKeyStoreRouter(service)
	if err != nil {
		return util.LoggingErrorMsg(err, "could not create key store router")
	}

	handlerPath := V1Prefix + KeyStorePrefix

	s.Handle(http.MethodPut, handlerPath, keyStoreRouter.StoreKey)
	s.Handle(http.MethodGet, path.Join(handlerPath, "/:id"), keyStoreRouter.GetKeyDetails)
	return
}

func (s *SSIServer) ManifestAPI(service svcframework.Service) (err error) {
	manifestRouter, err := router.NewManifestRouter(service)
	if err != nil {
		return util.LoggingErrorMsg(err, "could not create manifest router")
	}

	manifestHandlerPath := V1Prefix + ManifestsPrefix
	applicationsHandlerPath := V1Prefix + ManifestsPrefix + ApplicationsPrefix
	responsesHandlerPath := V1Prefix + ManifestsPrefix + ResponsesPrefix

	s.Handle(http.MethodPut, manifestHandlerPath, manifestRouter.CreateManifest)

	s.Handle(http.MethodGet, manifestHandlerPath, manifestRouter.GetManifests)
	s.Handle(http.MethodGet, path.Join(manifestHandlerPath, "/:id"), manifestRouter.GetManifest)
	s.Handle(http.MethodDelete, path.Join(manifestHandlerPath, "/:id"), manifestRouter.DeleteManifest)

	s.Handle(http.MethodPut, applicationsHandlerPath, manifestRouter.SubmitApplication)
	s.Handle(http.MethodGet, applicationsHandlerPath, manifestRouter.GetApplications)
	s.Handle(http.MethodGet, path.Join(applicationsHandlerPath, "/:id"), manifestRouter.GetApplication)
	s.Handle(http.MethodDelete, path.Join(applicationsHandlerPath, "/:id"), manifestRouter.DeleteApplication)

	s.Handle(http.MethodGet, responsesHandlerPath, manifestRouter.GetResponses)
	s.Handle(http.MethodGet, path.Join(responsesHandlerPath, "/:id"), manifestRouter.GetResponse)
	s.Handle(http.MethodDelete, path.Join(responsesHandlerPath, "/:id"), manifestRouter.DeleteResponse)
	return
}

func (s *SSIServer) DWNAPI(service svcframework.Service) (err error) {
	dwnRouter, err := router.NewDWNRouter(service)
	if err != nil {
		return util.LoggingErrorMsg(err, "could not create dwn router")
	}

	dwnPath := V1Prefix + DWNPrefix + ManifestsPrefix

	s.Handle(http.MethodPut, dwnPath, dwnRouter.PublishManifest)
	return
}
