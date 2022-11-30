package did

import (
	"fmt"

	didsdk "github.com/TBD54566975/ssi-sdk/did"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/pkg/errors"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/internal/did"
	"github.com/tbd54566975/ssi-service/internal/util"
	didstorage "github.com/tbd54566975/ssi-service/pkg/service/did/storage"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type Service struct {
	config   config.DIDServiceConfig
	storage  didstorage.Storage
	resolver *didsdk.Resolver

	// supported DID methods
	handlers map[didsdk.Method]MethodHandler

	// external dependencies
	keyStore *keystore.Service
}

func (s *Service) Type() framework.Type {
	return framework.DID
}

// Status is a self-reporting status for the DID service.
func (s *Service) Status() framework.Status {
	ae := sdkutil.NewAppendError()
	if s.storage == nil {
		ae.AppendString("no storage configured")
	}
	if len(s.handlers) == 0 {
		ae.AppendString("no did handlers configured")
	}
	if s.keyStore == nil {
		ae.AppendString("no key store service configured")
	}
	if s.resolver == nil {
		ae.AppendString("no resolver configured")
	}
	if !ae.IsEmpty() {
		return framework.Status{
			Status:  framework.StatusNotReady,
			Message: fmt.Sprintf("did service is not ready: %s", ae.Error().Error()),
		}
	}
	return framework.Status{Status: framework.StatusReady}
}

func (s *Service) Config() config.DIDServiceConfig {
	return s.config
}

func (s *Service) GetResolver() *didsdk.Resolver {
	return s.resolver
}

func NewDIDService(config config.DIDServiceConfig, s storage.ServiceStorage, keyStore *keystore.Service) (*Service, error) {
	didStorage, err := didstorage.NewDIDStorage(s)
	if err != nil {
		return nil, errors.Wrap(err, "could not instantiate DID storage for the DID service")
	}

	// instantiate DID resolver
	resolver, err := did.BuildResolver(config.ResolutionMethods)
	if err != nil {
		return nil, errors.Wrap(err, "could not instantiate DID resolver")
	}

	service := Service{
		storage:  didStorage,
		handlers: make(map[didsdk.Method]MethodHandler),
		keyStore: keyStore,
		resolver: resolver,
	}

	// instantiate all handlers for DID methods
	for _, m := range config.Methods {
		if err = service.instantiateHandlerForMethod(didsdk.Method(m)); err != nil {
			return nil, errors.Wrap(err, "could not instantiate DID service")
		}
	}

	if !service.Status().IsReady() {
		return nil, errors.New(service.Status().Message)
	}
	return &service, nil
}

// MethodHandler describes the functionality of *all* possible DID service, regardless of method
type MethodHandler interface {
	CreateDID(request CreateDIDRequest) (*CreateDIDResponse, error)
	GetDID(request GetDIDRequest) (*GetDIDResponse, error)
	GetDIDs(method didsdk.Method) (*GetDIDsResponse, error)
}

func (s *Service) instantiateHandlerForMethod(method didsdk.Method) error {
	switch method {
	case didsdk.KeyMethod:
		s.handlers[method] = newKeyDIDHandler(s.storage, s.keyStore)
	case didsdk.WebMethod:
		s.handlers[method] = newWebDIDHandler(s.storage, s.keyStore)
	default:
		return util.LoggingNewErrorf("unsupported DID method: %s", method)
	}
	return nil
}

func (s *Service) ResolveDID(request ResolveDIDRequest) (*ResolveDIDResponse, error) {
	if request.DID == "" {
		return nil, util.LoggingNewError("cannot resolve empty DID")
	}
	resolved, err := s.resolver.Resolve(request.DID)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not resolve DID: %s", request.DID)
	}
	return &ResolveDIDResponse{
		ResolutionMetadata:  &resolved.DIDResolutionMetadata,
		DIDDocument:         &resolved.DIDDocument,
		DIDDocumentMetadata: &resolved.DIDDocumentMetadata,
	}, nil
}

func (s *Service) GetSupportedMethods() GetSupportedMethodsResponse {
	methods := make([]didsdk.Method, 0, len(s.handlers))
	for method := range s.handlers {
		methods = append(methods, method)
	}
	return GetSupportedMethodsResponse{Methods: methods}
}

func (s *Service) CreateDIDByMethod(request CreateDIDRequest) (*CreateDIDResponse, error) {
	handler, err := s.getHandler(request.Method)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get handler for method<%s>", request.Method)
	}
	return handler.CreateDID(request)
}

func (s *Service) GetDIDByMethod(request GetDIDRequest) (*GetDIDResponse, error) {
	handler, err := s.getHandler(request.Method)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get handler for method<%s>", request.Method)
	}
	return handler.GetDID(request)
}

func (s *Service) GetDIDsByMethod(request GetDIDsRequest) (*GetDIDsResponse, error) {
	method := request.Method
	handler, err := s.getHandler(method)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get handler for method<%s>", method)
	}
	return handler.GetDIDs(method)
}

func (s *Service) getHandler(method didsdk.Method) (MethodHandler, error) {
	handler, ok := s.handlers[method]
	if !ok {
		return nil, util.LoggingNewErrorf("could not get handler for DID method: %s", method)
	}
	return handler, nil
}
