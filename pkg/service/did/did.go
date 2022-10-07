package did

import (
	"fmt"

	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/pkg/errors"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/internal/did"
	"github.com/tbd54566975/ssi-service/internal/util"
	didstorage "github.com/tbd54566975/ssi-service/pkg/service/did/storage"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type Method string

const (
	KeyMethod Method = "key"
)

type Service struct {
	config   config.DIDServiceConfig
	storage  didstorage.Storage
	resolver *didsdk.Resolver

	// supported DID methods
	handlers map[Method]MethodHandler

	// external dependencies
	keyStore *keystore.Service
}

// MethodHandler describes the functionality of *all* possible DID service, regardless of method
type MethodHandler interface {
	CreateDID(request CreateDIDRequest) (*CreateDIDResponse, error)
	GetDID(request GetDIDRequest) (*GetDIDResponse, error)
	GetDIDs(method Method) (*GetDIDsResponse, error)
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

	svc := Service{
		storage:  didStorage,
		handlers: make(map[Method]MethodHandler),
		keyStore: keyStore,
		resolver: resolver,
	}

	// instantiate all handlers for DID methods
	for _, m := range config.Methods {
		if err := svc.instantiateHandlerForMethod(Method(m)); err != nil {
			return nil, errors.Wrap(err, "could not instantiate DID service")
		}
	}

	return &svc, nil
}

func (s *Service) instantiateHandlerForMethod(method Method) error {
	switch method {
	case KeyMethod:
		handler, err := newKeyDIDHandler(s.storage, s.keyStore)
		if err != nil {
			err := fmt.Errorf("could not instnatiate did:%s handler", KeyMethod)
			return util.LoggingError(err)
		}
		s.handlers[method] = handler
	default:
		err := fmt.Errorf("unsupported DID method: %s", method)
		return util.LoggingError(err)
	}
	return nil
}

func (s *Service) Type() framework.Type {
	return framework.DID
}

// Status is a self-reporting status for the DID service.
func (s *Service) Status() framework.Status {
	if s.storage == nil || len(s.handlers) == 0 {
		return framework.Status{
			Status:  framework.StatusNotReady,
			Message: "storage not loaded and/or no DID methods loaded",
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

func (s *Service) ResolveDID(request ResolveDIDRequest) (*ResolveDIDResponse, error) {
	if request.DID == "" {
		return nil, util.LoggingNewError("cannot resolve empty DID")
	}
	resolved, err := s.resolver.Resolve(request.DID)
	if err != nil {
		return nil, err
	}
	return &ResolveDIDResponse{
		ResolutionMetadata:  &resolved.DIDResolutionMetadata,
		DIDDocument:         &resolved.DIDDocument,
		DIDDocumentMetadata: &resolved.DIDDocumentMetadata,
	}, nil
}

func (s *Service) GetSupportedMethods() GetSupportedMethodsResponse {
	var methods []Method
	for method := range s.handlers {
		methods = append(methods, method)
	}
	return GetSupportedMethodsResponse{Methods: methods}
}

func (s *Service) CreateDIDByMethod(request CreateDIDRequest) (*CreateDIDResponse, error) {
	handler, err := s.getHandler(request.Method)
	if err != nil {
		errMsg := fmt.Sprintf("could not get handler for method<%s>", request.Method)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	return handler.CreateDID(request)
}

func (s *Service) GetDIDByMethod(request GetDIDRequest) (*GetDIDResponse, error) {
	handler, err := s.getHandler(request.Method)
	if err != nil {
		errMsg := fmt.Sprintf("could not get handler for method<%s>", request.Method)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	return handler.GetDID(request)
}

func (s *Service) GetDIDsByMethod(request GetDIDsRequest) (*GetDIDsResponse, error) {
	method := request.Method
	handler, err := s.getHandler(method)
	if err != nil {
		errMsg := fmt.Sprintf("could not get handler for method<%s>", method)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	return handler.GetDIDs(method)
}

func (s *Service) getHandler(method Method) (MethodHandler, error) {
	handler, ok := s.handlers[method]
	if !ok {
		err := fmt.Errorf("could not get handler for DID method: %s", method)
		return nil, util.LoggingError(err)
	}
	return handler, nil
}
