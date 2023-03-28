package did

import (
	"context"
	"fmt"

	didsdk "github.com/TBD54566975/ssi-sdk/did"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/pkg/errors"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/internal/did"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/service/did/resolution"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type Service struct {
	config  config.DIDServiceConfig
	storage *Storage

	// supported DID methods
	handlers map[didsdk.Method]MethodHandler

	// resolver for DID methods
	resolver *resolution.ServiceResolver

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

func (s *Service) GetResolver() resolution.Resolver {
	return s
}

func NewDIDService(config config.DIDServiceConfig, s storage.ServiceStorage, keyStore *keystore.Service) (*Service, error) {
	didStorage, err := NewDIDStorage(s)
	if err != nil {
		return nil, errors.Wrap(err, "could not instantiate DID storage for the DID service")
	}

	service := Service{
		storage:  didStorage,
		handlers: make(map[didsdk.Method]MethodHandler),
		keyStore: keyStore,
	}

	// instantiate all handlers for DID methods
	for _, m := range config.Methods {
		if err = service.instantiateHandlerForMethod(didsdk.Method(m)); err != nil {
			return nil, errors.Wrap(err, "instantiating DID service")
		}
	}

	// create handler resolver first, which wraps our handlers as a resolver
	handlerResolver, err := NewHandlerResolver(service.handlers)
	if err != nil {
		return nil, errors.Wrap(err, "instantiating handler resolver")
	}

	// instantiate DID resolver
	resolver, err := resolution.NewServiceResolver(handlerResolver, config.ResolutionMethods, config.UniversalResolverURL)
	if err != nil {
		return nil, errors.Wrap(err, "instantiating DID resolver")
	}
	service.resolver = resolver

	if !service.Status().IsReady() {
		return nil, errors.New(service.Status().Message)
	}
	return &service, nil
}

func (s *Service) ResolveDID(request ResolveDIDRequest) (*ResolveDIDResponse, error) {
	if request.DID == "" {
		return nil, util.LoggingNewError("cannot resolve empty DID")
	}
	resolved, err := s.Resolve(context.Background(), request.DID)
	if err != nil {
		return nil, err
	}
	return &ResolveDIDResponse{
		ResolutionMetadata:  &resolved.ResolutionMetadata,
		DIDDocument:         &resolved.Document,
		DIDDocumentMetadata: &resolved.DocumentMetadata,
	}, nil
}

func (s *Service) Resolve(ctx context.Context, did string, _ ...didsdk.ResolutionOptions) (*didsdk.ResolutionResult, error) {
	return s.resolver.Resolve(ctx, did)
}

func (s *Service) GetSupportedMethods() GetSupportedMethodsResponse {
	methods := make([]didsdk.Method, 0, len(s.handlers))
	for method := range s.handlers {
		methods = append(methods, method)
	}
	return GetSupportedMethodsResponse{Methods: methods}
}

func (s *Service) CreateDIDByMethod(ctx context.Context, request CreateDIDRequest) (*CreateDIDResponse, error) {
	handler, err := s.getHandler(request.Method)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get handler for method<%s>", request.Method)
	}
	return handler.CreateDID(ctx, request)
}

func (s *Service) GetDIDByMethod(ctx context.Context, request GetDIDRequest) (*GetDIDResponse, error) {
	handler, err := s.getHandler(request.Method)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get handler for method<%s>", request.Method)
	}
	return handler.GetDID(ctx, request)
}

func (s *Service) GetKeyFromDID(ctx context.Context, request GetKeyFromDIDRequest) (*GetKeyFromDIDResponse, error) {
	resolved, err := s.Resolve(ctx, request.ID)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "resolving DID<%s>", request.ID)
	}

	// next, get the verification information (key) from the did document
	kid, pubKey, err := did.GetVerificationInformation(resolved.Document, request.KeyID)
	if err != nil {
		return nil, errors.Wrapf(err, "getting verification information from the did document: %s", request.ID)
	}

	return &GetKeyFromDIDResponse{
		KeyID:     kid,
		PublicKey: pubKey,
	}, nil
}

func (s *Service) GetDIDsByMethod(ctx context.Context, request GetDIDsRequest) (*GetDIDsResponse, error) {
	method := request.Method
	handler, err := s.getHandler(method)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get handler for method<%s>", method)
	}
	return handler.GetDIDs(ctx, method)
}

func (s *Service) SoftDeleteDIDByMethod(ctx context.Context, request DeleteDIDRequest) error {
	handler, err := s.getHandler(request.Method)
	if err != nil {
		return util.LoggingErrorMsgf(err, "could not get handler for method<%s>", request.Method)
	}
	return handler.SoftDeleteDID(ctx, request)
}

func (s *Service) getHandler(method didsdk.Method) (MethodHandler, error) {
	handler, ok := s.handlers[method]
	if !ok {
		return nil, util.LoggingNewErrorf("could not get handler for DID method: %s", method)
	}
	return handler, nil
}
