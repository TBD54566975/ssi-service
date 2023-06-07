package did

import (
	"context"
	"fmt"

	didsdk "github.com/TBD54566975/ssi-sdk/did"
	didresolution "github.com/TBD54566975/ssi-sdk/did/resolution"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/pkg/errors"

	"github.com/tbd54566975/ssi-service/config"
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

func (s *Service) GetResolver() didresolution.Resolver {
	return s.resolver
}

func NewDIDService(config config.DIDServiceConfig, s storage.ServiceStorage, keyStore *keystore.Service) (*Service, error) {
	didStorage, err := NewDIDStorage(s)
	if err != nil {
		return nil, errors.Wrap(err, "could not instantiate DID storage for the DID service")
	}

	service := Service{
		config:   config,
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
	hr, err := NewHandlerResolver(service.handlers)
	if err != nil {
		return nil, errors.Wrap(err, "instantiating handler resolver")
	}

	// instantiate DID resolver
	resolver, err := resolution.NewServiceResolver(hr, config.LocalResolutionMethods, config.UniversalResolverURL)
	if err != nil {
		return nil, errors.Wrap(err, "instantiating DID resolver")
	}
	service.resolver = resolver

	if !service.Status().IsReady() {
		return nil, errors.New(service.Status().Message)
	}
	return &service, nil
}

// instantiateHandlerForMethod instantiates a handler for the given DID method. All handlers supported by the DID
// service must be instantiated here.
func (s *Service) instantiateHandlerForMethod(method didsdk.Method) error {
	switch method {
	case didsdk.KeyMethod:
		kh, err := NewKeyHandler(s.storage, s.keyStore)
		if err != nil {
			return errors.Wrap(err, "instantiating key handler")
		}
		s.handlers[method] = kh
	case didsdk.WebMethod:
		wh, err := NewWebHandler(s.storage, s.keyStore)
		if err != nil {
			return errors.Wrap(err, "instantiating web handler")
		}
		s.handlers[method] = wh
	case didsdk.IONMethod:
		ih, err := NewIONHandler(s.Config().IONResolverURL, s.storage, s.keyStore)
		if err != nil {
			return errors.Wrap(err, "instantiating ion handler")
		}
		s.handlers[method] = ih
	default:
		return sdkutil.LoggingNewErrorf("unsupported DID method: %s", method)
	}
	return nil
}

func (s *Service) ResolveDID(request ResolveDIDRequest) (*ResolveDIDResponse, error) {
	if request.DID == "" {
		return nil, sdkutil.LoggingNewError("cannot resolve empty DID")
	}
	resolved, err := s.Resolve(context.Background(), request.DID)
	if err != nil {
		return nil, err
	}
	return &ResolveDIDResponse{
		ResolutionMetadata:  &resolved.Metadata,
		DIDDocument:         &resolved.Document,
		DIDDocumentMetadata: &resolved.DocumentMetadata,
	}, nil
}

func (s *Service) Resolve(ctx context.Context, did string, opts ...didresolution.Option) (*didresolution.Result, error) {
	return s.resolver.Resolve(ctx, did, opts)
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
		return nil, sdkutil.LoggingErrorMsgf(err, "could not get handler for method<%s>", request.Method)
	}
	return handler.CreateDID(ctx, request)
}

func (s *Service) GetDIDByMethod(ctx context.Context, request GetDIDRequest) (*GetDIDResponse, error) {
	handler, err := s.getHandler(request.Method)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "could not get handler for method<%s>", request.Method)
	}
	return handler.GetDID(ctx, request)
}

func (s *Service) GetKeyFromDID(ctx context.Context, request GetKeyFromDIDRequest) (*GetKeyFromDIDResponse, error) {
	resolved, err := s.Resolve(ctx, request.ID)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "resolving DID<%s>", request.ID)
	}

	// next, get the verification information (key) from the did document
	pubKey, err := didsdk.GetKeyFromVerificationMethod(resolved.Document, request.KeyID)
	if err != nil {
		return nil, errors.Wrapf(err, "getting verification information from the did document: %s", request.ID)
	}

	return &GetKeyFromDIDResponse{
		KeyID:     request.KeyID,
		PublicKey: pubKey,
	}, nil
}

func (s *Service) ListDIDsByMethod(ctx context.Context, request ListDIDsRequest) (*ListDIDsResponse, error) {
	handler, err := s.getHandler(request.Method)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "could not get handler for method<%s>", request.Method)
	}
	if request.Deleted {
		return handler.ListDeletedDIDs(ctx)
	}
	const allPages = int64(-1)

	var page Page
	page.Size = new(int64)
	*page.Size = allPages
	if request.PageSize != nil {
		page = Page{
			Token: request.PageToken,
			Size:  request.PageSize,
		}
	}
	return handler.ListDIDs(ctx, &page)
}

func (s *Service) SoftDeleteDIDByMethod(ctx context.Context, request DeleteDIDRequest) error {
	handler, err := s.getHandler(request.Method)
	if err != nil {
		return sdkutil.LoggingErrorMsgf(err, "could not get handler for method<%s>", request.Method)
	}
	return handler.SoftDeleteDID(ctx, request)
}

func (s *Service) getHandler(method didsdk.Method) (MethodHandler, error) {
	handler, ok := s.handlers[method]
	if !ok {
		return nil, sdkutil.LoggingNewErrorf("could not get handler for DID method: %s", method)
	}
	return handler, nil
}
