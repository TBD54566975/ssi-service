package did

import (
	"context"
	"fmt"
	"net/http"

	didsdk "github.com/TBD54566975/ssi-sdk/did"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/pkg/errors"
	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/internal/did"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/service/did/resolve"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type Service struct {
	config        config.DIDServiceConfig
	storage       *Storage
	localResolver *resolve.LocalResolver

	methodToResolver map[string]resolve.Resolver

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
	if s.localResolver == nil {
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

func (s *Service) GetResolver() resolve.Resolver {
	return s
}

func NewDIDService(config config.DIDServiceConfig, s storage.ServiceStorage, keyStore *keystore.Service) (*Service, error) {
	didStorage, err := NewDIDStorage(s)
	if err != nil {
		return nil, errors.Wrap(err, "could not instantiate DID storage for the DID service")
	}

	// instantiate DID resolver
	sdkResolver, err := did.BuildResolver(config.ResolutionMethods)
	if err != nil {
		return nil, errors.Wrap(err, "could not instantiate DID resolver")
	}

	service := Service{
		storage:          didStorage,
		handlers:         make(map[didsdk.Method]MethodHandler),
		keyStore:         keyStore,
		localResolver:    &resolve.LocalResolver{Resolver: sdkResolver},
		methodToResolver: make(map[string]resolve.Resolver),
	}

	for _, sm := range service.localResolver.SupportedMethods() {
		service.methodToResolver[sm.String()] = service.localResolver
	}

	ur := &resolve.UniversalResolver{
		Client: http.Client{},
		URL:    config.UniversalResolverURL,
	}
	for _, urm := range config.UniversalResolverMethods {
		service.methodToResolver[urm] = ur
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
	CreateDID(ctx context.Context, request CreateDIDRequest) (*CreateDIDResponse, error)
	GetDID(ctx context.Context, request GetDIDRequest) (*GetDIDResponse, error)
	GetDIDs(ctx context.Context, method didsdk.Method) (*GetDIDsResponse, error)
	SoftDeleteDID(ctx context.Context, request DeleteDIDRequest) error
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
	resolved, err := s.Resolve(context.Background(), request.DID)
	if err != nil {
		return nil, err
	}
	return &ResolveDIDResponse{
		ResolutionMetadata:  &resolved.DIDResolutionMetadata,
		DIDDocument:         &resolved.DIDDocument,
		DIDDocumentMetadata: &resolved.DIDDocumentMetadata,
	}, nil
}

func (s *Service) Resolve(ctx context.Context, did string, _ ...didsdk.ResolutionOptions) (*didsdk.DIDResolutionResult, error) {
	selectedResolver, err := s.chooseResolver(did)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "choosing resolver")
	}

	resolved, err := selectedResolver.Resolve(ctx, did)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not resolve DID: %s", did)
	}
	return resolved, nil
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

func (s *Service) chooseResolver(did string) (resolve.Resolver, error) {
	didMethod, err := util.GetMethodForDID(did)
	if err != nil {
		return nil, errors.Wrap(err, "getting method for did")
	}

	r, ok := s.methodToResolver[didMethod]
	if !ok {
		return nil, errors.Errorf("resolver for %s not available", didMethod)
	}

	return r, nil
}
