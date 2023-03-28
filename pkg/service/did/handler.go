package did

import (
	"context"

	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/pkg/errors"
)

// MethodHandler describes the functionality of *all* possible DID service, regardless of method
type MethodHandler interface {
	CreateDID(ctx context.Context, request CreateDIDRequest) (*CreateDIDResponse, error)
	GetDID(ctx context.Context, request GetDIDRequest) (*GetDIDResponse, error)
	GetDIDs(ctx context.Context, method didsdk.Method) (*GetDIDsResponse, error)
	SoftDeleteDID(ctx context.Context, request DeleteDIDRequest) error
}

// HandlerResolver is a DID resolver that uses a multimethod resolver backed by method handlers to resolve DIDs,
// meaning DIDs we store in our database
type HandlerResolver struct {
	*didsdk.MultiMethodResolver
}

// NewHandlerResolver creates a new HandlerResolver from a map of MethodHandlers which are used to resolve DIDs
func NewHandlerResolver(handlers map[didsdk.Method]MethodHandler) (*HandlerResolver, error) {
	if len(handlers) == 0 {
		return nil, util.LoggingNewError("no handlers provided")
	}

	methodResolvers := make([]didsdk.Resolver, 0, len(handlers))
	for method, handler := range handlers {
		methodResolver := resolverFromHandler(method, handler)
		methodResolvers = append(methodResolvers, methodResolver)
	}

	multiMethodResolver, err := didsdk.NewResolver(methodResolvers...)
	if err != nil {
		return nil, errors.Wrap(err, "creating multi-method resolver")
	}

	return &HandlerResolver{MultiMethodResolver: multiMethodResolver}, nil
}

// Resolve resolves a DID using the embedded MultiMethodResolver
func (hr HandlerResolver) Resolve(ctx context.Context, did string, opts ...didsdk.ResolutionOption) (*didsdk.ResolutionResult, error) {
	return hr.MultiMethodResolver.Resolve(ctx, did, opts)
}

func (hr HandlerResolver) Methods() []didsdk.Method {
	return hr.MultiMethodResolver.Methods()
}

// handlerResolver is a DID resolver that uses a MethodHandler to resolve DIDs
type handlerResolver struct {
	handler MethodHandler
	method  didsdk.Method
}

func (h handlerResolver) Resolve(ctx context.Context, did string, _ ...didsdk.ResolutionOption) (*didsdk.ResolutionResult, error) {
	method, err := didsdk.GetMethodForDID(did)
	if err != nil {
		return nil, errors.Wrap(err, "getting method from DID")
	}

	if method != h.method {
		return nil, errors.Errorf("invalid method %s for handler %s", method, h.method)
	}

	gotDIDResponse, err := h.handler.GetDID(ctx, GetDIDRequest{
		Method: h.method,
		ID:     did,
	})
	if err != nil {
		return nil, errors.Wrap(err, "getting DID from handler")
	}
	return &didsdk.ResolutionResult{Document: gotDIDResponse.DID}, nil
}

func (h handlerResolver) Methods() []didsdk.Method {
	return []didsdk.Method{h.method}
}

func resolverFromHandler(method didsdk.Method, handler MethodHandler) didsdk.Resolver {
	return &handlerResolver{handler: handler, method: method}
}
