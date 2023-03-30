package did

import (
	"context"

	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/pkg/errors"
)

// MethodHandler describes the functionality of *all* possible DID service, regardless of method
// TODO(gabe) consider smaller/more composable interfaces and promoting reusability across methods
// https://github.com/TBD54566975/ssi-service/issues/362
type MethodHandler interface {
	CreateDID(ctx context.Context, request CreateDIDRequest) (*CreateDIDResponse, error)
	// TODO(gabe): support query parameters to get soft deleted and other DIDs https://github.com/TBD54566975/ssi-service/issues/364
	GetDID(ctx context.Context, request GetDIDRequest) (*GetDIDResponse, error)
	GetDIDs(ctx context.Context) (*GetDIDsResponse, error)
	SoftDeleteDID(ctx context.Context, request DeleteDIDRequest) error
}

// NewHandlerResolver creates a new HandlerResolver from a map of MethodHandlers which are used to resolve DIDs
// stored in our database
func NewHandlerResolver(handlers map[didsdk.Method]MethodHandler) (*didsdk.MultiMethodResolver, error) {
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

	return multiMethodResolver, nil
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
