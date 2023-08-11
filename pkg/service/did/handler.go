package did

import (
	"context"

	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/resolution"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/pkg/errors"
	"github.com/tbd54566975/ssi-service/pkg/service/common"
)

// MethodHandler describes the functionality of *all* possible DID service, regardless of method
// TODO(gabe) consider smaller/more composable interfaces and promoting reusability across methods
// https://github.com/TBD54566975/ssi-service/issues/362
type MethodHandler interface {
	// GetMethod returns the did method that this handler is implementing.
	GetMethod() didsdk.Method

	// CreateDID creates a DID who's did method is `GetMethod`.
	CreateDID(ctx context.Context, request CreateDIDRequest) (*CreateDIDResponse, error)

	// GetDID returns a DID document for a did who's method is `GetMethod`. The DID must not have been soft-deleted.
	// TODO(gabe): support query parameters to get soft deleted and other DIDs https://github.com/TBD54566975/ssi-service/issues/364
	GetDID(ctx context.Context, request GetDIDRequest) (*GetDIDResponse, error)

	// ListDIDs returns all non-deleted DIDs for the given page. When page is nil, all non-deleted DIDs will be returned.
	ListDIDs(ctx context.Context, page *common.Page) (*ListDIDsResponse, error)

	// ListDeletedDIDs returns all soft-deleted DIDs.
	ListDeletedDIDs(ctx context.Context) (*ListDIDsResponse, error)

	// DeleteDID marks DIDs as deleted, and should do a reasonable effort to Delete. For instance, a DID ION would be deactivated.
	DeleteDID(ctx context.Context, request DeleteDIDRequest) (*DeleteDIDResponse, error)

	// Resolve returns the resolution result of the given DID according to https://w3c-ccg.github.io/did-resolution/#did-resolution-result.
	Resolve(ctx context.Context, did string) (*resolution.Result, error)
}

// NewHandlerResolver creates a new HandlerResolver from a map of MethodHandlers which are used to resolve DIDs
// stored in our database
func NewHandlerResolver(handlers map[didsdk.Method]MethodHandler) (*resolution.MultiMethodResolver, error) {
	if len(handlers) == 0 {
		return nil, util.LoggingNewError("no handlers provided")
	}

	methodResolvers := make([]resolution.Resolver, 0, len(handlers))
	for method, handler := range handlers {
		methodResolver := resolverFromHandler(method, handler)
		methodResolvers = append(methodResolvers, methodResolver)
	}

	multiMethodResolver, err := resolution.NewResolver(methodResolvers...)
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

func (h handlerResolver) Resolve(ctx context.Context, did string, _ ...resolution.Option) (*resolution.Result, error) {
	return h.handler.Resolve(ctx, did)
}

func (h handlerResolver) Methods() []didsdk.Method {
	return []didsdk.Method{h.method}
}

func resolverFromHandler(method didsdk.Method, handler MethodHandler) resolution.Resolver {
	return &handlerResolver{handler: handler, method: method}
}
