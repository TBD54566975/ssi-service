package did

import (
	"context"

	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/pkg/errors"

	internalutil "github.com/tbd54566975/ssi-service/internal/util"
)

// MethodHandler describes the functionality of *all* possible DID service, regardless of method
type MethodHandler interface {
	CreateDID(ctx context.Context, request CreateDIDRequest) (*CreateDIDResponse, error)
	GetDID(ctx context.Context, request GetDIDRequest) (*GetDIDResponse, error)
	GetDIDs(ctx context.Context, method didsdk.Method) (*GetDIDsResponse, error)
	SoftDeleteDID(ctx context.Context, request DeleteDIDRequest) error
}

// HandlerResolver is a DID resolver that uses MethodHandlers to resolution DIDs, meaning DIDs we store in our database
type HandlerResolver struct {
	handlers map[didsdk.Method]MethodHandler
}

// NewHandlerResolver creates a new HandlerResolver from a map of MethodHandlers which are used to resolution DIDs
func NewHandlerResolver(handlers map[didsdk.Method]MethodHandler) (*HandlerResolver, error) {
	if len(handlers) == 0 {
		return nil, util.LoggingNewError("no handlers provided")
	}
	return &HandlerResolver{handlers: handlers}, nil
}

// Resolve resolves a DID using the MethodHandler for the DID's method, wrapping the result in a ResolutionResult
func (hr HandlerResolver) Resolve(ctx context.Context, did string, _ ...didsdk.ResolutionOptions) (*didsdk.ResolutionResult, error) {
	// get method from DID
	method, err := internalutil.GetMethodForDID(did)
	if err != nil {
		return nil, errors.Wrap(err, "getting method from DID")
	}

	if handler, ok := hr.handlers[method]; ok {
		gotDID, err := handler.GetDID(ctx, GetDIDRequest{Method: method, ID: did})
		if err != nil {
			return nil, errors.Wrap(err, "getting DID from handler")
		}
		return &didsdk.ResolutionResult{Document: gotDID.DID}, nil
	}
	return nil, util.LoggingNewErrorf("no handler for method %s", method)
}

func (s *Service) instantiateHandlerForMethod(method didsdk.Method) error {
	switch method {
	case didsdk.KeyMethod:
		s.handlers[method] = NewKeyDIDHandler(s.storage, s.keyStore)
	case didsdk.WebMethod:
		s.handlers[method] = NewWebDIDHandler(s.storage, s.keyStore)
	default:
		return util.LoggingNewErrorf("unsupported DID method: %s", method)
	}
	return nil
}
