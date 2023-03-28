package resolve

import (
	"context"

	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/pkg/errors"
)

// localResolver is an implementation of Resolver that passes through the parameters into the sdk implementation that
// resolves DIDs. This is done because, when this is being written, the didsdk.Resolution interface does not let callers
// pass in their own context.
type localResolver struct {
	*didsdk.Resolver
}

func newLocalResolver(resolver *didsdk.Resolver) (*localResolver, error) {
	if resolver == nil {
		return nil, errors.New("resolver cannot be nil")
	}
	if len(resolver.SupportedMethods()) == 0 {
		return nil, errors.New("resolver must support at least one method")
	}
	return &localResolver{Resolver: resolver}, nil
}

func (lr localResolver) Resolve(_ context.Context, did string, opts ...didsdk.ResolutionOptions) (*didsdk.ResolutionResult, error) {
	return lr.Resolver.Resolve(did, opts...)
}
