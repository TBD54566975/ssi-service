package resolution

import (
	"context"

	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/pkg/errors"
)

// localResolver is an implementation of didsdk.Resolution that passes through the parameters into the sdk implementation that
// resolves DIDs. This is done because, when this is being written, the didsdk.Resolution interface does not let callers
// pass in their own context.
type localResolver struct {
	*didsdk.MultiMethodResolver
}

var _ didsdk.Resolver = (*localResolver)(nil)

func newLocalResolver(resolver *didsdk.MultiMethodResolver) (*localResolver, error) {
	if resolver == nil {
		return nil, errors.New("resolver cannot be nil")
	}
	if len(resolver.Methods()) == 0 {
		return nil, errors.New("resolver must support at least one method")
	}
	return &localResolver{MultiMethodResolver: resolver}, nil
}

func (lr localResolver) Resolve(ctx context.Context, did string, opts ...didsdk.ResolutionOption) (*didsdk.ResolutionResult, error) {
	return lr.MultiMethodResolver.Resolve(ctx, did, opts...)
}

func (lr localResolver) Methods() []didsdk.Method {
	return lr.MultiMethodResolver.Methods()
}
