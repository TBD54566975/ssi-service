package resolution

import (
	"context"

	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	internaldid "github.com/tbd54566975/ssi-service/internal/did"
	internalutil "github.com/tbd54566975/ssi-service/internal/util"
)

type Resolver interface {
	Resolve(ctx context.Context, did string, opts ...didsdk.ResolutionOptions) (*didsdk.ResolutionResult, error)
}

// ServiceResolver is a resolver that can resolve DIDs using a combination of local and universal resolvers.
type ServiceResolver struct {
	resolutionMethods []string
	hr                Resolver
	lr                *localResolver
	ur                *universalResolver
}

// NewServiceResolver creates a new ServiceResolver instance which can resolve DIDs using a combination of local and
// universal resolvers.
func NewServiceResolver(handlerResolver Resolver, resolutionMethods []string, universalResolverURL string) (*ServiceResolver, error) {
	if len(resolutionMethods) == 0 {
		return nil, errors.New("no resolution methods configured")
	}

	// instantiate sdk resolver
	sdkResolver, err := internaldid.BuildResolver(resolutionMethods)
	if err != nil {
		return nil, errors.Wrap(err, "instantiating SDK DID resolver")
	}
	lr, err := newLocalResolver(sdkResolver)
	if err != nil {
		return nil, errors.Wrap(err, "instantiating local resolver")
	}

	// instantiate universal resolver
	var ur *universalResolver
	if universalResolverURL != "" {
		ur, err = newUniversalResolver(universalResolverURL)
		if err != nil {
			return nil, errors.Wrap(err, "instantiating universal resolver")
		}
	}

	return &ServiceResolver{
		resolutionMethods: resolutionMethods,
		hr:                handlerResolver,
		lr:                lr,
		ur:                ur,
	}, nil
}

// Resolve resolves a DID using a combination of local and universal resolvers. The ordering is as follows:
// 1. Try to resolve with the handlers we have, wrapping the resulting DID in resolution result
// 2. Try to resolve with the local resolver
// 3. Try to resolve with the universal resolver
func (sr *ServiceResolver) Resolve(ctx context.Context, did string, opts ...didsdk.ResolutionOptions) (*didsdk.ResolutionResult, error) {
	// check the did is valid
	if _, err := internalutil.GetMethodForDID(did); err != nil {
		return nil, errors.Wrap(err, "getting method DID")
	}

	ae := util.NewAppendError()
	// first, try to resolve with the handlers we have
	if sr.hr != nil {
		handlersResolvedDID, err := sr.hr.Resolve(ctx, did, opts...)
		if err != nil {
			logrus.WithError(err).Error("error resolving DID with handler resolver")
			ae.Append(err)
		} else {
			return handlersResolvedDID, nil
		}
	}

	// next, try to resolve with the local resolver
	if sr.lr != nil {
		locallyResolvedDID, err := sr.lr.Resolve(ctx, did, opts...)
		if err != nil {
			logrus.WithError(err).Error("error resolving DID with local resolver")
			ae.Append(err)
		} else {
			return locallyResolvedDID, nil
		}
	}

	// finally, resolution with the universal resolver
	if sr.ur != nil {
		universallyResolvedDID, err := sr.ur.Resolve(ctx, did, opts...)
		if err != nil {
			logrus.WithError(err).Error("error resolving DID with universal resolver")
			ae.Append(err)
		} else {
			return universallyResolvedDID, nil
		}
	}

	if ae.IsEmpty() {
		return nil, errors.New("unable to resolution DID")
	}

	return nil, ae.Error()
}
