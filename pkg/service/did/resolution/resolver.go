package resolution

import (
	"context"
	"fmt"

	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/resolution"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	didint "github.com/tbd54566975/ssi-service/internal/did"
	utilint "github.com/tbd54566975/ssi-service/internal/util"
)

// ServiceResolver is a resolver that can resolve DIDs using a combination of local and universal resolvers.
type ServiceResolver struct {
	resolutionMethods []string
	hr                resolution.Resolver
	lr                resolution.Resolver
	ur                *universalResolver
}

var _ resolution.Resolver = (*ServiceResolver)(nil)

// NewServiceResolver creates a new ServiceResolver instance which can resolve DIDs using a combination of local and
// universal resolvers.
func NewServiceResolver(handlerResolver resolution.Resolver, localResolutionMethods []string, universalResolverURL string) (*ServiceResolver, error) {
	var lr resolution.Resolver
	var err error
	if len(localResolutionMethods) > 0 {
		// instantiate sdk resolver
		lr, err = didint.BuildMultiMethodResolver(localResolutionMethods)
		if err != nil {
			return nil, errors.Wrap(err, "instantiating local DID resolver")
		}
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
		resolutionMethods: localResolutionMethods,
		hr:                handlerResolver,
		lr:                lr,
		ur:                ur,
	}, nil
}

// Resolve resolves a DID using a combination of local and universal resolvers. The ordering is as follows:
// 1. Try to resolve with the handlers we have, wrapping the resulting DID in resolution result
// 2. Try to resolve with the local resolver
// 3. Try to resolve with the universal resolver
// TODO(gabe) avoid caching DIDs that should be externally resolved https://github.com/TBD54566975/ssi-service/issues/361
func (sr *ServiceResolver) Resolve(ctx context.Context, did string, opts ...resolution.ResolutionOption) (*resolution.ResolutionResult, error) {
	// check the did is valid
	if _, err := utilint.GetMethodForDID(did); err != nil {
		return nil, errors.Wrap(err, "getting method DID")
	}

	// first, try to resolve with the handlers we have
	if sr.hr != nil {
		handlersResolvedDID, err := sr.hr.Resolve(ctx, did, opts...)
		if err == nil {
			return handlersResolvedDID, nil
		}
		logrus.WithError(err).Error("error resolving DID with handler resolver")
	}

	// next, try to resolve with the local resolver
	if sr.lr != nil {
		locallyResolvedDID, err := sr.lr.Resolve(ctx, did, opts...)
		if err == nil {
			return locallyResolvedDID, nil
		}
		logrus.WithError(err).Error("error resolving DID with local resolver")
	}

	// finally, resolution with the universal resolver
	if sr.ur != nil {
		universallyResolvedDID, err := sr.ur.Resolve(ctx, did, opts...)
		if err == nil {
			return universallyResolvedDID, nil

		}
		logrus.WithError(err).Error("error resolving DID with universal resolver")
	}

	return nil, fmt.Errorf("unable to resolve DID %s", did)
}

func (sr *ServiceResolver) Methods() []didsdk.Method {
	methods := make([]didsdk.Method, 0, len(sr.resolutionMethods))
	for _, m := range sr.resolutionMethods {
		methods = append(methods, didsdk.Method(m))
	}
	return methods
}
