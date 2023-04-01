package did

import (
	"fmt"

	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// BuildMultiMethodResolver builds a multi method DID resolver from a list of methods to support resolution for
func BuildMultiMethodResolver(methods []string) (*didsdk.MultiMethodResolver, error) {
	if len(methods) == 0 {
		return nil, errors.New("no methods provided")
	}
	resolvers := make([]didsdk.Resolver, 0, len(methods))
	for _, method := range methods {
		resolver, err := getKnownResolver(method)
		if err != nil {
			// if we can't create a resolver for a method, we just skip it since not all methods are supported locally
			logrus.WithError(err).Errorf("failed to create resolver for method %s", method)
			continue
		}
		resolvers = append(resolvers, resolver)
	}
	if len(resolvers) == 0 {
		return nil, errors.New("no resolvers created")
	}
	return didsdk.NewResolver(resolvers...)
}

// all possible resolvers for the DID service
func getKnownResolver(method string) (didsdk.Resolver, error) {
	switch didsdk.Method(method) {
	case didsdk.KeyMethod:
		return new(didsdk.KeyResolver), nil
	case didsdk.WebMethod:
		return new(didsdk.WebResolver), nil
	case didsdk.PKHMethod:
		return new(didsdk.PKHResolver), nil
	case didsdk.PeerMethod:
		return new(didsdk.PeerResolver), nil
	}
	return nil, fmt.Errorf("unsupported method: %s", method)
}
