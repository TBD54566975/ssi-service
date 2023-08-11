package did

import (
	"fmt"

	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/ion"
	"github.com/TBD54566975/ssi-sdk/did/jwk"
	"github.com/TBD54566975/ssi-sdk/did/key"
	"github.com/TBD54566975/ssi-sdk/did/peer"
	"github.com/TBD54566975/ssi-sdk/did/pkh"
	"github.com/TBD54566975/ssi-sdk/did/resolution"
	"github.com/TBD54566975/ssi-sdk/did/web"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// BuildMultiMethodResolver builds a multi method DID resolver from a list of methods to support resolution for
func BuildMultiMethodResolver(methods []string) (*resolution.MultiMethodResolver, error) {
	if len(methods) == 0 {
		return nil, errors.New("no methods provided")
	}
	resolvers := make([]resolution.Resolver, 0, len(methods))
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
	return resolution.NewResolver(resolvers...)
}

// all possible resolvers for the DID service
func getKnownResolver(method string) (resolution.Resolver, error) {
	switch didsdk.Method(method) {
	case didsdk.KeyMethod:
		return new(key.Resolver), nil
	case didsdk.WebMethod:
		return new(web.Resolver), nil
	case didsdk.PKHMethod:
		return new(pkh.Resolver), nil
	case didsdk.PeerMethod:
		return new(peer.Resolver), nil
	case didsdk.JWKMethod:
		return new(jwk.Resolver), nil
	case didsdk.IONMethod:
		return new(ion.LocalResolver), nil
	}
	return nil, fmt.Errorf("unsupported method: %s", method)
}
