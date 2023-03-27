package did

import (
	"fmt"

	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/pkg/errors"
)

// BuildResolver builds a DID resolver from a list of method to support resolution for
func BuildResolver(methods []string) (*didsdk.Resolver, error) {
	if len(methods) == 0 {
		return nil, errors.New("no method provided")
	}
	resolvers := make([]didsdk.Resolution, 0, len(methods))
	for _, method := range methods {
		resolver, err := getKnownResolver(method)
		if err != nil {
			return nil, err
		}
		resolvers = append(resolvers, resolver)
	}
	if len(resolvers) == 0 {
		return nil, errors.New("no resolvers created")
	}
	return didsdk.NewResolver(resolvers...)
}

// all possible resolvers for the DID service
func getKnownResolver(method string) (didsdk.Resolution, error) {
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
