package did

import (
	"fmt"

	didsdk "github.com/TBD54566975/ssi-sdk/did"
)

// BuildResolver builds a DID resolver from a list of methods to support resolution for
func BuildResolver(methods []string) (*didsdk.Resolver, error) {
	var resolvers []didsdk.Resolution
	for _, method := range methods {
		resolver, err := getKnownResolver(method)
		if err != nil {
			return nil, err
		}
		resolvers = append(resolvers, resolver)
	}
	return didsdk.NewResolver(resolvers...)
}

// all possible resolvers for the DID service
func getKnownResolver(method string) (didsdk.Resolution, error) {
	switch didsdk.Method(method) {
	case didsdk.KeyMethod:
		return didsdk.KeyResolver{}, nil
	case didsdk.WebMethod:
		return didsdk.WebResolver{}, nil
	case didsdk.PKHMethod:
		return didsdk.PKHResolver{}, nil
	case didsdk.PeerMethod:
		return didsdk.PeerResolver{}, nil
	}
	return nil, fmt.Errorf("unsupported method: %s", method)
}
