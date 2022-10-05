package did

import (
	"crypto"

	"github.com/tbd54566975/ssi-service/pkg/service/did"
)

func GetSupportedDIDMethods() []did.Method {
	return []did.Method{
		did.KeyMethod,
	}
}

type Resolver interface {
	ResolveKeys(did string) (map[string]crypto.PublicKey, error)
}

func NewResolver() Resolver {
	return &resolver{}
}

type resolver struct{}

func (r *resolver) ResolveKeys(did string) (map[string]crypto.PublicKey, error) {
	return nil, nil
}
