package router

import (
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
)

type KeyStoreRouter struct {
	service *keystore.Service
}

func NewKeyStoreRouter(s svcframework.Service) (*KeyStoreRouter, error) {
	{

	}
}
