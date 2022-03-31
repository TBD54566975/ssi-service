package did

import (
	"github.com/tbd54566975/vc-service/pkg/service"
	"github.com/tbd54566975/vc-service/pkg/storage"
)

func NewKeyDIDHandler(s storage.DID) (service.DIDServiceHandler, error) {
	return &keyDIDHandler{storage: s}, nil
}

type keyDIDHandler struct {
	storage storage.DID
}

func (ks *keyDIDHandler) CreateDID() (*service.CreateDIDResponse, error) {
	return &service.CreateDIDResponse{DID: "look ma, I'm a did"}, nil
}

func (ks *keyDIDHandler) GetDID() (*service.GetDIDResponse, error) {
	return &service.GetDIDResponse{DID: "look ma, I got a did"}, nil
}
