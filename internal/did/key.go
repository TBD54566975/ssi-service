package did

import (
	"github.com/tbd54566975/vc-service/pkg/service"
)

func NewKeyDIDHandler(s Storage) (service.DIDServiceHandler, error) {
	return &keyDIDHandler{storage: s}, nil
}

type keyDIDHandler struct {
	storage Storage
}

func (h *keyDIDHandler) CreateDID() (*service.CreateDIDResponse, error) {
	h.storage.CreateDID()
	return &service.CreateDIDResponse{DID: "look ma, I'm a did"}, nil
}

func (h *keyDIDHandler) GetDID() (*service.GetDIDResponse, error) {
	return &service.GetDIDResponse{DID: "look ma, I got a did"}, nil
}
