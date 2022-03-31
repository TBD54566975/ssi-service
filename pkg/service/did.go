package service

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/tbd54566975/vc-service/internal/did"
	"github.com/tbd54566975/vc-service/pkg/storage"
)

type DIDMethod string

const (
	KeyMethod DIDMethod = "key"
)

type DIDService struct {
	// supported DID methods
	handlers map[DIDMethod]DIDServiceHandler
	storage  storage.DID
}

// DIDServiceHandler describes the functionality of *all* possible DID services, regardless of method
type DIDServiceHandler interface {
	CreateDID() (*CreateDIDResponse, error)
	GetDID() (*GetDIDResponse, error)
}

type CreateDIDResponse struct {
	DID interface{}
}

type GetDIDResponse struct {
	DID interface{}
}

func NewDIDService(methods []DIDMethod, s storage.DID) (*DIDService, error) {
	service := DIDService{storage: s}
	handlers := make(map[DIDMethod]DIDServiceHandler)
	for _, m := range methods {
		if err := service.instantiateHandlerForMethod(m); err != nil {
			return nil, errors.Wrap(err, "could not instantiate DID service")
		}
	}
	return &DIDService{
		handlers: handlers,
		storage:  s,
	}, nil
}

func (s *DIDService) instantiateHandlerForMethod(method DIDMethod) error {
	switch method {
	case KeyMethod:
		handler, err := did.NewKeyDIDHandler(s.storage)
		if err != nil {
			return fmt.Errorf("could not instnatiate did:%s handler", KeyMethod)
		}
		s.handlers[method] = handler
	default:
		return fmt.Errorf("unsupported DID method: %s", method)
	}
	return nil
}
