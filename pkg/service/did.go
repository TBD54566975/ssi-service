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

func (d DIDService) Type() Type {
	return DID
}

// Status is a self-reporting status for the DID service.
// TODO(gabe) consider turning this into an eventing service with self-reporting status per-method
func (d DIDService) Status() Status {
	if d.storage == nil {
		return Status{
			Status:  StatusError,
			Message: "storage not loaded",
		}
	}
	if len(d.handlers) == 0 {
		return Status{
			Status:  StatusInitializing,
			Message: "no DID method handlers loaded yet",
		}
	}
	return Status{
		Status: StatusReady,
	}
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

func (d *DIDService) instantiateHandlerForMethod(method DIDMethod) error {
	switch method {
	case KeyMethod:
		handler, err := did.NewKeyDIDHandler(d.storage)
		if err != nil {
			return fmt.Errorf("could not instnatiate did:%s handler", KeyMethod)
		}
		d.handlers[method] = handler
	default:
		return fmt.Errorf("unsupported DID method: %s", method)
	}
	return nil
}
