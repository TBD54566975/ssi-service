package did

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/tbd54566975/vc-service/pkg/services"
	didstorage "github.com/tbd54566975/vc-service/pkg/services/did/storage"
	"github.com/tbd54566975/vc-service/pkg/storage"
)

type Method string

const (
	KeyMethod Method = "key"
)

type Service struct {
	// supported DID methods
	handlers map[Method]ServiceHandler
	storage  didstorage.Storage
}

func (s Service) Type() services.Type {
	return services.DID
}

// Status is a self-reporting status for the DID service.
// TODO(gabe) consider turning this into an eventing service with self-reporting status per-method
func (s Service) Status() services.Status {
	if s.storage == nil || len(s.handlers) == 0 {
		return services.Status{
			Status:  services.StatusNotReady,
			Message: "storage not loaded and/or no DID methods loaded",
		}
	}
	return services.Status{Status: services.StatusReady}
}

// ServiceHandler describes the functionality of *all* possible DID services, regardless of method
type ServiceHandler interface {
	CreateDID(request CreateDIDRequest) (*CreateDIDResponse, error)
	GetDID(id string) (*GetDIDResponse, error)
}

func NewDIDService(methods []Method, s storage.ServiceStorage) (*Service, error) {
	didStorage, err := didstorage.NewDIDStorage(s)
	if err != nil {
		return nil, errors.Wrap(err, "could not instantiate DID storage for DID service")
	}
	svc := Service{storage: didStorage}

	handlers := make(map[Method]ServiceHandler)
	for _, m := range methods {
		if err := svc.instantiateHandlerForMethod(m); err != nil {
			return nil, errors.Wrap(err, "could not instantiate DID svc")
		}
	}
	svc.handlers = handlers
	return &svc, nil
}

func (s *Service) instantiateHandlerForMethod(method Method) error {
	switch method {
	case KeyMethod:
		handler, err := NewKeyDIDHandler(s.storage)
		if err != nil {
			return fmt.Errorf("could not instnatiate did:%s handler", KeyMethod)
		}
		s.handlers[method] = handler
	default:
		return fmt.Errorf("unsupported DID method: %s", method)
	}
	return nil
}
