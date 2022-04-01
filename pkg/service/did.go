package service

import (
	"fmt"
	"github.com/TBD54566975/did-sdk/crypto"
	sdkdid "github.com/TBD54566975/did-sdk/did"
	"github.com/pkg/errors"
	"github.com/tbd54566975/vc-service/internal/did"
)

type DIDMethod string

const (
	KeyMethod DIDMethod = "key"
)

type DIDService struct {
	// supported DID methods
	handlers map[DIDMethod]DIDServiceHandler
	storage  did.Storage
}

func (d DIDService) Type() Type {
	return DID
}

// Status is a self-reporting status for the DID service.
// TODO(gabe) consider turning this into an eventing service with self-reporting status per-method
func (d DIDService) Status() Status {
	if d.storage == nil || len(d.handlers) == 0 {
		return Status{
			Status:  StatusNotReady,
			Message: "storage not loaded and/or no DID methods loaded",
		}
	}
	return Status{Status: StatusReady}
}

// DIDServiceHandler describes the functionality of *all* possible DID services, regardless of method
type DIDServiceHandler interface {
	CreateDID(request CreateDIDRequest) (*CreateDIDResponse, error)
	GetDID(id string) (*GetDIDResponse, error)
}

// CreateDIDRequest is the  SON-serializable request for creating a DID across DID methods
type CreateDIDRequest struct {
	KeyType crypto.KeyType `validate:"required"`
}

// CreateDIDResponse is the JSON-serializable response for creating a DID
type CreateDIDResponse struct {
	DID sdkdid.DIDDocument `json:"did"`
	// TODO(gabe) this is temporary, and should never be exposed like this!
	PrivateKey string `json:"base58PrivateKey"`
}

// GetDIDResponse is the JSON-serializable response for getting a DID
type GetDIDResponse struct {
	DID sdkdid.DIDDocument `json:"did"`
}

func NewDIDService(methods []DIDMethod, s did.Storage) (*DIDService, error) {
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
