package storage

import (
	"go.einride.tech/aip/filtering"
)

type StoredOperation struct {
	ID string `json:"id"`

	// Whether this operation has finished.
	Done bool `json:"done"`

	// Populated when there was an error with the operation.
	Error string `json:"errorResult,omitempty"`

	// Populated only when Done == true and Error == ""
	Response []byte `json:"response,omitempty"`
}

func (s StoredOperation) FilterVariablesMap() map[string]any {
	return map[string]any{
		"done": s.Done,
		// "true" and "false" are currently being parsed as identifiers, so we need to pass in the values that they
		// evaluate to. Ideally, we should change them to be parsed as constants. That requires an upstream change in
		// the filtering library.
		"true":  true,
		"false": false,
	}
}

type Storage interface {
	StoreOperation(op StoredOperation) error
	GetOperation(id string) (StoredOperation, error)
	GetOperations(parent string, filter filtering.Filter) ([]StoredOperation, error)
	DeleteOperation(id string) error
	CancelOperation(id string) (*StoredOperation, error)
}
