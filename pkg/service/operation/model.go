package operation

import (
	"github.com/TBD54566975/ssi-sdk/util"
	"go.einride.tech/aip/filtering"
)

type Result struct {
	Error    string `json:"error,omitempty"`
	Response any    `json:"response,omitempty"`
}

type Operation struct {
	ID     string `json:"json"`
	Done   bool   `json:"done"`
	Result Result `json:"result,omitempty"`
}

type GetOperationsRequest struct {
	Parent string `validate:"required"`
	Filter filtering.Filter
}

func (r GetOperationsRequest) IsValid() error {
	return util.NewValidator().Struct(r)
}

type GetOperationsResponse struct {
	Operations []Operation
}

type GetOperationRequest struct {
	ID string `json:"id" validate:"required"`
}

// IsValid does struct validation and returns an error when invalid.
func (r GetOperationRequest) IsValid() error {
	return util.NewValidator().Struct(r)
}

type CancelOperationRequest struct {
	ID string `json:"id" validate:"required"`
}

// IsValid does struct validation and returns an error when invalid.
func (r CancelOperationRequest) IsValid() error {
	return util.NewValidator().Struct(r)
}
