package operation

import (
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/tbd54566975/ssi-service/pkg/server/pagination"
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

type ListOperationsRequest struct {
	Parent      string `validate:"required"`
	Filter      filtering.Filter
	PageRequest *pagination.PageRequest
}

func (r ListOperationsRequest) Validate() error {
	return util.NewValidator().Struct(r)
}

type ListOperationsResponse struct {
	Operations    []Operation
	NextPageToken string
}

type GetOperationRequest struct {
	ID string `json:"id" validate:"required"`
}

// Validate does struct validation and returns an error when invalid.
func (r GetOperationRequest) Validate() error {
	return util.NewValidator().Struct(r)
}

type CancelOperationRequest struct {
	ID string `json:"id" validate:"required"`
}

// Validate does struct validation and returns an error when invalid.
func (r CancelOperationRequest) Validate() error {
	return util.NewValidator().Struct(r)
}
