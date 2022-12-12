package operation

import (
	"fmt"

	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/tbd54566975/ssi-service/pkg/service/operation/storage"
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

func (r GetOperationsRequest) Validate() error {
	return util.NewValidator().Struct(r)
}

type GetOperationsResponse struct {
	Operations []Operation
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

// IDFromSubmissionID returns a submission operation ID from the submission ID.
func IDFromSubmissionID(id string) string {
	return fmt.Sprintf("%s/%s", storage.SubmissionParentResource, id)
}
