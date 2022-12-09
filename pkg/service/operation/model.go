package operation

import (
	"fmt"
	"github.com/TBD54566975/ssi-sdk/util"
	"go.einride.tech/aip/filtering"
	"strings"
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

// SubmissionID attempts to parse the submission id from the ID of the operation. This is done by taking the last word
// that results from splitting the id by "/". On failures, the empty string is returned.
func SubmissionID(opID string) string {
	i := strings.LastIndex(opID, "/")
	if i == -1 {
		return ""
	}
	return opID[(i + 1):]
}

type GetOperationsRequest struct {
	Parent string
	Filter filtering.Filter
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

const SubmissionOperationPrefix = "/presentations/submissions"

// IDFromSubmissionID returns a submission operation ID from the submission ID.
func IDFromSubmissionID(id string) string {
	return fmt.Sprintf("%s/%s", SubmissionOperationPrefix, id)
}
