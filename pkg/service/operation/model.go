package operation

import (
	"github.com/TBD54566975/ssi-sdk/util"
	"go.einride.tech/aip/filtering"
	"strings"
)

type Result struct {
	Error    string      `json:"error,omitempty"`
	Response interface{} `json:"response,omitempty"`
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
	Parent string `validate:"required"`
	Filter filtering.Filter
}

func (r GetOperationsRequest) Validate() error {
	return util.NewValidator().Struct(r)
}

type GetOperationsResponse struct {
	Operations []Operation
}
