package submission

import (
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/util"
)

const (
	Version1 string = "1.0"
)

type CreateSubmissionRequest struct {
	Submission exchange.PresentationSubmission `json:"submission" validate:"required"`
}

func (csr CreateSubmissionRequest) IsValid() bool {
	return util.IsValidStruct(csr) == nil
}

type CreateSubmissionResponse struct {
	Submission exchange.PresentationSubmission `json:"submission"`
}

type GetSubmissionRequest struct {
	ID string `json:"id" validate:"required"`
}

type GetSubmissionResponse struct {
	ID         string                          `json:"id"`
	Submission exchange.PresentationSubmission `json:"submission"`
}

type DeleteSubmissionRequest struct {
	ID string `json:"id" validate:"required"`
}
