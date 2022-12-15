package submission

import (
	"errors"

	credsdk "github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"go.einride.tech/aip/filtering"
)

type Status uint8

func (s Status) String() string {
	switch s {
	case StatusPending:
		return "pending"
	case StatusDenied:
		return "denied"
	case StatusApproved:
		return "approved"
	default:
		return "unknown"
	}
}

const (
	StatusUnknown Status = iota
	StatusPending
	StatusDenied
	StatusApproved
)

type StoredSubmission struct {
	Status     Status                          `json:"status"`
	Submission exchange.PresentationSubmission `json:"submission"`
	Reason     string                          `json:"reason"`
}

func (s StoredSubmission) FilterVariablesMap() map[string]any {
	return map[string]any{
		"status": s.Status.String(),
	}
}

type Submission struct {
	// One of {`pending`, `approved`, `denied`}.
	Status string `json:"status" validate:"required"`
	// The reason why the submission was approved or denied.
	Reason string `json:"reason"`
	*exchange.PresentationSubmission
}

var ErrSubmissionNotFound = errors.New("submission not found")

type CreateSubmissionRequest struct {
	Presentation  credsdk.VerifiablePresentation  `json:"presentation" validate:"required"`
	SubmissionJWT keyaccess.JWT                   `json:"submissionJwt,omitempty" validate:"required"`
	Submission    exchange.PresentationSubmission `json:"submission" validate:"required"`
	Credentials   []credential.Container          `json:"credentials,omitempty"`
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
	Submission Submission `json:"submission"`
}

type DeleteSubmissionRequest struct {
	ID string `json:"id" validate:"required"`
}

type ListSubmissionRequest struct {
	Filter filtering.Filter
}

type ListSubmissionResponse struct {
	Submissions []Submission `json:"submissions"`
}

type ReviewSubmissionRequest struct {
	ID       string `json:"id" validate:"required"`
	Approved bool   `json:"approved"`
	Reason   string `json:"reason"`
}

// Validate runs validation on the request struct and returns errors when it's invalid.
func (r ReviewSubmissionRequest) Validate() error {
	return util.NewValidator().Struct(r)
}
