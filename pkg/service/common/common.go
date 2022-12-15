package common

import (
	"errors"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
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

// ServiceModel creates a Submission from a given StoredSubmission.
func ServiceModel(storedSubmission *StoredSubmission) Submission {
	return Submission{
		Status:                 storedSubmission.Status.String(),
		Reason:                 storedSubmission.Reason,
		PresentationSubmission: &storedSubmission.Submission,
	}
}

var ErrSubmissionNotFound = errors.New("submission not found")
