package storage

import (
	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/pkg/errors"
	opstorage "github.com/tbd54566975/ssi-service/pkg/service/operation/storage"
	"github.com/tbd54566975/ssi-service/pkg/service/operation/submission"
	"go.einride.tech/aip/filtering"
)

type StoredPresentation struct {
	ID                     string                          `json:"id"`
	PresentationDefinition exchange.PresentationDefinition `json:"presentationDefinition"`
}

type Storage interface {
	DefinitionStorage
	SubmissionStorage
}

type DefinitionStorage interface {
	// TODO: rename to Definition
	StorePresentation(schema StoredPresentation) error
	GetPresentation(id string) (*StoredPresentation, error)
	DeletePresentation(id string) error
}

type StoredSubmission struct {
	Status                 submission.Status                 `json:"status"`
	Reason                 string                            `json:"reason"`
	VerifiablePresentation credential.VerifiablePresentation `json:"vp"`
}

func (s StoredSubmission) FilterVariablesMap() map[string]any {
	return map[string]any{
		"status": s.Status.String(),
	}
}

type SubmissionStorage interface {
	StoreSubmission(schema StoredSubmission) error
	GetSubmission(id string) (*StoredSubmission, error)
	ListSubmissions(filtering.Filter) ([]StoredSubmission, error)
	UpdateSubmission(id string, approved bool, reason string, submissionID string) (StoredSubmission, opstorage.StoredOperation, error)
}

var ErrSubmissionNotFound = errors.New("submission not found")
