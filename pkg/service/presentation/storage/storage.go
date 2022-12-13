package storage

import (
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/pkg/errors"
	"github.com/tbd54566975/ssi-service/internal/util"
	opstorage "github.com/tbd54566975/ssi-service/pkg/service/operation/storage"
	"github.com/tbd54566975/ssi-service/pkg/service/operation/submission"
	"github.com/tbd54566975/ssi-service/pkg/storage"
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

// NewPresentationStorage finds the presentation storage impl for a given ServiceStorage value
func NewPresentationStorage(s storage.ServiceStorage) (Storage, error) {
	switch s.Type() {
	case storage.Bolt:
		gotBolt, ok := s.(*storage.BoltDB)
		if !ok {
			return nil, util.LoggingNewErrorf("trouble instantiating : %s", s.Type())
		}
		boltStorage, err := NewBoltPresentationStorage(gotBolt)
		if err != nil {
			return nil, util.LoggingErrorMsg(err, "could not instantiate schema bolt storage")
		}
		return boltStorage, err
	default:
		return nil, util.LoggingNewErrorf("unsupported storage type: %s", s.Type())
	}
}

type StoredSubmission struct {
	Status     submission.Status               `json:"status"`
	Submission exchange.PresentationSubmission `json:"submission"`
	Reason     string                          `json:"reason"`
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
