package storage

import (
	"context"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/pkg/errors"
	"github.com/tbd54566975/ssi-service/pkg/service/common"
	opstorage "github.com/tbd54566975/ssi-service/pkg/service/operation/storage"
	"github.com/tbd54566975/ssi-service/pkg/service/operation/submission"
	"go.einride.tech/aip/filtering"
)

type StoredDefinition struct {
	ID                     string                          `json:"id"`
	PresentationDefinition exchange.PresentationDefinition `json:"presentationDefinition"`
	Author                 string                          `json:"issuerID"`
	AuthorKID              string                          `json:"issuerKid"`
}

type Storage interface {
	DefinitionStorage
	SubmissionStorage
}

type DefinitionStorage interface {
	StoreDefinition(ctx context.Context, presentation StoredDefinition) error
	GetDefinition(ctx context.Context, id string) (*StoredDefinition, error)
	DeleteDefinition(ctx context.Context, id string) error
	// TODO: Make this consistent across API boundaries https://github.com/TBD54566975/ssi-service/issues/449
	ListDefinitions(ctx context.Context) ([]StoredDefinition, error)
}

type StoredSubmission struct {
	Status                 submission.Status                 `json:"status"`
	Reason                 string                            `json:"reason"`
	VerifiablePresentation credential.VerifiablePresentation `json:"vp"`
}

type StoredSubmissions struct {
	Submissions   []StoredSubmission
	NextPageToken string
}

func (s StoredSubmission) FilterVariablesMap() map[string]any {
	return map[string]any{
		"status": s.Status.String(),
	}
}

type SubmissionStorage interface {
	StoreSubmission(ctx context.Context, schema StoredSubmission) error
	GetSubmission(ctx context.Context, id string) (*StoredSubmission, error)
	ListSubmissions(ctx context.Context, filter filtering.Filter, page common.Page) (*StoredSubmissions, error)
	UpdateSubmission(ctx context.Context, id string, approved bool, reason string, submissionID string) (StoredSubmission, opstorage.StoredOperation, error)
}

var ErrSubmissionNotFound = errors.New("submission not found")
