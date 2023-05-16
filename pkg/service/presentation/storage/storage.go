package storage

import (
	"context"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/pkg/errors"
	opstorage "github.com/tbd54566975/ssi-service/pkg/service/operation/storage"
	"github.com/tbd54566975/ssi-service/pkg/service/operation/submission"
	"go.einride.tech/aip/filtering"
)

type StoredPresentationRequest struct {
	ID                     string                          `json:"id"`
	PresentationDefinition exchange.PresentationDefinition `json:"presentationDefinition"`
	Author                 string                          `json:"issuerID"`
	AuthorKID              string                          `json:"issuerKid"`
}

type Storage interface {
	RequestStorage
	SubmissionStorage
}

type RequestStorage interface {
	StorePresentationRequest(ctx context.Context, schema StoredPresentationRequest) error
	GetPresentationRequest(ctx context.Context, id string) (*StoredPresentationRequest, error)
	DeletePresentationRequest(ctx context.Context, id string) error
	ListPresentationRequests(ctx context.Context) ([]StoredPresentationRequest, error)
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
	StoreSubmission(ctx context.Context, schema StoredSubmission) error
	GetSubmission(ctx context.Context, id string) (*StoredSubmission, error)
	ListSubmissions(context.Context, filtering.Filter) ([]StoredSubmission, error)
	UpdateSubmission(ctx context.Context, id string, approved bool, reason string, submissionID string) (StoredSubmission, opstorage.StoredOperation, error)
}

var ErrSubmissionNotFound = errors.New("submission not found")
