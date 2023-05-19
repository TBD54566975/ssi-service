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

type StoredDefinition struct {
	ID                     string                          `json:"id"`
	PresentationDefinition exchange.PresentationDefinition `json:"presentationDefinition"`
	Author                 string                          `json:"issuerID"`
	AuthorKID              string                          `json:"issuerKid"`
}

type Storage interface {
	DefinitionStorage
	RequestStorage
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

func (s StoredSubmission) FilterVariablesMap() map[string]any {
	return map[string]any{
		"status": s.Status.String(),
	}
}

type SubmissionStorage interface {
	StoreSubmission(ctx context.Context, schema StoredSubmission) error
	GetSubmission(ctx context.Context, id string) (*StoredSubmission, error)
	ListSubmissions(ctx context.Context, filter filtering.Filter) ([]StoredSubmission, error)
	UpdateSubmission(ctx context.Context, id string, approved bool, reason string, submissionID string) (StoredSubmission, opstorage.StoredOperation, error)
}

var ErrSubmissionNotFound = errors.New("submission not found")

type StoredRequest struct {
	ID                        string   `json:"id"`
	Audience                  []string `json:"audience"`
	Expiration                string   `json:"expiration"`
	IssuerDID                 string   `json:"issuerId"`
	IssuerKID                 string   `json:"issuerKid"`
	PresentationDefinitionID  string   `json:"presentationDefinitionId"`
	PresentationDefinitionJWT string   `json:"presentationRequestJwt"`
}

type RequestStorage interface {
	StoreRequest(context.Context, StoredRequest) error
	GetRequest(context.Context, string) (*StoredRequest, error)
	DeleteRequest(context.Context, string) error
}
