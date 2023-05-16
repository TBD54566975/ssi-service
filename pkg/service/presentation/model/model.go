package model

import (
	credsdk "github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"go.einride.tech/aip/filtering"

	"github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/pkg/service/presentation/storage"
)

type CreatePresentationRequestRequest struct {
	PresentationDefinition exchange.PresentationDefinition `json:"presentationDefinition" validate:"required"`
	Author                 string                          `json:"author" validate:"required"`
	AuthorKID              string                          `json:"authorKid" validate:"required"`
}

func (cpr CreatePresentationRequestRequest) IsValid() error {
	return util.IsValidStruct(cpr)
}

type CreatePresentationRequestResponse struct {
	PresentationRequest    exchange.PresentationDefinitionEnvelope `json:"presentationRequest"`
	PresentationRequestJWT keyaccess.JWT                           `json:"presentationRequestJWT"`
}

type GetPresentationRequestRequest struct {
	ID string `json:"id" validate:"required"`
}

type GetPresentationRequestResponse struct {
	ID                     string                                  `json:"id"`
	PresentationRequest    exchange.PresentationDefinitionEnvelope `json:"presentationRequest"`
	PresentationRequestJWT keyaccess.JWT                           `json:"presentationRequestJWT"`
}

type DeletePresentationRequestRequest struct {
	ID string `json:"id" validate:"required"`
}

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

type Submission struct {
	// One of {`pending`, `approved`, `denied`, `cancelled`}.
	Status string `json:"status" validate:"required"`
	// The reason why the submission was approved or denied.
	Reason string `json:"reason"`
	// The verifiable presentation containing the presentation_submission along with the credentials presented.
	VerifiablePresentation *credsdk.VerifiablePresentation `json:"verifiablePresentation,omitempty"`
}

func (r Submission) GetSubmission() *exchange.PresentationSubmission {
	switch m := r.VerifiablePresentation.PresentationSubmission.(type) {
	case exchange.PresentationSubmission:
		return &m
	case *exchange.PresentationSubmission:
		return m
	case map[string]any:
		var ts *exchange.PresentationSubmission
		data, _ := json.Marshal(m)
		_ = json.Unmarshal(data, &ts)
		return ts
	default:
		return nil
	}
}

type ListSubmissionResponse struct {
	Submissions []Submission `json:"submissions"`
}

type ListPresentationRequestsResponse struct {
	Requests []*exchange.PresentationDefinitionEnvelope `json:"requests"`
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

// ServiceModel creates a Submission from a given StoredSubmission.
func ServiceModel(storedSubmission *storage.StoredSubmission) Submission {
	return Submission{
		Status:                 storedSubmission.Status.String(),
		Reason:                 storedSubmission.Reason,
		VerifiablePresentation: &storedSubmission.VerifiablePresentation,
	}
}
