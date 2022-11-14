package router

import (
	"context"
	"fmt"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/pkg/errors"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/submission"
	"net/http"
)

type SubmissionRouter struct {
	service *submission.Service
}

func NewSubmissionRouter(s svcframework.Service) (*SubmissionRouter, error) {
	if s == nil {
		return nil, errors.New("service cannot be nil")
	}
	service, ok := s.(*submission.Service)
	if !ok {
		return nil, fmt.Errorf("could not create submission router with service type: %s", s.Type())
	}
	return &SubmissionRouter{service: service}, nil
}

type CreateSubmissionRequest struct {
	PresentationJwt keyaccess.JWT `json:"presentationJwt" validate:"required"`
}

type Operation struct {
	ID     string          `json:"id"`
	Done   bool            `json:"bool"`
	Result OperationResult `json:"result"`
}

type OperationResult struct {
	Error    string                          `json:"error"`
	Response exchange.PresentationSubmission `json:"response"`
}

// CreateSubmission godoc
// @Summary      Create Submission
// @Description  Creates a submission in this server ready to be reviewed.
// @Tags         SubmissionAPI
// @Accept       json
// @Produce      json
// @Param        request  body      CreateSubmissionRequest  true  "request body"
// @Success      201      {object}  Operation
// @Failure      400      {string}  string  "Bad request"
// @Failure      500      {string}  string  "Internal server error"
// @Router       /v1/presentations/submissions [put]
func (sr SubmissionRouter) CreateSubmission(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	var resp Operation
	return framework.Respond(ctx, w, resp, http.StatusCreated)
}

type GetSubmissionResponse struct {
	Submission exchange.PresentationSubmission `json:"submission"`
}

// GetSubmission godoc
// @Summary      Get Submission
// @Description  Get a submission by its ID
// @Tags         SubmissionAPI
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "ID"
// @Success      200  {object}  GetSubmissionResponse
// @Failure      400  {string}  string  "Bad request"
// @Router       /v1/presentations/submission/{id} [get]
func (sr SubmissionRouter) GetSubmission(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	var resp GetSubmissionResponse
	return framework.Respond(ctx, w, resp, http.StatusOK)
}

type ListSubmissionRequest struct {
	Filter string `json:"filter"`
}

type ListSubmissionResponse struct {
	Submissions []exchange.PresentationSubmission `json:"submissions"`
}

// ListSubmissions godoc
// @Summary      List Submissions
// @Description  List existing submissions according to a filtering query.
// @Tags         SubmissionAPI
// @Accept       json
// @Produce      json
// @Param        request  body      ListSubmissionRequest  true  "request body"
// @Success      200  {object}  ListSubmissionResponse
// @Failure      400  {string}  string  "Bad request"
// @Failure      500  {string}  string  "Internal server error"
// @Router       /v1/presentations/submissions [get]
func (sr SubmissionRouter) ListSubmissions(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	return framework.Respond(ctx, w, ListSubmissionRequest{}, http.StatusOK)
}

type ReviewSubmissionRequest struct {
	Approved bool   `json:"approved" validate:"required"`
	Reason   string `json:"reason"`
}

type ReviewSubmissionResponse struct {
	Submission exchange.PresentationSubmission `json:"submission"`
}

// ReviewSubmission godoc
// @Summary      Review a pending submissions
// @Description  Reviews a pending submission. After this method is called, the operation with `id==presentations/submissions/{submission_id}` will be updated with the result of this invocation.
// @Tags         SubmissionAPI
// @Accept       json
// @Produce      json
// @Param        request  body      ReviewSubmissionRequest  true  "request body"
// @Success      200  {object}  ReviewSubmissionResponse
// @Failure      400  {string}  string  "Bad request"
// @Failure      500  {string}  string  "Internal server error"
// @Router       /v1/presentations/submissions [get]
func (sr SubmissionRouter) ReviewSubmission(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	return framework.Respond(ctx, w, ReviewSubmissionResponse{}, http.StatusOK)
}
