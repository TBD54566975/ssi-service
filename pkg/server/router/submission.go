package router

import (
	"context"
	"fmt"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
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

type CreateSubmissionResponse struct {
	// TODO(andres): return an operation here.
	Status     string                          `json:"status"`
	Submission exchange.PresentationSubmission `json:"submission"`
}

// CreateSubmission godoc
// @Summary      Create Submission
// @Description  Creates a submission in this server ready to be reviewed.
// @Tags         SubmissionAPI
// @Accept       json
// @Produce      json
// @Param        request  body      CreateSubmissionRequest  true  "request body"
// @Success      201      {object}  CreateSubmissionResponse
// @Failure      400      {string}  string  "Bad request"
// @Failure      500      {string}  string  "Internal server error"
// @Router       /v1/presentations/submissions [put]
func (sr SubmissionRouter) CreateSubmission(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	var request CreateSubmissionRequest
	errMsg := "Invalid create submission request"
	if err := framework.Decode(r, &request); err != nil {
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	if err := framework.ValidateRequest(request); err != nil {
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	// TODO: convert from request.PresentationJwt
	s := exchange.PresentationSubmission{
		ID:           "dummy value",
		DefinitionID: "another dummy",
		DescriptorMap: []exchange.SubmissionDescriptor{
			{
				ID:         "what?",
				Format:     "jwt_vp",
				Path:       "ohhh yeah",
				PathNested: nil,
			},
		},
	}

	req := submission.CreateSubmissionRequest{
		Submission: s,
	}
	sub, err := sr.service.CreateSubmission(req)
	if err != nil {
		errMsg := fmt.Sprintf("could not create submission definition")
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	resp := CreateSubmissionResponse{Status: "pending", Submission: sub.Submission}
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
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		errMsg := "cannot get submission without ID parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	def, err := sr.service.GetSubmission(submission.GetSubmissionRequest{ID: *id})
	if err != nil {
		errMsg := fmt.Sprintf("could not get submission with id: %s", *id)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}
	// TODO(andres): introduce not found errors that can be mapped to 404.

	resp := GetSubmissionResponse{
		Submission: def.Submission,
	}
	return framework.Respond(ctx, w, resp, http.StatusOK)
}

// DeleteSubmission godoc
// @Summary      Delete Submission
// @Description  Delete a submission by its ID
// @Tags         SubmissionAPI
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "ID"
// @Success      200  {string}  string  "OK"
// @Failure      400  {string}  string  "Bad request"
// @Failure      500  {string}  string  "Internal server error"
// @Router       /v1/presentations/submissions/{id} [delete]
func (sr SubmissionRouter) DeleteSubmission(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		errMsg := "cannot delete a submission without an ID parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	if err := sr.service.DeleteSubmission(submission.DeleteSubmissionRequest{ID: *id}); err != nil {
		errMsg := fmt.Sprintf("could not delete submission with id: %s", *id)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	return framework.Respond(ctx, w, nil, http.StatusOK)
}
