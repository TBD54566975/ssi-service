package router

import (
	"context"
	"fmt"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/credential/signing"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	credint "github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/presentation"
	"net/http"
)

type PresentationRouter struct {
	service *presentation.Service
}

func NewPresentationRouter(s svcframework.Service) (*PresentationRouter, error) {
	if s == nil {
		return nil, errors.New("service cannot be nil")
	}
	service, ok := s.(*presentation.Service)
	if !ok {
		return nil, fmt.Errorf("could not create presentation router with service type: %s", s.Type())
	}
	return &PresentationRouter{service: service}, nil
}

type CreatePresentationDefinitionRequest struct {
	Name                   string                           `json:"name,omitempty"`
	Purpose                string                           `json:"purpose,omitempty"`
	Format                 *exchange.ClaimFormat            `json:"format,omitempty" validate:"omitempty,dive"`
	InputDescriptors       []exchange.InputDescriptor       `json:"inputDescriptors" validate:"required,dive"`
	SubmissionRequirements []exchange.SubmissionRequirement `json:"submissionRequirements,omitempty" validate:"omitempty,dive"`
}

type CreatePresentationDefinitionResponse struct {
	PresentationDefinition exchange.PresentationDefinition `json:"presentation_definition"`
}

// CreatePresentationDefinition godoc
// @Summary      Create PresentationDefinition
// @Description  Create presentation definition
// @Tags         PresentationDefinitionAPI
// @Accept       json
// @Produce      json
// @Param        request  body      CreatePresentationDefinitionRequest  true  "request body"
// @Success      201      {object}  CreatePresentationDefinitionResponse
// @Failure      400      {string}  string  "Bad request"
// @Failure      500      {string}  string  "Internal server error"
// @Router       /v1/presentation/definition [put]
func (pr PresentationRouter) CreatePresentationDefinition(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	var request CreatePresentationDefinitionRequest
	errMsg := "Invalid Presentation Definition Request"
	if err := framework.Decode(r, &request); err != nil {
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	if err := framework.ValidateRequest(request); err != nil {
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	def, err := definitionFromRequest(request)
	if err != nil {
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}
	serviceResp, err := pr.service.CreatePresentationDefinition(presentation.CreatePresentationDefinitionRequest{PresentationDefinition: *def})
	if err != nil {
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	resp := CreatePresentationDefinitionResponse{
		PresentationDefinition: serviceResp.PresentationDefinition,
	}
	return framework.Respond(ctx, w, resp, http.StatusCreated)
}

func definitionFromRequest(request CreatePresentationDefinitionRequest) (*exchange.PresentationDefinition, error) {
	b := exchange.NewPresentationDefinitionBuilder()
	if err := b.SetName(request.Name); err != nil {
		return nil, err
	}
	if err := b.SetPurpose(request.Purpose); err != nil {
		return nil, err
	}
	if request.Format != nil {
		if err := b.SetClaimFormat(*request.Format); err != nil {
			return nil, err
		}
	}
	if len(request.SubmissionRequirements) > 0 {
		if err := b.SetSubmissionRequirements(request.SubmissionRequirements); err != nil {
			return nil, err
		}
	}
	if len(request.InputDescriptors) > 0 {
		if err := b.SetInputDescriptors(request.InputDescriptors); err != nil {
			return nil, err
		}
	}

	req, err := b.Build()
	if err != nil {
		return nil, err
	}
	return req, nil
}

type GetPresentationDefinitionResponse struct {
	PresentationDefinition exchange.PresentationDefinition `json:"presentation_definition"`
}

// GetPresentationDefinition godoc
// @Summary      Get PresentationDefinition
// @Description  Get a presentation definition by its ID
// @Tags         PresentationDefinitionAPI
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "ID"
// @Success      200  {object}  GetPresentationDefinitionResponse
// @Failure      400  {string}  string  "Bad request"
// @Router       /v1/presentation/definition/{id} [get]
func (pr PresentationRouter) GetPresentationDefinition(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		errMsg := "cannot get presentation without ID parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	def, err := pr.service.GetPresentationDefinition(presentation.GetPresentationDefinitionRequest{ID: *id})
	if err != nil {
		errMsg := fmt.Sprintf("could not get presentation with id: %s", *id)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	resp := GetPresentationDefinitionResponse{
		PresentationDefinition: def.PresentationDefinition,
	}
	return framework.Respond(ctx, w, resp, http.StatusOK)
}

// DeletePresentationDefinition godoc
// @Summary      Delete PresentationDefinition
// @Description  Delete a presentation definition by its ID
// @Tags         PresentationDefinitionAPI
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "ID"
// @Success      200  {string}  string  "OK"
// @Failure      400  {string}  string  "Bad request"
// @Failure      500  {string}  string  "Internal server error"
// @Router       /v1/presentation/definition/{id} [delete]
func (pr PresentationRouter) DeletePresentationDefinition(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		errMsg := "cannot delete a presentation without an ID parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	if err := pr.service.DeletePresentationDefinition(presentation.DeletePresentationDefinitionRequest{ID: *id}); err != nil {
		errMsg := fmt.Sprintf("could not delete presentation with id: %s", *id)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	return framework.Respond(ctx, w, nil, http.StatusOK)
}

type CreateSubmissionRequest struct {
	SubmissionJWT keyaccess.JWT `json:"submissionJwt" validate:"required"`
}

func (r CreateSubmissionRequest) toServiceRequest() (*presentation.CreateSubmissionRequest, error) {
	sdkVp, err := signing.ParseVerifiablePresentationFromJWT(r.SubmissionJWT.String())
	if err != nil {
		return nil, errors.Wrap(err, "parsing presentation from jwt")
	}
	if err := sdkVp.IsValid(); err != nil {
		return nil, errors.Wrap(err, "verifying vp validity")
	}

	submissionData, err := json.Marshal(sdkVp.PresentationSubmission)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling presentation_submission")
	}
	var s exchange.PresentationSubmission
	if err := json.Unmarshal(submissionData, &s); err != nil {
		return nil, errors.Wrap(err, "unmarshalling presentation submission")
	}
	if err := s.IsValid(); err != nil {
		return nil, errors.Wrap(err, "verifying submission validity")
	}
	sdkVp.PresentationSubmission = s

	credContainers, err := credint.NewCredentialContainerFromArray(sdkVp.VerifiableCredential)
	if err != nil {
		return nil, errors.Wrap(err, "parsing verifiable credential array")
	}

	return &presentation.CreateSubmissionRequest{
		Presentation:  *sdkVp,
		SubmissionJWT: r.SubmissionJWT,
		Submission:    s,
		Credentials:   credContainers}, nil
}

type Operation struct {
	ID     string          `json:"id"`
	Done   bool            `json:"done"`
	Result OperationResult `json:"result,omitempty"`
}

type OperationResult struct {
	Error    string                          `json:"error,omitempty"`
	Response exchange.PresentationSubmission `json:"response,omitempty"`
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
func (pr PresentationRouter) CreateSubmission(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	var request CreateSubmissionRequest
	if err := framework.Decode(r, &request); err != nil {
		return framework.NewRequestError(util.LoggingErrorMsg(err, "invalid create submission request"), http.StatusBadRequest)
	}

	req, err := request.toServiceRequest()
	if err != nil {
		return framework.NewRequestError(util.LoggingErrorMsg(err, "invalid create submission request"), http.StatusBadRequest)
	}

	operation, err := pr.service.CreateSubmission(*req)
	if err != nil {
		return framework.NewRequestError(util.LoggingErrorMsg(err, "cannot create submission"), http.StatusInternalServerError)
	}

	resp := Operation{
		ID: operation.ID,
	}
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
func (pr PresentationRouter) GetSubmission(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
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
// @Description  List existing submissions according to a filtering query. The `filter` field follows the syntax described in https://google.aip.dev/160.
// @Tags         SubmissionAPI
// @Accept       json
// @Produce      json
// @Param        request  body      ListSubmissionRequest  true  "request body"
// @Success      200  {object}  ListSubmissionResponse
// @Failure      400  {string}  string  "Bad request"
// @Failure      500  {string}  string  "Internal server error"
// @Router       /v1/presentations/submissions [get]
func (pr PresentationRouter) ListSubmissions(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	return framework.Respond(ctx, w, ListSubmissionResponse{}, http.StatusOK)
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
func (pr PresentationRouter) ReviewSubmission(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	return framework.Respond(ctx, w, ReviewSubmissionResponse{}, http.StatusOK)
}
