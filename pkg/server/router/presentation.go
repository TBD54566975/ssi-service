package router

import (
	"fmt"
	"net/http"
	"time"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/gin-gonic/gin"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"go.einride.tech/aip/filtering"

	credint "github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/presentation"
	"github.com/tbd54566975/ssi-service/pkg/service/presentation/model"
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
	PresentationDefinition exchange.PresentationDefinition `json:"presentation_definition,omitempty"`

	// Signed envelope that contains the PresentationDefinition created using the privateKey of the author of the
	// definition.
	PresentationDefinitionJWT keyaccess.JWT `json:"presentationDefinitionJwt,omitempty"`
}

// CreateDefinition godoc
//
// @Summary     Create PresentationDefinition
// @Description Create presentation definition
// @Tags        PresentationDefinitionAPI
// @Accept      json
// @Produce     json
// @Param       request body     CreatePresentationDefinitionRequest true "request body"
// @Success     201     {object} CreatePresentationDefinitionResponse
// @Failure     400     {string} string "Bad request"
// @Failure     500     {string} string "Internal server error"
// @Router      /v1/presentation/definition [put]
func (pr PresentationRouter) CreateDefinition(c *gin.Context) error {
	var request CreatePresentationDefinitionRequest
	errMsg := "Invalid Presentation Definition Request"
	if err := framework.Decode(c.Request, &request); err != nil {
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
	}

	if err := framework.ValidateRequest(request); err != nil {
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
	}

	def, err := definitionFromRequest(request)
	if err != nil {
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
	}
	serviceResp, err := pr.service.CreatePresentationDefinition(c, model.CreatePresentationDefinitionRequest{
		PresentationDefinition: *def,
	})
	if err != nil {
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}

	resp := CreatePresentationDefinitionResponse{
		PresentationDefinition: serviceResp.PresentationDefinition,
	}
	return framework.Respond(c, resp, http.StatusCreated)
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
	PresentationDefinition exchange.PresentationDefinition `json:"presentation_definition,omitempty"`
}

// GetDefinition godoc
//
// @Summary     Get PresentationDefinition
// @Description Get a presentation definition by its ID
// @Tags        PresentationDefinitionAPI
// @Accept      json
// @Produce     json
// @Param       id  path     string true "ID"
// @Success     200 {object} GetPresentationDefinitionResponse
// @Failure     400 {string} string "Bad request"
// @Router      /v1/presentation/definition/{id} [get]
func (pr PresentationRouter) GetDefinition(c *gin.Context) error {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "cannot get presentation without ID parameter"
		return framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
	}

	def, err := pr.service.GetPresentationDefinition(c, model.GetPresentationDefinitionRequest{ID: *id})
	if err != nil {
		errMsg := fmt.Sprintf("could not get presentation with id: %s", *id)
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
	}

	resp := GetPresentationDefinitionResponse{
		PresentationDefinition: def.PresentationDefinition,
	}
	return framework.Respond(c, resp, http.StatusOK)
}

type ListDefinitionsRequest struct{}

type ListDefinitionsResponse struct {
	Definitions []*exchange.PresentationDefinition `json:"definitions,omitempty"`
}

// ListDefinitions godoc
//
// @Summary     List Presentation Definitions
// @Description Lists all the existing presentation definitions
// @Tags        PresentationDefinitionAPI
// @Accept      json
// @Produce     json
// @Param       request body     ListDefinitionsRequest true "request body"
// @Success     200     {object} ListDefinitionsResponse
// @Failure     400     {string} string "Bad request"
// @Failure     500     {string} string "Internal server error"
// @Router      /v1/presentations/definitions [get]
func (pr PresentationRouter) ListDefinitions(c *gin.Context) error {
	svcResponse, err := pr.service.ListDefinitions(c)
	if err != nil {
		errMsg := "could not get definitions"
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}

	resp := ListDefinitionsResponse{Definitions: svcResponse.Definitions}
	return framework.Respond(c, resp, http.StatusOK)
}

// DeleteDefinition godoc
//
// @Summary     Delete PresentationDefinition
// @Description Delete a presentation definition by its ID
// @Tags        PresentationDefinitionAPI
// @Accept      json
// @Produce     json
// @Param       id  path     string true "ID"
// @Success     204 {string} string "No Content"
// @Failure     400 {string} string "Bad request"
// @Failure     500 {string} string "Internal server error"
// @Router      /v1/presentation/definition/{id} [delete]
func (pr PresentationRouter) DeleteDefinition(c *gin.Context) error {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "cannot delete a presentation without an ID parameter"
		return framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
	}

	if err := pr.service.DeletePresentationDefinition(c, model.DeletePresentationDefinitionRequest{ID: *id}); err != nil {
		errMsg := fmt.Sprintf("could not delete presentation with id: %s", *id)
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}

	return framework.Respond(c, nil, http.StatusNoContent)
}

type CreateSubmissionRequest struct {
	// A Verifiable Presentation that's encoded as a JWT.
	// Verifiable Presentation are described in https://www.w3.org/TR/vc-data-model/#presentations-0
	// JWT encoding of the Presentation as described in https://www.w3.org/TR/vc-data-model/#presentations-0
	SubmissionJWT keyaccess.JWT `json:"submissionJwt" validate:"required"`
}

func (r CreateSubmissionRequest) toServiceRequest() (*model.CreateSubmissionRequest, error) {
	_, _, vp, err := credential.ParseVerifiablePresentationFromJWT(r.SubmissionJWT.String())
	if err != nil {
		return nil, errors.Wrap(err, "parsing presentation from jwt")
	}
	if err = vp.IsValid(); err != nil {
		return nil, errors.Wrap(err, "verifying vp validity")
	}

	submissionData, err := json.Marshal(vp.PresentationSubmission)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling presentation_submission")
	}
	var s exchange.PresentationSubmission
	if err = json.Unmarshal(submissionData, &s); err != nil {
		return nil, errors.Wrap(err, "unmarshalling presentation submission")
	}
	if err = s.IsValid(); err != nil {
		return nil, errors.Wrap(err, "verifying submission validity")
	}
	vp.PresentationSubmission = s

	credContainers, err := credint.NewCredentialContainerFromArray(vp.VerifiableCredential)
	if err != nil {
		return nil, errors.Wrap(err, "parsing verifiable credential array")
	}

	return &model.CreateSubmissionRequest{
		Presentation:  *vp,
		SubmissionJWT: r.SubmissionJWT,
		Submission:    s,
		Credentials:   credContainers}, nil
}

// CreateSubmission godoc
//
// @Summary     Create Submission
// @Description Creates a submission in this server ready to be reviewed.
// @Tags        PresentationSubmissionAPI
// @Accept      json
// @Produce     json
// @Param       request body     CreateSubmissionRequest true "request body"
// @Success     201     {object} Operation               "The type of response is Submission once the operation has finished."
// @Failure     400     {string} string                  "Bad request"
// @Failure     500     {string} string                  "Internal server error"
// @Router      /v1/presentations/submissions [put]
func (pr PresentationRouter) CreateSubmission(c *gin.Context) error {
	var request CreateSubmissionRequest
	invalidCreateSubmissionRequestErr := "invalid create submission request"
	if err := framework.Decode(c.Request, &request); err != nil {
		return framework.LoggingRespondErrWithMsg(c, err, invalidCreateSubmissionRequestErr, http.StatusBadRequest)
	}

	req, err := request.toServiceRequest()
	if err != nil {
		return framework.LoggingRespondErrWithMsg(c, err, invalidCreateSubmissionRequestErr, http.StatusBadRequest)
	}

	operation, err := pr.service.CreateSubmission(c, *req)
	if err != nil {
		errMsg := "cannot create submission"
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}

	resp := Operation{ID: operation.ID}
	return framework.Respond(c, resp, http.StatusCreated)
}

type GetSubmissionResponse struct {
	*model.Submission `json:"submission,omitempty"`
}

// GetSubmission godoc
//
// @Summary     Get Submission
// @Description Get a submission by its ID
// @Tags        PresentationSubmissionAPI
// @Accept      json
// @Produce     json
// @Param       id  path     string true "ID"
// @Success     200 {object} GetSubmissionResponse
// @Failure     400 {string} string "Bad request"
// @Router      /v1/presentations/submissions/{id} [get]
func (pr PresentationRouter) GetSubmission(c *gin.Context) error {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "get submission request requires id"
		return framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
	}

	submission, err := pr.service.GetSubmission(c, model.GetSubmissionRequest{ID: *id})
	if err != nil {
		errMsg := "failed getting submission"
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
	}
	resp := GetSubmissionResponse{Submission: &submission.Submission}
	return framework.Respond(c, resp, http.StatusOK)
}

type ListSubmissionRequest struct {
	// A standard filter expression conforming to https://google.aip.dev/160.
	// For example: `status = "done"`.
	Filter string `json:"filter,omitempty"`
}

func (l ListSubmissionRequest) GetFilter() string {
	return l.Filter
}

type ListSubmissionResponse struct {
	Submissions []model.Submission `json:"submissions,omitempty"`
}

// ListSubmissions godoc
//
// @Summary     List Submissions
// @Description List existing submissions according to a filtering query. The `filter` field follows the syntax described in https://google.aip.dev/160.
// @Tags        PresentationSubmissionAPI
// @Accept      json
// @Produce     json
// @Param       request body     ListSubmissionRequest true "request body"
// @Success     200     {object} ListSubmissionResponse
// @Failure     400     {string} string "Bad request"
// @Failure     500     {string} string "Internal server error"
// @Router      /v1/presentations/submissions [get]
func (pr PresentationRouter) ListSubmissions(c *gin.Context) error {
	var request ListSubmissionRequest
	if err := framework.Decode(c.Request, &request); err != nil {
		errMsg := "invalid list submissions request"
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
	}

	const StatusIdentifier = "status"
	declarations, err := filtering.NewDeclarations(
		filtering.DeclareFunction(filtering.FunctionEquals,
			filtering.NewFunctionOverload(
				filtering.FunctionOverloadEqualsString, filtering.TypeBool, filtering.TypeString, filtering.TypeString)),
		filtering.DeclareIdent(StatusIdentifier, filtering.TypeString),
	)
	if err != nil {
		errMsg := "creating filter declarations"
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}

	// Because parsing filters can be expensive, we limit is to a fixed len of chars. That should be more than enough
	// for most use cases.
	invalidFilterErr := "invalid filter"
	if len(request.GetFilter()) > FilterCharacterLimit {
		err = errors.Errorf("filter longer than %d character size limit", FilterCharacterLimit)
		return framework.LoggingRespondErrWithMsg(c, err, invalidFilterErr, http.StatusBadRequest)

	}
	filter, err := filtering.ParseFilter(request, declarations)
	if err != nil {
		return framework.LoggingRespondErrWithMsg(c, err, invalidFilterErr, http.StatusBadRequest)
	}
	resp, err := pr.service.ListSubmissions(c, model.ListSubmissionRequest{Filter: filter})
	if err != nil {
		errMsg := "failed listing submissions"
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}
	return framework.Respond(c, ListSubmissionResponse{Submissions: resp.Submissions}, http.StatusOK)
}

type ReviewSubmissionRequest struct {
	Approved bool   `json:"approved" validate:"required"`
	Reason   string `json:"reason,omitempty"`
}

func (r ReviewSubmissionRequest) toServiceRequest(id string) model.ReviewSubmissionRequest {
	return model.ReviewSubmissionRequest{
		ID:       id,
		Approved: r.Approved,
		Reason:   r.Reason,
	}
}

type ReviewSubmissionResponse struct {
	*model.Submission
}

// ReviewSubmission godoc
//
// @Summary     Review a pending submission
// @Description Reviews a pending submission. After this method is called, the operation with `id==presentations/submissions/{submission_id}` will be updated with the result of this invocation.
// @Tags        PresentationSubmissionAPI
// @Accept      json
// @Produce     json
// @Param       request body     ReviewSubmissionRequest true "request body"
// @Success     200     {object} ReviewSubmissionResponse
// @Failure     400     {string} string "Bad request"
// @Failure     500     {string} string "Internal server error"
// @Router      /v1/presentations/submissions/{id}/review [put]
func (pr PresentationRouter) ReviewSubmission(c *gin.Context) error {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "review submission request requires id"
		return framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
	}

	var request ReviewSubmissionRequest
	if err := framework.Decode(c.Request, &request); err != nil {
		errMsg := "invalid review submissions request"
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
	}

	req := request.toServiceRequest(*id)
	submission, err := pr.service.ReviewSubmission(c, req)
	if err != nil {
		errMsg := "failed reviewing submission"
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}
	return framework.Respond(c, ReviewSubmissionResponse{Submission: submission}, http.StatusOK)
}

const DefaultExpirationDuration = 30 * time.Minute

type CreateRequestRequest struct {
	// Audience as defined in https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.3
	// Optional
	Audience []string `json:"audience"`

	// Expiration as defined in https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.4
	// Optional. When not specified, the request will be valid for 30 minutes.
	Expiration string `json:"expiration"`

	// DID of the issuer of this presentation definition. The DID must have been previously created with the DID API,
	// or the PrivateKey must have been added independently.
	IssuerDID string `json:"issuerId" validate:"required"`

	// The privateKey associated with the KID will be used to sign an envelope that contains
	// the created presentation definition.
	IssuerKID string `json:"issuerKid" validate:"required"`

	// ID of the presentation definition to use for this request.
	PresentationDefinitionID string `json:"presentationDefinitionId" validate:"required"`
}

type CreateRequestResponse struct {
	Request *model.Request `json:"presentationRequest"`
}

type GetRequestResponse struct {
	Request *model.Request `json:"presentationRequest"`
}

// CreateRequest godoc
//
// @Summary     Create Presentation Request
// @Description Create presentation request from an existing presentation definition.
// @Tags        PresentationRequestAPI
// @Accept      json
// @Produce     json
// @Param       request body     CreateRequestRequest true "request body"
// @Success     201     {object} CreateRequestResponse
// @Failure     400     {string} string "Bad request"
// @Failure     500     {string} string "Internal server error"
// @Router      /v1/presentation/request [put]
func (pr PresentationRouter) CreateRequest(c *gin.Context) error {
	var request CreateRequestRequest
	errMsg := "Invalid Presentation Request Request"
	if err := framework.Decode(c.Request, &request); err != nil {
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
	}
	if err := framework.ValidateRequest(request); err != nil {
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
	}

	req, err := serviceRequestFromRequest(request)
	if err != nil {
		return framework.LoggingRespondError(c, err, http.StatusBadRequest)
	}

	doc, err := pr.service.CreateRequest(c, model.CreateRequestRequest{PresentationRequest: *req})
	if err != nil {
		return framework.LoggingRespondError(c, sdkutil.LoggingErrorMsg(err, "signing and storing"), http.StatusInternalServerError)
	}
	return framework.Respond(c, CreateRequestResponse{doc}, http.StatusCreated)
}

func serviceRequestFromRequest(request CreateRequestRequest) (*model.Request, error) {
	var expiration time.Time
	var err error

	if request.Expiration != "" {
		expiration, err = time.Parse(time.RFC3339, request.Expiration)
		if err != nil {
			return nil, err
		}
	} else {
		expiration = time.Now().Add(DefaultExpirationDuration)
	}

	return &model.Request{
		Audience:                 request.Audience,
		Expiration:               expiration,
		IssuerDID:                request.IssuerDID,
		KID:                      request.KID,
		PresentationDefinitionID: request.PresentationDefinitionID,
	}, nil
}

// GetRequest godoc
//
// @Summary     Get Presentation Request
// @Description Get a presentation request by its ID
// @Tags        PresentationRequestAPI
// @Accept      json
// @Produce     json
// @Param       id  path     string true "ID"
// @Success     200 {object} GetRequestResponse
// @Failure     400 {string} string "Bad request"
// @Router      /v1/presentation/request/{id} [get]
func (pr PresentationRouter) GetRequest(c *gin.Context) error {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		return framework.LoggingRespondError(c,
			sdkutil.LoggingNewError("cannot get issuance template without an ID"), http.StatusBadRequest)
	}

	request, err := pr.service.GetRequest(c, &model.GetRequestRequest{ID: *id})
	if err != nil {
		return framework.LoggingRespondError(c,
			sdkutil.LoggingErrorMsg(err, "getting issuance template"), http.StatusInternalServerError)
	}
	return framework.Respond(c, GetRequestResponse{request}, http.StatusOK)
}

// DeleteRequest godoc
//
// @Summary     Delete PresentationRequest
// @Description Delete a presentation request by its ID
// @Tags        PresentationRequestAPI
// @Accept      json
// @Produce     json
// @Param       id  path     string true "ID"
// @Success     204 {string} string "No Content"
// @Failure     400 {string} string "Bad request"
// @Failure     500 {string} string "Internal server error"
// @Router      /v1/presentation/requests/{id} [delete]
func (pr PresentationRouter) DeleteRequest(c *gin.Context) error {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "cannot delete a presentation request without an ID parameter"
		return framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
	}

	if err := pr.service.DeleteRequest(c, model.DeleteRequestRequest{ID: *id}); err != nil {
		errMsg := fmt.Sprintf("could not delete presentation request with id: %s", *id)
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}

	return framework.Respond(c, nil, http.StatusNoContent)
}
