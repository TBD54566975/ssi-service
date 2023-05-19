package router

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"

	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/webhook"
)

type WebhookRouter struct {
	service *webhook.Service
}

func NewWebhookRouter(s svcframework.Service) (*WebhookRouter, error) {
	if s == nil {
		return nil, errors.New("service cannot be nil")
	}
	webhookService, ok := s.(*webhook.Service)
	if !ok {
		return nil, fmt.Errorf("could not create webhook router with service type: %s", s.Type())
	}
	return &WebhookRouter{service: webhookService}, nil
}

// CreateWebhookRequest In the context of webhooks, it's common to use noun.verb notation to describe events,
// such as "credential.create" or "schema.delete".
type CreateWebhookRequest struct {
	// The noun (entity) for the new webhook.eg: Credential
	Noun webhook.Noun `json:"noun" validate:"required"`
	// The verb for the new webhook.eg: Create
	Verb webhook.Verb `json:"verb" validate:"required"`
	// The URL to post the output of this request to Noun.Verb action to.
	URL string `json:"url" validate:"required"`
}

type CreateWebhookResponse struct {
	Webhook webhook.Webhook `json:"webhook"`
}

// CreateWebhook godoc
//
//	@Summary		Create Webhook
//	@Description	Create webhook
//	@Tags			WebhookAPI
//	@Accept			json
//	@Produce		json
//	@Param			request	body		CreateWebhookRequest	true	"request body"
//	@Success		201		{object}	CreateWebhookResponse
//	@Failure		400		{string}	string	"Bad request"
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/v1/webhooks [put]
func (wr WebhookRouter) CreateWebhook(c *gin.Context) error {
	var request CreateWebhookRequest
	invalidCreateWebhookRequest := "invalid create webhook request"
	if err := framework.Decode(c.Request, &request); err != nil {
		return framework.LoggingRespondErrWithMsg(c, err, invalidCreateWebhookRequest, http.StatusBadRequest)
	}

	if err := framework.ValidateRequest(request); err != nil {
		return framework.LoggingRespondErrWithMsg(c, err, invalidCreateWebhookRequest, http.StatusBadRequest)
	}

	req := webhook.CreateWebhookRequest{Noun: request.Noun, Verb: request.Verb, URL: request.URL}
	if !req.IsValid() {
		errMsg := "invalid create webhook request. wrong noun, verb, or url format (needs http / https)"
		return framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
	}

	createWebhookResponse, err := wr.service.CreateWebhook(c, req)
	if err != nil {
		errMsg := "could not create webhook"
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}

	resp := CreateWebhookResponse{Webhook: createWebhookResponse.Webhook}
	return framework.Respond(c, resp, http.StatusCreated)
}

type GetWebhookResponse struct {
	Webhook webhook.Webhook `json:"webhook"`
}

// GetWebhook godoc
//
//	@Summary		Get Webhook
//	@Description	Get a webhook by its ID
//	@Tags			WebhookAPI
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"ID"
//	@Success		200	{object}	GetWebhookResponse
//	@Failure		400	{string}	string	"Bad request"
//	@Router			/v1/webhooks/{noun}/{verb} [get]
func (wr WebhookRouter) GetWebhook(c *gin.Context) error {
	noun := framework.GetParam(c, "noun")
	if noun == nil {
		errMsg := "cannot get webhook without noun parameter"
		return framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
	}

	verb := framework.GetParam(c, "verb")
	if verb == nil {
		errMsg := "cannot get webhook without verb parameter"
		return framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
	}

	gotWebhook, err := wr.service.GetWebhook(c, webhook.GetWebhookRequest{Noun: webhook.Noun(*noun), Verb: webhook.Verb(*verb)})
	if err != nil {
		errMsg := fmt.Sprintf("could not get webhook with id: %s-%s", *noun, *verb)
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}

	resp := GetWebhookResponse{Webhook: gotWebhook.Webhook}
	return framework.Respond(c, resp, http.StatusOK)
}

type GetWebhooksResponse struct {
	Webhooks []GetWebhookResponse `json:"webhooks,omitempty"`
}

// GetWebhooks godoc
//
//	@Summary		Get Webhooks
//	@Description	Get webhooks
//	@Tags			WebhookAPI
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	GetWebhooksResponse
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/v1/webhooks [get]
func (wr WebhookRouter) GetWebhooks(c *gin.Context) error {
	gotWebhooks, err := wr.service.GetWebhooks(c)
	if err != nil {
		errMsg := "could not get webhooks"
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}

	webhooks := make([]GetWebhookResponse, 0, len(gotWebhooks.Webhooks))
	for _, w := range gotWebhooks.Webhooks {
		webhooks = append(webhooks, GetWebhookResponse{Webhook: w})
	}

	resp := GetWebhooksResponse{Webhooks: webhooks}
	return framework.Respond(c, resp, http.StatusOK)
}

type DeleteWebhookRequest struct {
	Noun webhook.Noun `json:"noun" validate:"required"`
	Verb webhook.Verb `json:"verb" validate:"required"`
	URL  string       `json:"url" validate:"required"`
}

// DeleteWebhook godoc
//
//	@Summary		Delete Webhook
//	@Description	Delete a webhook by its ID
//	@Tags			WebhookAPI
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"ID"
//	@Success		204	{string}	string	"No Content"
//	@Failure		400	{string}	string	"Bad request"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/v1/webhooks/{noun}/{verb}/{url} [delete]
func (wr WebhookRouter) DeleteWebhook(c *gin.Context) error {
	var request DeleteWebhookRequest
	invalidCreateWebhookRequest := "invalid delete webhook request"
	if err := framework.Decode(c.Request, &request); err != nil {
		return framework.LoggingRespondErrWithMsg(c, err, invalidCreateWebhookRequest, http.StatusBadRequest)
	}

	req := webhook.DeleteWebhookRequest{Noun: request.Noun, Verb: request.Verb, URL: request.URL}
	if !req.IsValid() {
		return framework.LoggingRespondErrMsg(c, invalidCreateWebhookRequest, http.StatusBadRequest)
	}

	if err := wr.service.DeleteWebhook(c, req); err != nil {
		errMsg := fmt.Sprintf("could not delete webhook with id: %s-%s-%s", request.Noun, request.Verb, request.URL)
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}

	return framework.Respond(c, nil, http.StatusNoContent)
}

type GetSupportedNounsResponse struct {
	Nouns []webhook.Noun `json:"nouns,omitempty"`
}

// GetSupportedNouns godoc
//
//	@Summary		Get Supported Nouns
//	@Description	Get supported nouns for webhook generation
//	@Tags			WebhookAPI
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	webhook.GetSupportedNounsResponse
//	@Router			/v1/webhooks/nouns [get]
func (wr WebhookRouter) GetSupportedNouns(c *gin.Context) error {
	nouns := wr.service.GetSupportedNouns()
	return framework.Respond(c, GetSupportedNounsResponse{nouns.Nouns}, http.StatusOK)
}

type GetSupportedVerbsResponse struct {
	Verbs []webhook.Verb `json:"verbs,omitempty"`
}

// GetSupportedVerbs godoc
//
//	@Summary		Get Supported Verbs
//	@Description	Get supported verbs for webhook generation
//	@Tags			WebhookAPI
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	webhook.GetSupportedVerbsResponse
//	@Router			/v1/webhooks/verbs [get]
func (wr WebhookRouter) GetSupportedVerbs(c *gin.Context) error {
	verbs := wr.service.GetSupportedVerbs()
	return framework.Respond(c, GetSupportedVerbsResponse{verbs.Verbs}, http.StatusOK)
}
