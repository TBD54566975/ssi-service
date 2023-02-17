package webhook

type Noun string
type Action string

type Webhook struct {
	WebhookNoun   Noun     `json:"webhookNoun" validate:"required"`
	WebhookAction Action   `json:"webhookAction" validate:"required"`
	Urls          []string `json:"urls" validate:"required"`
}

type CreateWebhookRequest struct {
	WebhookNoun   Noun     `json:"webhookNoun" validate:"required"`
	WebhookAction Action   `json:"webhookAction" validate:"required"`
	Urls          []string `json:"urls" validate:"required"`
}

type CreateWebhookResponse struct {
	ID      string  `json:"id"`
	Webhook Webhook `json:"webhook"`
}

type GetWebhookRequest struct {
	ID string `json:"id" validate:"required"`
}

type GetWebhookResponse struct {
	ID      string  `json:"id"`
	Webhook Webhook `json:"webhook"`
}

type GetWebhooksResponse struct {
	Webhooks []Webhook `json:"webhooks,omitempty"`
}

type DeleteWebhookRequest struct {
	ID string `json:"id" validate:"required"`
}
