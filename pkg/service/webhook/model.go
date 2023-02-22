package webhook

// In the context of webhooks, it's common to use noun.verb notation to describe events,
// such as "credential.create" or "schema.delete".
type Noun string
type Verb string

type Webhook struct {
	ID   string   `json:"id" validate:"required"`
	Noun Noun     `json:"noun" validate:"required"`
	Verb Verb     `json:"verb" validate:"required"`
	Urls []string `json:"urls" validate:"required"`
}

type CreateWebhookRequest struct {
	Noun Noun     `json:"noun" validate:"required"`
	Verb Verb     `json:"verb" validate:"required"`
	Urls []string `json:"urls" validate:"required"`
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

type GetSupportedNounsResponse struct {
	Nouns []Noun `json:"nouns,omitempty"`
}

type GetSupportedVerbsResponse struct {
	Verbs []Verb `json:"verbs,omitempty"`
}
