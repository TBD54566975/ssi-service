package webhook

import (
	"encoding/json"
	"net/url"
)

// In the context of webhooks, it's common to use noun.verb notation to describe events,
// such as "credential.create" or "schema.delete".
type (
	Noun string
	Verb string
)

// Supported Nouns
const (
	Credential   = Noun("Credential")
	DID          = Noun("DID")
	Manifest     = Noun("Manifest")
	Schema       = Noun("SchemaID")
	Presentation = Noun("Presentation")
	Application  = Noun("Application")
	Submission   = Noun("Submission")
)

// Supported Verbs
const (
	BatchCreate = Verb("BatchCreate")
	Create      = Verb("Create")
	Delete      = Verb("Delete")
)

type Webhook struct {
	Noun Noun     `json:"noun" validate:"required"`
	Verb Verb     `json:"verb" validate:"required"`
	URLS []string `json:"urls" validate:"required"`
}

type Payload struct {
	Noun Noun            `json:"noun" validate:"required"`
	Verb Verb            `json:"verb" validate:"required"`
	URL  string          `json:"url" validate:"required"`
	Data json.RawMessage `json:"data,omitempty"`
}

type CreateWebhookRequest struct {
	Noun Noun   `json:"noun" validate:"required"`
	Verb Verb   `json:"verb" validate:"required"`
	URL  string `json:"url" validate:"required"`
}

type CreateWebhookResponse struct {
	Webhook Webhook `json:"webhook"`
}

type GetWebhookRequest struct {
	Noun Noun `json:"noun" validate:"required"`
	Verb Verb `json:"verb" validate:"required"`
}

type GetWebhookResponse struct {
	Webhook Webhook `json:"webhook"`
}

type ListWebhooksResponse struct {
	Webhooks []Webhook `json:"webhooks,omitempty"`
}

type DeleteWebhookRequest struct {
	Noun Noun   `json:"noun" validate:"required"`
	Verb Verb   `json:"verb" validate:"required"`
	URL  string `json:"url" validate:"required"`
}

type GetSupportedNounsResponse struct {
	Nouns []Noun `json:"nouns,omitempty"`
}

type GetSupportedVerbsResponse struct {
	Verbs []Verb `json:"verbs,omitempty"`
}

func (wh Webhook) IsEmpty() bool {
	if wh.URLS != nil && len(wh.URLS) > 0 && wh.Noun == "" && wh.Verb == "" {
		return true
	}
	return false
}

func (cwr DeleteWebhookRequest) IsValid() bool {
	if cwr.Noun.IsValid() && cwr.Verb.isValid() && isValidURL(cwr.URL) {
		return true
	}
	return false
}

func (cwr CreateWebhookRequest) IsValid() bool {
	if cwr.Noun.IsValid() && cwr.Verb.isValid() && isValidURL(cwr.URL) {
		return true
	}
	return false
}

func (n Noun) IsValid() bool {
	switch n {
	case Credential, DID, Manifest, Schema, Presentation, Application, Submission:
		return true
	}
	return false
}

func (v Verb) isValid() bool {
	switch v {
	case Create, Delete:
		return true
	default:
		return false
	}
}

// isValidURL checks if there were any errors during parsing and if the parsed DIDWebID has a non-empty Scheme and Host.
// currently we support any scheme including http, https, ftp ...
func isValidURL(urlStr string) bool {
	parsedURL, err := url.Parse(urlStr)
	return err == nil && parsedURL.Scheme != "" && parsedURL.Host != ""
}
