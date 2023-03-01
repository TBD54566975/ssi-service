package webhook

import (
	"fmt"
	"net/url"
)

// In the context of webhooks, it's common to use noun.verb notation to describe events,
// such as "credential.create" or "schema.delete".
type Noun string
type Verb string

const (
	// Supported Nouns
	Credential   = Noun("Credential")
	DID          = Noun("DID")
	Manifest     = Noun("Manifest")
	Schema       = Noun("Schema")
	Presentation = Noun("Presentation")

	// Supported Verbs
	Create = Verb("Create")
	Delete = Verb("Delete")
)

type Webhook struct {
	Noun Noun     `json:"noun" validate:"required"`
	Verb Verb     `json:"verb" validate:"required"`
	URLS []string `json:"urls" validate:"required"`
}

type Payload struct {
	Noun Noun   `json:"noun" validate:"required"`
	Verb Verb   `json:"verb" validate:"required"`
	URL  string `json:"url" validate:"required"`
	Data any    `json:"data,omitempty"`
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

type GetWebhooksResponse struct {
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

func (cwr DeleteWebhookRequest) IsValid() bool {
	fmt.Println(cwr)
	if isValidNoun(cwr.Noun) && isValidVerb(cwr.Verb) && isValidURL(cwr.URL) {
		return true
	}
	return false
}

func (cwr CreateWebhookRequest) IsValid() bool {
	fmt.Println(cwr)
	if isValidNoun(cwr.Noun) && isValidVerb(cwr.Verb) && isValidURL(cwr.URL) {
		return true
	}
	return false
}

func isValidNoun(noun Noun) bool {
	switch noun {
	case Credential, DID, Manifest, Schema, Presentation:
		return true
	}
	return false
}

func isValidVerb(verb Verb) bool {
	switch verb {
	case Create, Delete:
		return true
	}
	return false
}

func isValidURL(urlStr string) bool {
	parsedURL, err := url.Parse(urlStr)
	return err == nil && parsedURL.Scheme != "" && parsedURL.Host != ""
}
