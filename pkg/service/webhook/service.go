package webhook

import (
	"context"
	"fmt"

	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type Service struct {
	storage *Storage
	config  config.WebhookServiceConfig
}

func (s Service) Type() framework.Type {
	return framework.Webhook
}

func (s Service) Status() framework.Status {
	ae := sdkutil.NewAppendError()
	if s.storage == nil {
		ae.AppendString("no storage configured")
	}

	if !ae.IsEmpty() {
		return framework.Status{
			Status:  framework.StatusNotReady,
			Message: fmt.Sprintf("webhook service is not ready: %s", ae.Error().Error()),
		}
	}
	return framework.Status{Status: framework.StatusReady}
}

func (s Service) Config() config.WebhookServiceConfig {
	return s.config
}

func NewWebhookService(config config.WebhookServiceConfig, s storage.ServiceStorage) (*Service, error) {
	webhookStorage, err := NewWebhookStorage(s)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not instantiate storage for the webhook service")
	}
	service := Service{
		storage: webhookStorage,
		config:  config,
	}
	if !service.Status().IsReady() {
		return nil, errors.New(service.Status().Message)
	}
	return &service, nil
}

func (s Service) CreateWebhook(ctx context.Context, request CreateWebhookRequest) (*CreateWebhookResponse, error) {
	logrus.Debugf("creating webhook: %+v", request)
	return nil, nil
}

func (s Service) GetWebhooks(ctx context.Context) (*GetWebhooksResponse, error) {
	logrus.Debug("getting all webhooks")
	return nil, nil
}

func (s Service) GetWebhook(ctx context.Context, request GetWebhookRequest) (*GetWebhookResponse, error) {
	logrus.Debugf("getting webhook: %s", request.ID)
	return nil, nil
}

func (s Service) DeleteWebhook(ctx context.Context, request DeleteWebhookRequest) error {
	return nil
}

func (s Service) GetSupportedNouns() GetSupportedNounsResponse {
	return GetSupportedNounsResponse{Nouns: []Noun{Credential, DID, Manifest, Schema, Presentation}}
}

func (s Service) GetSupportedVerbs() GetSupportedVerbsResponse {
	return GetSupportedVerbsResponse{Verbs: []Verb{Create, Delete}}
}
