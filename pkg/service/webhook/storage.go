package webhook

import (
	"context"

	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/pkg/storage"
)

const webhookNamespace = "webhook"

type Storage struct {
	db storage.ServiceStorage
}

func NewWebhookStorage(db storage.ServiceStorage) (*Storage, error) {
	if db == nil {
		return nil, errors.New("db reference is nil")
	}
	return &Storage{db: db}, nil
}

func (whs *Storage) StoreWebhook(ctx context.Context, noun, verb string, webhook Webhook) error {
	storedWebhookBytes, err := json.Marshal(webhook)
	if err != nil {
		return sdkutil.LoggingErrorMsg(err, "webhook marshal")
	}
	return whs.db.Write(ctx, webhookNamespace, getWebhookKey(noun, verb), storedWebhookBytes)
}

func (whs *Storage) GetWebhook(ctx context.Context, noun, verb string) (*Webhook, error) {
	webhookBytes, err := whs.db.Read(ctx, webhookNamespace, getWebhookKey(noun, verb))
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "read db")
	}

	if webhookBytes == nil || len(webhookBytes) == 0 {
		return nil, nil
	}

	var webhook Webhook
	if err = json.Unmarshal(webhookBytes, &webhook); err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "unmarshalling webhoook with key: %s", getWebhookKey(noun, verb))
	}
	return &webhook, nil
}

func (whs *Storage) ListWebhooks(ctx context.Context) ([]Webhook, error) {
	gotWebhooks, err := whs.db.ReadAll(ctx, webhookNamespace)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not get all webhooks")
	}

	var webhooks []Webhook
	for _, webhookBytes := range gotWebhooks {
		var webhook Webhook
		if err = json.Unmarshal(webhookBytes, &webhook); err == nil {
			webhooks = append(webhooks, webhook)
		} else {
			logrus.WithError(err).Warn("unmarshal webhook")
		}
	}

	return webhooks, nil
}

func (whs *Storage) DeleteWebhook(ctx context.Context, noun, verb string) error {
	return whs.db.Delete(ctx, webhookNamespace, getWebhookKey(noun, verb))
}

func getWebhookKey(noun, verb string) string {
	return noun + ":" + verb
}
