package webhook

import (
	"context"

	"github.com/pkg/errors"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type Storage struct {
	db storage.ServiceStorage
}

func NewWebhookStorage(db storage.ServiceStorage) (*Storage, error) {
	if db == nil {
		return nil, errors.New("bolt db reference is nil")
	}
	return &Storage{db: db}, nil
}

func (whs *Storage) StoreWebhook(ctx context.Context, webhook Webhook) error {
	return nil
}

func (whs *Storage) GetWebhook(ctx context.Context, id string) (*Webhook, error) {
	return nil, nil
}

func (whs *Storage) GetWebhooks(ctx context.Context) ([]Webhook, error) {
	return nil, nil
}

func (whs *Storage) DeleteWebhook(ctx context.Context, id string) error {
	return nil
}
