package issuing

import (
	"github.com/pkg/errors"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type Storage struct {
	db storage.ServiceStorage
}

const namespace = "issuance_template"

func NewIssuingStorage(s storage.ServiceStorage) (*Storage, error) {
	if s == nil {
		return nil, errors.New("s cannot be nil")
	}
	return &Storage{
		db: s,
	}, nil
}

type StoredIssuanceTemplate struct {
	IssuanceTemplate IssuanceTemplate
}
