package issuing

import (
	"github.com/goccy/go-json"
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

func (s Storage) StoreIssuanceTemplate(template StoredIssuanceTemplate) error {
	if template.IssuanceTemplate.ID == "" {
		return errors.New("cannot store issuance template without an ID")
	}
	data, err := json.Marshal(template)
	if err != nil {
		return errors.Wrap(err, "marshalling template")
	}
	return s.db.Write(namespace, template.IssuanceTemplate.ID, data)
}

func (s Storage) GetIssuanceTemplate(id string) (*StoredIssuanceTemplate, error) {
	if id == "" {
		return nil, errors.New("cannot fetch issuance template without an ID")
	}
	data, err := s.db.Read(namespace, id)
	if err != nil {
		return nil, errors.Wrap(err, "reading from db")
	}
	if len(data) == 0 {
		return nil, errors.Errorf("issuance template not found with id: %s", id)
	}
	var st StoredIssuanceTemplate
	if err = json.Unmarshal(data, &st); err != nil {
		return nil, errors.Wrap(err, "unmarshalling template")
	}
	return &st, nil
}
