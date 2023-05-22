package issuing

import (
	"context"

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
	return &Storage{db: s}, nil
}

type StoredIssuanceTemplate struct {
	IssuanceTemplate IssuanceTemplate `json:"issuanceTemplate"`
}

func (s Storage) StoreIssuanceTemplate(ctx context.Context, template StoredIssuanceTemplate) error {
	if template.IssuanceTemplate.ID == "" {
		return errors.New("cannot store issuing template without an ID")
	}
	data, err := json.Marshal(template)
	if err != nil {
		return errors.Wrap(err, "marshalling template")
	}
	return s.db.Write(ctx, namespace, template.IssuanceTemplate.ID, data)
}

func (s Storage) GetIssuanceTemplate(ctx context.Context, id string) (*StoredIssuanceTemplate, error) {
	if id == "" {
		return nil, errors.New("cannot fetch issuing template without an ID")
	}
	data, err := s.db.Read(ctx, namespace, id)
	if err != nil {
		return nil, errors.Wrap(err, "reading from db")
	}
	if len(data) == 0 {
		return nil, errors.Errorf("issuing template not found with id: %s", id)
	}
	var st StoredIssuanceTemplate
	if err = json.Unmarshal(data, &st); err != nil {
		return nil, errors.Wrap(err, "unmarshalling template")
	}
	return &st, nil
}

func (s Storage) DeleteIssuanceTemplate(ctx context.Context, id string) error {
	if id == "" {
		return nil
	}
	if err := s.db.Delete(ctx, namespace, id); err != nil {
		return errors.Wrap(err, "deleting from db")
	}
	return nil
}

func (s Storage) ListIssuanceTemplates(ctx context.Context) ([]IssuanceTemplate, error) {
	m, err := s.db.ReadAll(ctx, namespace)
	if err != nil {
		return nil, errors.Wrap(err, "reading all")
	}
	ts := make([]IssuanceTemplate, len(m))
	i := 0
	for k, v := range m {
		if err = json.Unmarshal(v, &ts[i]); err != nil {
			return nil, errors.Wrapf(err, "unmarshalling template with key <%s>", k)
		}
		i++
	}
	return ts, nil
}

func (s Storage) GetIssuanceTemplatesByManifestID(ctx context.Context, manifestID string) ([]StoredIssuanceTemplate, error) {
	if manifestID == "" {
		return nil, errors.New("cannot find issuing template without a manifest ID")
	}
	ms, err := s.db.ReadAll(ctx, namespace)
	if err != nil {
		return nil, errors.Wrap(err, "reading all values")
	}
	var ts []StoredIssuanceTemplate
	for key, data := range ms {
		var sit StoredIssuanceTemplate
		if err := json.Unmarshal(data, &sit); err != nil {
			return nil, errors.Wrapf(err, "unmarshalling <%s>", key)
		}
		if sit.IssuanceTemplate.CredentialManifest == manifestID {
			ts = append(ts, sit)
		}
	}
	return ts, nil
}
