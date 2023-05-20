package issuance

import (
	"context"

	"github.com/google/uuid"
	"github.com/pkg/errors"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	manifeststg "github.com/tbd54566975/ssi-service/pkg/service/manifest/storage"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type Service struct {
	config          config.IssuanceServiceConfig
	storage         Storage
	manifestStorage manifeststg.Storage
	schemaStorage   schema.Storage
}

func NewIssuanceService(config config.IssuanceServiceConfig, s storage.ServiceStorage) (*Service, error) {
	issuanceStorage, err := NewIssuanceStorage(s)
	if err != nil {
		return nil, errors.Wrap(err, "creating issuance storage")
	}
	manifestStorage, err := manifeststg.NewManifestStorage(s)
	if err != nil {
		return nil, errors.Wrap(err, "creating manifest storage")
	}
	schemaStorage, err := schema.NewSchemaStorage(s)
	if err != nil {
		return nil, errors.Wrap(err, "creating manifest storage")
	}
	return &Service{
		storage:         *issuanceStorage,
		config:          config,
		manifestStorage: *manifestStorage,
		schemaStorage:   *schemaStorage,
	}, nil
}

func (s *Service) GetIssuanceTemplate(ctx context.Context, request *GetIssuanceTemplateRequest) (*GetIssuanceTemplateResponse, error) {
	storedIssuanceTemplate, err := s.storage.GetIssuanceTemplate(ctx, request.ID)
	if err != nil {
		return nil, errors.Wrapf(err, "getting issuance template with id: %s", request.ID)
	}
	if storedIssuanceTemplate == nil {
		return nil, errors.Errorf("issuance template with id<%s> not be found", request.ID)
	}
	return &GetIssuanceTemplateResponse{IssuanceTemplate: serviceModel(*storedIssuanceTemplate)}, nil
}

func (s *Service) CreateIssuanceTemplate(ctx context.Context, request *CreateIssuanceTemplateRequest) (*IssuanceTemplate, error) {
	if !request.IsValid() {
		return nil, errors.New("invalid create issuance template request")
	}

	for i, c := range request.IssuanceTemplate.Credentials {
		if c.Expiry.Time != nil && c.Expiry.Duration != nil {
			return nil, errors.Errorf("Time and Duration cannot be both set simultaneously at index %d", i)
		}
		if c.ID == "" {
			return nil, errors.Errorf("ID cannot be empty at index %d", i)
		}
		if c.Schema != "" {
			if _, err := s.schemaStorage.GetSchema(ctx, c.Schema); err != nil {
				return nil, errors.Wrapf(err, "getting schema at index %d", i)
			}
		}
	}

	if _, err := s.manifestStorage.GetManifest(ctx, request.IssuanceTemplate.CredentialManifest); err != nil {
		return nil, errors.Wrap(err, "getting manifest")
	}

	storedTemplate := StoredIssuanceTemplate{
		IssuanceTemplate: request.IssuanceTemplate,
	}
	storedTemplate.IssuanceTemplate.ID = uuid.NewString()

	if err := s.storage.StoreIssuanceTemplate(ctx, storedTemplate); err != nil {
		return nil, errors.Wrap(err, "storing issuance template")
	}

	return serviceModel(storedTemplate), nil
}

func serviceModel(template StoredIssuanceTemplate) *IssuanceTemplate {
	return &template.IssuanceTemplate
}

func (s *Service) DeleteIssuanceTemplate(ctx context.Context, request *DeleteIssuanceTemplateRequest) error {
	if err := s.storage.DeleteIssuanceTemplate(ctx, request.ID); err != nil {
		return errors.Wrap(err, "deleting template from storage")
	}
	return nil
}

func (s *Service) ListIssuanceTemplates(ctx context.Context, request *ListIssuanceTemplatesRequest) (*ListIssuanceTemplatesResponse, error) {
	if err := request.Validate(); err != nil {
		return nil, errors.Wrap(err, "invalid request")
	}

	ops, err := s.storage.ListIssuanceTemplates(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "fetching ops from storage")
	}

	resp := &ListIssuanceTemplatesResponse{IssuanceTemplates: ops}
	return resp, nil
}

func (s *Service) Type() framework.Type {
	return framework.Issuance
}

func (s *Service) Status() framework.Status {
	return framework.Status{Status: framework.StatusReady}
}
