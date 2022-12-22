package issuing

import (
	"github.com/pkg/errors"
	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/manifest/storage"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
	storage2 "github.com/tbd54566975/ssi-service/pkg/storage"
)

type Service struct {
	config          config.IssuingServiceConfig
	storage         Storage
	manifestStorage storage.Storage
	schemaStorage   schema.Storage
}

func NewIssuingService(config config.IssuingServiceConfig, s storage2.ServiceStorage) (*Service, error) {
	issuingStorage, err := NewIssuingStorage(s)
	if err != nil {
		return nil, errors.Wrap(err, "creating issuing storage")
	}
	manifestStorage, err := storage.NewManifestStorage(s)
	if err != nil {
		return nil, errors.Wrap(err, "creating manifest storage")
	}
	schemaStorage, err := schema.NewSchemaStorage(s)
	if err != nil {
		return nil, errors.Wrap(err, "creating manifest storage")
	}
	return &Service{
		storage:         *issuingStorage,
		config:          config,
		manifestStorage: *manifestStorage,
		schemaStorage:   *schemaStorage,
	}, nil
}

func (s *Service) GetIssuanceTemplate(request *GetIssuanceTemplateRequest) (*GetIssuanceTemplateResponse, error) {
	storedIssuanceTemplate, err := s.storage.GetIssuanceTemplate(request.ID)
	if err != nil {
		return nil, errors.Wrapf(err, "getting issuance template with id: %s", request.ID)
	}
	if storedIssuanceTemplate == nil {
		return nil, errors.Errorf("issuance template with id<%s> not be found", request.ID)
	}
	return &GetIssuanceTemplateResponse{
		IssuanceTemplate: serviceModel(*storedIssuanceTemplate)}, nil
}

func (s *Service) CreateIssuanceTemplate(request *CreateIssuanceTemplateRequest) (*IssuanceTemplate, error) {
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
		if _, err := s.schemaStorage.GetSchema(c.Schema); err != nil {
			return nil, errors.Wrapf(err, "getting schema at index %d", i)
		}
	}

	if _, err := s.manifestStorage.GetManifest(request.IssuanceTemplate.CredentialManifest); err != nil {
		return nil, errors.Wrap(err, "getting manifest")
	}

	storedTemplate := StoredIssuanceTemplate{
		IssuanceTemplate: request.IssuanceTemplate,
	}
	storedTemplate.IssuanceTemplate.ID = request.ID

	if err := s.storage.StoreIssuanceTemplate(storedTemplate); err != nil {
		return nil, errors.Wrap(err, "storing issuance template")
	}

	return serviceModel(storedTemplate), nil
}

func serviceModel(template StoredIssuanceTemplate) *IssuanceTemplate {
	return &template.IssuanceTemplate
}

func (s *Service) DeleteIssuanceTemplate(request *DeleteIssuanceTemplateRequest) error {
	if err := s.storage.DeleteIssuanceTemplate(request.ID); err != nil {
		return errors.Wrap(err, "deleting template from storage")
	}
	return nil
}

func (s *Service) ListIssuanceTemplates(request *ListIssuanceTemplatesRequest) (*ListIssuanceTemplatesResponse, error) {
	return nil, nil
}

func (s *Service) Type() framework.Type {
	return framework.Issuing
}

func (s *Service) Status() framework.Status {
	return framework.Status{Status: framework.StatusReady}
}
