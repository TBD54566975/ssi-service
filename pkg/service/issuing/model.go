package issuing

import (
	"time"

	"github.com/pkg/errors"
	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type GetIssuanceTemplateRequest struct {
	ID string `json:"id" validate:"required"`
}

type CredentialTemplateData struct {
	// ID of the input descriptor in the application. Correponds to one of the
	// PresentationDefinition.InputDescriptors[].ID in the credential manifest.
	CredentialInputDescriptor string `json:"credentialInputDescriptor"`

	// The set of information that will be used to create claims.
	Claims ClaimTemplates
}

type TimeLike struct {
	// For fixed time in the future.
	*time.Time

	// For a fixed offset from when it was issued.
	*time.Duration
}

type ClaimTemplates struct {
	// Values may be json path like strings, or any other JSON primitive. Each entry will be used to come up with a
	// claim about the credentialSubject in the credential that will be issued.
	Data map[string]any
}

type CredentialTemplate struct {
	// ID corresponding to an OutputDescriptor.ID from the manifest.
	ID string `json:"id"`

	// ID of the CredentialSchema to be used for the issued credential.
	Schema string `json:"schema"`

	// Date that will be used to determine credential claims.
	Data CredentialTemplateData `json:"data"`

	// Parameter to determine the expiry of the credential.
	Expiry TimeLike `json:"expiry"`

	// Whether the credentials created should be revocable.
	Revocable bool `json:"revocable"`
}

type IssuanceTemplate struct {
	// ID of the credential manifest that this template corresponds to.
	CredentialManifest string `json:"credentialManifest"`

	// ID of the issuer that will be issuing the credentials.
	Issuer string `json:"issuer"`

	// Info required to create a credential from a credential application.
	Credentials []CredentialTemplate `json:"credentials"`
}

type GetIssuanceTemplateResponse struct {
	IssuanceTemplate IssuanceTemplate `json:"issuanceTemplate"`
}

type CreateIssuanceTemplateRequest struct {
	ID               string           `json:"id" validate:"required"`
	IssuanceTemplate IssuanceTemplate `json:"issuanceTemplate"`
}

type DeleteIssuanceTemplateRequest struct {
	ID string `json:"id" validate:"required"`
}

type Service struct {
	config  config.IssuingServiceConfig
	storage Storage
}

func (s *Service) Type() framework.Type {
	return framework.Issuing
}

func (s *Service) Status() framework.Status {
	return framework.Status{Status: framework.StatusReady}
}

func NewIssuingService(config config.IssuingServiceConfig, s storage.ServiceStorage) (*Service, error) {
	issuingStorage, err := NewIssuingStorage(s)
	if err != nil {
		return nil, errors.Wrap(err, "creating issuing storage")
	}
	return &Service{
		storage: *issuingStorage,
		config:  config,
	}, nil
}

type Storage struct {
	db storage.ServiceStorage
}

func NewIssuingStorage(s storage.ServiceStorage) (*Storage, error) {
	if s == nil {
		return nil, errors.New("s cannot be nil")
	}
	return &Storage{
		db: s,
	}, nil
}

func (s *Service) GetIssuanceTemplate(request *GetIssuanceTemplateRequest) (*GetIssuanceTemplateResponse, error) {
	return nil, nil
}

func (s *Service) CreateIssuanceTemplate(request *CreateIssuanceTemplateRequest) (*IssuanceTemplate, error) {
	return nil, nil
}

func (s *Service) DeleteIssuanceTemplate(request *DeleteIssuanceTemplateRequest) error {
	return nil
}
