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

type CredentialData struct {
	CredentialInputDescriptor string `json:"credentialInputDescriptor"`
	Claims                    Claims
}

type TimeLike struct {
	// For fixed time in the future.
	*time.Time

	// For a fixed offset from when it was issued.
	*time.Duration
}

type Claims struct {
	// Values may be json path like strings, or any other JSON primitive.
	Data map[string]any
}

type Credential struct {
	ID        string         `json:"id"`
	Schema    string         `json:"schema"`
	Data      CredentialData `json:"data"`
	Expiry    TimeLike       `json:"expiry"`
	Revocable bool           `json:"revocable"`
}

type IssuanceTemplate struct {
	CredentialManifest string       `json:"credentialManifest"`
	Issuer             string       `json:"issuer"`
	Credentials        []Credential `json:"credentials"`
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
