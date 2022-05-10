package credential

import (
	"github.com/tbd54566975/ssi-service/config"
	credstorage "github.com/tbd54566975/ssi-service/pkg/service/credential/storage"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
)

type Service struct {
	storage credstorage.Storage
	config  config.CredentialServiceConfig
}

func (s Service) Type() framework.Type {
	return framework.Credential
}

func (s Service) Status() framework.Status {
	if s.storage == nil {
		return framework.Status{
			Status:  framework.StatusNotReady,
			Message: "no storage",
		}
	}
	return framework.Status{Status: framework.StatusReady}
}

func (s Service) Config() config.CredentialServiceConfig {
	return s.config
}

func (s Service) CreateCredential(request CreateCredentialRequest) (*CreateCredentialResponse, error) {
	return nil, nil
}

func (s Service) GetCredential(request GetCredentialRequest) (*GetCredentialResponse, error) {
	return nil, nil
}

func (s Service) GetCredentialsByIssuer(request GetCredentialByIssuerRequest) (*GetCredentialsResponse, error) {
	return nil, nil
}

func (s Service) GetCredentialsBySubject(request GetCredentialBySubjectRequest) (*GetCredentialsResponse, error) {
	return nil, nil
}

func (s Service) GetCredentialsBySchema(request GetCredentialBySchemaRequest) (*GetCredentialsResponse, error) {
	return nil, nil
}

func (s Service) DeleteCredential(request DeleteCredentialRequest) error {
	return nil
}
