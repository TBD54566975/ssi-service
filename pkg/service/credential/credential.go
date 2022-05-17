package credential

import (
	"fmt"
	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tbd54566975/ssi-service/config"
	credstorage "github.com/tbd54566975/ssi-service/pkg/service/credential/storage"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"time"
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

	logrus.Debugf("creating credential: %+v", request)

	builder := credential.NewVerifiableCredentialBuilder()

	if err := builder.SetIssuer(request.Issuer); err != nil {
		errMsg := fmt.Sprintf("could not build credential when setting issuer: %s", request.Issuer)
		logrus.WithError(err).Errorf(errMsg)
		return nil, errors.Wrap(err, errMsg)
	}

	// check if there's a conflict with subject ID
	if id, ok := request.Data[credential.VerifiableCredentialIDProperty]; ok && id != request.Subject {
		errMsg := fmt.Sprintf("cannot set subject<%s>, data already contains a different ID value: %s", request.Subject, id)
		logrus.Error(errMsg)
		return nil, errors.New(errMsg)
	}

	// set subject value
	subject := credential.CredentialSubject(request.Data)
	subject[credential.VerifiableCredentialIDProperty] = request.Subject

	// if a context value exists, set it
	if request.Context != "" {
		if err := builder.AddContext(request.Context); err != nil {
			errMsg := fmt.Sprintf("could not add context to credential: %s", request.Context)
			logrus.WithError(err).Error(errMsg)
			return nil, errors.Wrap(err, errMsg)
		}
	}

	// if a schema value exists, set it
	if request.JSONSchema != "" {
		schema := credential.CredentialSchema{
			ID:   request.JSONSchema,
			Type: CredentialSchemaType,
		}
		if err := builder.SetCredentialSchema(schema); err != nil {
			errMsg := fmt.Sprintf("could not set JSON Schema for credential: %s", request.JSONSchema)
			logrus.WithError(err).Error(errMsg)
			return nil, errors.Wrap(err, errMsg)
		}
	}

	// if an expiry value exists, set it
	if request.Expiry != "" {
		if err := builder.SetExpirationDate(request.Expiry); err != nil {
			errMsg := fmt.Sprintf("could not set expirty for credential: %s", request.Expiry)
			logrus.WithError(err).Error(errMsg)
			return nil, errors.Wrap(err, errMsg)
		}
	}

	if err := builder.SetIssuanceDate(time.Now().Format(time.RFC3339)); err != nil {
		errMsg := fmt.Sprintf("could not set credential issuance date")
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrap(err, errMsg)
	}

	cred, err := builder.Build()
	if err != nil {
		errMsg := "could not build credential"
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrap(err, errMsg)
	}

	// store the credential
	storageRequest := credstorage.StoredCredential{
		ID:           cred.ID,
		Credential:   *cred,
		Issuer:       request.Issuer,
		Subject:      request.Subject,
		Schema:       request.JSONSchema,
		IssuanceDate: cred.IssuanceDate,
	}
	if err := s.storage.StoreCredential(storageRequest); err != nil {
		errMsg := "could not store credential"
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrap(err, errMsg)
	}

	// return the result
	response := CreateCredentialResponse{Credential: *cred}
	return &response, nil
}

func (s Service) GetCredential(request GetCredentialRequest) (*GetCredentialResponse, error) {

	logrus.Debugf("getting credential: %s", request.ID)

	gotCred, err := s.storage.GetCredential(request.ID)
	if err != nil {
		errMsg := fmt.Sprintf("could not get credential: %s", request.ID)
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrap(err, errMsg)
	}

	response := GetCredentialResponse{Credential: gotCred.Credential}
	return &response, nil
}

func (s Service) GetCredentialsByIssuer(request GetCredentialByIssuerRequest) (*GetCredentialsResponse, error) {

	logrus.Debugf("getting credential(s) for issuer: %s", request.Issuer)

	gotCreds, err := s.storage.GetCredentialsByIssuer(request.Issuer)
	if err != nil {
		errMsg := fmt.Sprintf("could not get credential(s) for issuer: %s", request.Issuer)
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrap(err, errMsg)
	}

	var creds []credential.VerifiableCredential
	for _, cred := range gotCreds {
		creds = append(creds, cred.Credential)
	}

	response := GetCredentialsResponse{Credentials: creds}
	return &response, nil
}

func (s Service) GetCredentialsBySubject(request GetCredentialBySubjectRequest) (*GetCredentialsResponse, error) {

	logrus.Debugf("getting credential(s) for subject: %s", request.Subject)

	gotCreds, err := s.storage.GetCredentialsBySubject(request.Subject)
	if err != nil {
		errMsg := fmt.Sprintf("could not get credential(s) for subject: %s", request.Subject)
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrap(err, errMsg)
	}

	var creds []credential.VerifiableCredential
	for _, cred := range gotCreds {
		creds = append(creds, cred.Credential)
	}

	response := GetCredentialsResponse{Credentials: creds}
	return &response, nil
}

func (s Service) GetCredentialsBySchema(request GetCredentialBySchemaRequest) (*GetCredentialsResponse, error) {

	logrus.Debugf("getting credential(s) for schema: %s", request.Schema)

	gotCreds, err := s.storage.GetCredentialsBySchema(request.Schema)
	if err != nil {
		errMsg := fmt.Sprintf("could not get credential(s) for schema: %s", request.Schema)
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrap(err, errMsg)
	}

	var creds []credential.VerifiableCredential
	for _, cred := range gotCreds {
		creds = append(creds, cred.Credential)
	}

	response := GetCredentialsResponse{Credentials: creds}
	return &response, nil
}

func (s Service) DeleteCredential(request DeleteCredentialRequest) error {

	logrus.Debugf("deleting credential: %s", request.ID)

	if err := s.storage.DeleteCredential(request.ID); err != nil {
		errMsg := fmt.Sprintf("could not delete credential with id: %s", request.ID)
		logrus.WithError(err).Error(errMsg)
		return errors.Wrap(err, errMsg)
	}

	return nil
}
