package manifest

import (
	"fmt"
	"github.com/TBD54566975/ssi-sdk/credential/manifest"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	manifeststorage "github.com/tbd54566975/ssi-service/pkg/service/manifest/storage"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type Service struct {
	storage manifeststorage.Storage
	config  config.ManifestServiceConfig
}

func (s Service) Type() framework.Type {
	return framework.Manifest
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

func (s Service) Config() config.ManifestServiceConfig {
	return s.config
}

func NewManifestService(config config.ManifestServiceConfig, s storage.ServiceStorage) (*Service, error) {
	manifestStorage, err := manifeststorage.NewManifestStorage(s)
	if err != nil {
		errMsg := "could not instantiate storage for the manifest service"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	return &Service{
		storage: manifestStorage,
		config:  config,
	}, nil
}

func (s Service) CreateManifest(request CreateManifestRequest) (*CreateManifestResponse, error) {

	logrus.Debugf("creating manifest: %+v", request)

	builder := manifest.NewCredentialManifestBuilder()

	issuer := manifest.Issuer{ID: request.Issuer}
	if err := builder.SetIssuer(issuer); err != nil {
		errMsg := fmt.Sprintf("could not build manifest when setting issuer: %s", request.Issuer)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	//// check if there's a conflict with subject ID
	//if id, ok := request.Data[credential.VerifiableCredentialIDProperty]; ok && id != request.Subject {
	//	errMsg := fmt.Sprintf("cannot set subject<%s>, data already contains a different ID value: %s", request.Subject, id)
	//	logrus.Error(errMsg)
	//	return nil, util.LoggingNewError(errMsg)
	//}
	//
	//// set subject value
	//subject := credential.CredentialSubject(request.Data)
	//subject[credential.VerifiableCredentialIDProperty] = request.Subject
	//
	//if err := builder.SetCredentialSubject(subject); err != nil {
	//	errMsg := fmt.Sprintf("could not set subject: %+v", subject)
	//	return nil, util.LoggingErrorMsg(err, errMsg)
	//}
	//
	//// if a context value exists, set it
	//if request.Context != "" {
	//	if err := builder.AddContext(request.Context); err != nil {
	//		errMsg := fmt.Sprintf("could not add context to credential: %s", request.Context)
	//		return nil, util.LoggingErrorMsg(err, errMsg)
	//	}
	//}
	//
	//// if a schema value exists, set it
	//if request.JSONSchema != "" {
	//	schema := credential.CredentialSchema{
	//		ID:   request.JSONSchema,
	//		Type: SchemaType,
	//	}
	//	if err := builder.SetCredentialSchema(schema); err != nil {
	//		errMsg := fmt.Sprintf("could not set JSON Schema for credential: %s", request.JSONSchema)
	//		return nil, util.LoggingErrorMsg(err, errMsg)
	//	}
	//}
	//
	//// if an expiry value exists, set it
	//if request.Expiry != "" {
	//	if err := builder.SetExpirationDate(request.Expiry); err != nil {
	//		errMsg := fmt.Sprintf("could not set expirty for credential: %s", request.Expiry)
	//		return nil, util.LoggingErrorMsg(err, errMsg)
	//	}
	//}
	//
	//if err := builder.SetIssuanceDate(time.Now().Format(time.RFC3339)); err != nil {
	//	errMsg := fmt.Sprintf("could not set credential issuance date")
	//	return nil, util.LoggingErrorMsg(err, errMsg)
	//}

	mfst, err := builder.Build()
	if err != nil {
		errMsg := "could not build manifest"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	// store the manifest
	storageRequest := manifeststorage.StoredManifest{
		Manifest: *mfst,
	}

	if err := s.storage.StoreManifest(storageRequest); err != nil {
		errMsg := "could not store manifest"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	// return the result
	response := CreateManifestResponse{*mfst}
	return &response, nil
}

func (s Service) GetManifest(request GetManifestRequest) (*GetManifestResponse, error) {

	logrus.Debugf("getting manifest: %s", request.ID)

	gotManifest, err := s.storage.GetManifest(request.ID)
	if err != nil {
		errMsg := fmt.Sprintf("could not get manifest: %s", request.ID)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	response := GetManifestResponse{Manifest: gotManifest.Manifest}
	return &response, nil
}

//func (s Service) GetManifestsByIssuer(request GetManifestByIssuerRequest) (*GetManifestsResponse, error) {
//
//	logrus.Debugf("getting manifest(s) for issuer: %s", util.SanitizeLog(request.Issuer))
//
//	gotCreds, err := s.storage.GetManifestsByIssuer(request.Issuer)
//	if err != nil {
//		errMsg := fmt.Sprintf("could not get credential(s) for issuer: %s", request.Issuer)
//		return nil, util.LoggingErrorMsg(err, errMsg)
//	}
//
//	var creds []credential.VerifiableCredential
//	for _, cred := range gotCreds {
//		creds = append(creds, cred.Credential)
//	}
//
//	response := GetCredentialsResponse{Credentials: creds}
//	return &response, nil
//}

func (s Service) DeleteManifest(request DeleteManifestRequest) error {

	logrus.Debugf("deleting manifest: %s", request.ID)

	if err := s.storage.DeleteManifest(request.ID); err != nil {
		errMsg := fmt.Sprintf("could not delete manifest with id: %s", request.ID)
		return util.LoggingErrorMsg(err, errMsg)
	}

	return nil
}
