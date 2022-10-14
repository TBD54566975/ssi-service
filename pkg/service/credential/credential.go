package credential

import (
	"fmt"
	"time"

	"github.com/TBD54566975/ssi-sdk/credential"
	schemalib "github.com/TBD54566975/ssi-sdk/credential/schema"
	didint "github.com/TBD54566975/ssi-sdk/did"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/config"
	credint "github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/internal/util"
	credstorage "github.com/tbd54566975/ssi-service/pkg/service/credential/storage"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type Service struct {
	storage  credstorage.Storage
	config   config.CredentialServiceConfig
	verifier *credint.Verifier

	// external dependencies
	keyStore *keystore.Service
	schema   *schema.Service
}

func (s Service) Type() framework.Type {
	return framework.Credential
}

func (s Service) Status() framework.Status {
	ae := sdkutil.NewAppendError()
	if s.storage == nil {
		ae.AppendString("no storage configured")
	}
	if s.verifier == nil {
		ae.AppendString("no credential verifier configured")
	}
	if s.keyStore == nil {
		ae.AppendString("no key store service configured")
	}
	if s.schema == nil {
		ae.AppendString("no schema service configured")
	}
	if !ae.IsEmpty() {
		return framework.Status{
			Status:  framework.StatusNotReady,
			Message: fmt.Sprintf("credential service is not ready: %s", ae.Error().Error()),
		}
	}
	return framework.Status{Status: framework.StatusReady}
}

func (s Service) Config() config.CredentialServiceConfig {
	return s.config
}

func NewCredentialService(config config.CredentialServiceConfig, s storage.ServiceStorage, keyStore *keystore.Service, didResolver *didint.Resolver, schema *schema.Service) (*Service, error) {
	credentialStorage, err := credstorage.NewCredentialStorage(s)
	if err != nil {
		errMsg := "could not instantiate storage for the credential service"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	verifier, err := credint.NewCredentialVerifier(didResolver, schema)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not instantiate verifier for the credential service")
	}
	service := Service{
		storage:  credentialStorage,
		config:   config,
		verifier: verifier,
		keyStore: keyStore,
		schema:   schema,
	}
	if !service.Status().IsReady() {
		return nil, errors.New(service.Status().Message)
	}
	return &service, nil
}

func (s Service) CreateCredential(request CreateCredentialRequest) (*CreateCredentialResponse, error) {

	logrus.Debugf("creating credential: %+v", request)

	builder := credential.NewVerifiableCredentialBuilder()

	if err := builder.SetIssuer(request.Issuer); err != nil {
		errMsg := fmt.Sprintf("could not build credential when setting issuer: %s", request.Issuer)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	// check if there's a conflict with subject ID
	if id, ok := request.Data[credential.VerifiableCredentialIDProperty]; ok && id != request.Subject {
		errMsg := fmt.Sprintf("cannot set subject<%s>, data already contains a different ID value: %s", request.Subject, id)
		return nil, util.LoggingNewError(errMsg)
	}

	// set subject value
	subject := credential.CredentialSubject(request.Data)
	subject[credential.VerifiableCredentialIDProperty] = request.Subject

	if err := builder.SetCredentialSubject(subject); err != nil {
		errMsg := fmt.Sprintf("could not set subject: %+v", subject)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	// if a context value exists, set it
	if request.Context != "" {
		if err := builder.AddContext(request.Context); err != nil {
			errMsg := fmt.Sprintf("could not add context to credential: %s", request.Context)
			return nil, util.LoggingErrorMsg(err, errMsg)
		}
	}

	// if a schema value exists, verify we can access it, validate the data against it, then set it
	var credSchema *schemalib.VCJSONSchema
	if request.JSONSchema != "" {
		// resolve schema and save it for validation later
		gotSchema, err := s.schema.GetSchema(schema.GetSchemaRequest{ID: request.JSONSchema})
		if err != nil {
			errMsg := fmt.Sprintf("failed to create credential; could not get schema: %s", request.JSONSchema)
			return nil, util.LoggingErrorMsg(err, errMsg)
		}
		credSchema = &gotSchema.Schema

		credSchema := credential.CredentialSchema{
			ID:   request.JSONSchema,
			Type: SchemaLDType,
		}
		if err = builder.SetCredentialSchema(credSchema); err != nil {
			errMsg := fmt.Sprintf("could not set JSON Schema for credential: %s", request.JSONSchema)
			return nil, util.LoggingErrorMsg(err, errMsg)
		}
	}

	// if an expiry value exists, set it
	if request.Expiry != "" {
		if err := builder.SetExpirationDate(request.Expiry); err != nil {
			errMsg := fmt.Sprintf("could not set expirty for credential: %s", request.Expiry)
			return nil, util.LoggingErrorMsg(err, errMsg)
		}
	}

	if err := builder.SetIssuanceDate(time.Now().Format(time.RFC3339)); err != nil {
		errMsg := fmt.Sprintf("could not set credential issuance date")
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	cred, err := builder.Build()
	if err != nil {
		errMsg := "could not build credential"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	// verify the built schema complies with the schema we've set
	if credSchema != nil {
		if err = schemalib.IsCredentialValidForVCJSONSchema(*cred, *credSchema); err != nil {
			errMsg := fmt.Sprintf("credential data does not comply with the provided schema: %s", request.JSONSchema)
			return nil, util.LoggingErrorMsg(err, errMsg)
		}
	}

	// TODO(gabe) support Data Integrity creds too https://github.com/TBD54566975/ssi-service/issues/105
	// sign the credential
	credJWT, err := s.signCredentialJWT(request.Issuer, *cred)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not sign credential")
	}

	// store the credential
	container := credint.Container{
		ID:            cred.ID,
		Credential:    cred,
		CredentialJWT: credJWT,
	}
	storageRequest := credstorage.StoreCredentialRequest{
		Container: container,
	}
	if err := s.storage.StoreCredential(storageRequest); err != nil {
		errMsg := "could not store credential"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	// return the result
	response := CreateCredentialResponse{Container: container}
	return &response, nil
}

// signCredentialJWT signs a credential and returns it as a vc-jwt
func (s Service) signCredentialJWT(issuer string, cred credential.VerifiableCredential) (*keyaccess.JWT, error) {
	gotKey, err := s.keyStore.GetKey(keystore.GetKeyRequest{ID: issuer})
	if err != nil {
		errMsg := fmt.Sprintf("could not get key for signing credential with key<%s>", issuer)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	keyAccess, err := keyaccess.NewJWKKeyAccess(gotKey.ID, gotKey.Key)
	if err != nil {
		errMsg := fmt.Sprintf("could not create key access for signing credential with key<%s>", gotKey.ID)
		return nil, errors.Wrap(err, errMsg)
	}
	credToken, err := keyAccess.SignVerifiableCredential(cred)
	if err != nil {
		errMsg := fmt.Sprintf("could not sign credential with key<%s>", gotKey.ID)
		return nil, errors.Wrap(err, errMsg)
	}
	return credToken, nil
}

type VerifyCredentialRequest struct {
	DataIntegrityCredential *credential.VerifiableCredential `json:"credential,omitempty"`
	CredentialJWT           *keyaccess.JWT                   `json:"credentialJwt,omitempty"`
}

// IsValid checks if the request is valid, meaning there is at least one data integrity OR jwt credential, but not both
func (vcr VerifyCredentialRequest) IsValid() error {
	if vcr.DataIntegrityCredential == nil && vcr.CredentialJWT == nil {
		return errors.New("either a credential or a credential JWT must be provided")
	}
	if vcr.DataIntegrityCredential != nil && vcr.CredentialJWT != nil {
		return errors.New("only one of credential or credential JWT can be provided")
	}
	return nil
}

type VerifyCredentialResponse struct {
	Verified bool   `json:"verified" json:"verified"`
	Reason   string `json:"reason,omitempty" json:"reason,omitempty"`
}

// VerifyCredential does three levels of verification on a credential:
// 1. Makes sure the credential has a valid signature
// 2. Makes sure the credential has is not expired
// 3. Makes sure the credential complies with the VC Data Model
// 4. If the credential has a schema, makes sure its data complies with the schema
// LATER: Makes sure the credential has not been revoked, other checks.
// Note: https://github.com/TBD54566975/ssi-sdk/issues/213
func (s Service) VerifyCredential(request VerifyCredentialRequest) (*VerifyCredentialResponse, error) {

	logrus.Debugf("verifying credential: %+v", request)

	if err := request.IsValid(); err != nil {
		return nil, util.LoggingErrorMsg(err, "invalid verify credential request")
	}

	if request.CredentialJWT != nil {
		if err := s.verifier.VerifyJWTCredential(*request.CredentialJWT); err != nil {
			return &VerifyCredentialResponse{Verified: false, Reason: err.Error()}, nil
		}
	} else {
		if err := s.verifier.VerifyDataIntegrityCredential(*request.DataIntegrityCredential); err != nil {
			return &VerifyCredentialResponse{Verified: false, Reason: err.Error()}, nil
		}
	}

	return &VerifyCredentialResponse{Verified: true}, nil
}

func (s Service) GetCredential(request GetCredentialRequest) (*GetCredentialResponse, error) {

	logrus.Debugf("getting credential: %s", request.ID)

	gotCred, err := s.storage.GetCredential(request.ID)
	if err != nil {
		errMsg := fmt.Sprintf("could not get credential: %s", request.ID)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	if !gotCred.IsValid() {
		errMsg := fmt.Sprintf("credential returned is not valid: %s", request.ID)
		return nil, util.LoggingNewError(errMsg)
	}
	response := GetCredentialResponse{
		credint.Container{
			ID:            gotCred.CredentialID,
			Credential:    gotCred.Credential,
			CredentialJWT: gotCred.CredentialJWT,
		},
	}
	return &response, nil
}

func (s Service) GetCredentialsByIssuer(request GetCredentialByIssuerRequest) (*GetCredentialsResponse, error) {

	logrus.Debugf("getting credential(s) for issuer: %s", util.SanitizeLog(request.Issuer))

	gotCreds, err := s.storage.GetCredentialsByIssuer(request.Issuer)
	if err != nil {
		errMsg := fmt.Sprintf("could not get credential(s) for issuer: %s", request.Issuer)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	var creds []credint.Container
	for _, cred := range gotCreds {
		container := credint.Container{
			ID:            cred.CredentialID,
			Credential:    cred.Credential,
			CredentialJWT: cred.CredentialJWT,
		}
		creds = append(creds, container)
	}

	response := GetCredentialsResponse{Credentials: creds}
	return &response, nil
}

func (s Service) GetCredentialsBySubject(request GetCredentialBySubjectRequest) (*GetCredentialsResponse, error) {

	logrus.Debugf("getting credential(s) for subject: %s", util.SanitizeLog(request.Subject))

	gotCreds, err := s.storage.GetCredentialsBySubject(request.Subject)
	if err != nil {
		errMsg := fmt.Sprintf("could not get credential(s) for subject: %s", request.Subject)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	var creds []credint.Container
	for _, cred := range gotCreds {
		container := credint.Container{
			ID:            cred.CredentialID,
			Credential:    cred.Credential,
			CredentialJWT: cred.CredentialJWT,
		}
		creds = append(creds, container)
	}
	response := GetCredentialsResponse{Credentials: creds}
	return &response, nil
}

func (s Service) GetCredentialsBySchema(request GetCredentialBySchemaRequest) (*GetCredentialsResponse, error) {

	logrus.Debugf("getting credential(s) for schema: %s", util.SanitizeLog(request.Schema))

	gotCreds, err := s.storage.GetCredentialsBySchema(request.Schema)
	if err != nil {
		errMsg := fmt.Sprintf("could not get credential(s) for schema: %s", request.Schema)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	var creds []credint.Container
	for _, cred := range gotCreds {
		container := credint.Container{
			ID:            cred.CredentialID,
			Credential:    cred.Credential,
			CredentialJWT: cred.CredentialJWT,
		}
		creds = append(creds, container)
	}
	response := GetCredentialsResponse{Credentials: creds}
	return &response, nil
}

func (s Service) DeleteCredential(request DeleteCredentialRequest) error {

	logrus.Debugf("deleting credential: %s", request.ID)

	if err := s.storage.DeleteCredential(request.ID); err != nil {
		errMsg := fmt.Sprintf("could not delete credential with id: %s", request.ID)
		return util.LoggingErrorMsg(err, errMsg)
	}

	return nil
}
