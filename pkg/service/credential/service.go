package credential

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/TBD54566975/ssi-sdk/credential"
	schemalib "github.com/TBD54566975/ssi-sdk/credential/schema"
	statussdk "github.com/TBD54566975/ssi-sdk/credential/status"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/config"
	credint "github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type Service struct {
	storage  *Storage
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

func NewCredentialService(config config.CredentialServiceConfig, s storage.ServiceStorage, keyStore *keystore.Service, didResolver *didsdk.Resolver, schema *schema.Service) (*Service, error) {
	credentialStorage, err := NewCredentialStorage(s)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not instantiate storage for the credential service")
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

func (s Service) CreateCredential(ctx context.Context, request CreateCredentialRequest) (*CreateCredentialResponse, error) {
	watchKeys := make([]storage.WatchKey, 0)

	var slcMetadata StatusListCredentialMetadata

	if request.hasStatus() && request.isStatusValid() {

		statusPurpose := statussdk.StatusRevocation

		if request.Suspendable {
			statusPurpose = statussdk.StatusSuspension
		}

		statusListCredentialWatchKey := s.storage.GetStatusListCredentialWatchKey(request.Issuer, request.JSONSchema, string(statusPurpose))
		statusListCredentialIndexPoolWatchKey := s.storage.GetStatusListIndexPoolWatchKey(request.Issuer, request.JSONSchema, string(statusPurpose))
		statusListCredentialCurrentIndexWatchKey := s.storage.GetStatusListCurrentIndexWatchKey(request.Issuer, request.JSONSchema, string(statusPurpose))

		watchKeys = append(watchKeys, statusListCredentialWatchKey)
		watchKeys = append(watchKeys, statusListCredentialIndexPoolWatchKey)
		watchKeys = append(watchKeys, statusListCredentialCurrentIndexWatchKey)

		slcMetadata = StatusListCredentialMetadata{statusListCredentialWatchKey: statusListCredentialWatchKey, statusListIndexPoolWatchKey: statusListCredentialIndexPoolWatchKey, statusListCurrentIndexWatchKey: statusListCredentialCurrentIndexWatchKey}
	}

	returnFunc := s.createCredentialFunc(request, slcMetadata)

	returnValue, err := s.storage.db.Execute(ctx, returnFunc, watchKeys)

	if err != nil {
		return nil, errors.Wrap(err, "execute")
	}

	credResponse, ok := returnValue.(*CreateCredentialResponse)
	if !ok {
		return nil, errors.New("Problem with casting to CreateCredentialResponse")
	}

	return credResponse, nil
}

func (s Service) createCredentialFunc(request CreateCredentialRequest, slcMetadata StatusListCredentialMetadata) storage.BusinessLogicFunc {
	return func(ctx context.Context, tx storage.Tx) (any, error) {
		return s.createCredentialBusinessLogic(ctx, request, tx, slcMetadata)
	}
}

func (s Service) createCredentialBusinessLogic(ctx context.Context, request CreateCredentialRequest, tx storage.Tx, slcMetadata StatusListCredentialMetadata) (*CreateCredentialResponse, error) {
	logrus.Debugf("creating credential: %+v", request)

	if !request.isStatusValid() {
		return nil, util.LoggingNewError("credential may have at most one status")
	}

	builder := credential.NewVerifiableCredentialBuilder()

	if err := builder.SetIssuer(request.Issuer); err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not build credential when setting issuer: %s", request.Issuer)
	}

	// check if there's a conflict with subject ID
	if id, ok := request.Data[credential.VerifiableCredentialIDProperty]; ok && id != request.Subject {
		return nil, util.LoggingNewErrorf("cannot set subject<%s>, data already contains a different ID value: %s", request.Subject, id)
	}

	// set subject value
	subject := credential.CredentialSubject(request.Data)
	subject[credential.VerifiableCredentialIDProperty] = request.Subject

	if err := builder.SetCredentialSubject(subject); err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not set subject: %+v", subject)
	}

	// if a context value exists, set it
	if request.Context != "" {
		if err := builder.AddContext(request.Context); err != nil {
			return nil, util.LoggingErrorMsgf(err, "could not add context to credential: %s", request.Context)
		}
	}

	// if a schema value exists, verify we can access it, validate the data against it, then set it
	var knownSchema *schemalib.VCJSONSchema
	if request.JSONSchema != "" {
		// resolve schema and save it for validation later
		gotSchema, err := s.schema.GetSchema(ctx, schema.GetSchemaRequest{ID: request.JSONSchema})
		if err != nil {
			return nil, util.LoggingErrorMsgf(err, "failed to create credential; could not get schema: %s", request.JSONSchema)
		}
		knownSchema = &gotSchema.Schema

		credSchema := credential.CredentialSchema{
			ID:   request.JSONSchema,
			Type: SchemaLDType,
		}
		if err = builder.SetCredentialSchema(credSchema); err != nil {
			return nil, util.LoggingErrorMsgf(err, "could not set JSON Schema for credential: %s", request.JSONSchema)
		}
	}

	// if an expiry value exists, set it
	if request.Expiry != "" {
		if err := builder.SetExpirationDate(request.Expiry); err != nil {
			return nil, util.LoggingErrorMsgf(err, "could not set expiry for credential: %s", request.Expiry)
		}
	}

	if err := builder.SetIssuanceDate(time.Now().Format(time.RFC3339)); err != nil {
		errMsg := fmt.Sprintf("could not set credential issuance date")
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	if request.hasStatus() {

		credID := builder.ID
		issuerID := request.Issuer
		schemaID := request.JSONSchema

		statusPurpose := statussdk.StatusRevocation

		if request.Suspendable {
			statusPurpose = statussdk.StatusSuspension
		}

		var slCredential *credential.VerifiableCredential
		var statusListCredentialID string
		var randomIndex int
		var err error

		statusListCredential, err := s.storage.GetStatusListCredentialKeyData(
			ctx,
			issuerID,
			schemaID,
			statusPurpose,
		)
		if err != nil {
			return nil, errors.Wrap(err, "getting status list credential key data")
		}

		if statusListCredential == nil {
			// creates status list credential with random index
			randomIndex, slCredential, err = createStatusListCredential(ctx, tx, s, statusPurpose, issuerID, schemaID, slcMetadata)
			if err != nil {
				return nil, util.LoggingErrorMsgf(err, "problem with getting status list credential")
			}

			statusListCredentialID = slCredential.ID
		} else {
			randomIndex, err = s.storage.GetNextStatusListRandomIndex(ctx, slcMetadata)
			if err != nil {
				return nil, util.LoggingErrorMsg(err, "problem with getting status list index")
			}

			statusListCredentialID = statusListCredential.Credential.ID

			if err := s.storage.IncrementStatusListIndexTx(ctx, tx, slcMetadata); err != nil {
				return nil, errors.Wrap(err, "incrementing status list index")
			}
		}

		status := statussdk.StatusList2021Entry{
			ID:                   fmt.Sprintf(`%s/v1/credentials/%s/status`, s.config.ServiceEndpoint, credID),
			Type:                 statussdk.StatusList2021EntryType,
			StatusPurpose:        statusPurpose,
			StatusListIndex:      strconv.Itoa(randomIndex),
			StatusListCredential: statusListCredentialID,
		}

		if err := builder.SetCredentialStatus(status); err != nil {
			return nil, util.LoggingErrorMsg(err, "could not set credential status")
		}
	}

	cred, err := builder.Build()
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not build credential")
	}

	// verify the built schema complies with the schema we've set
	if knownSchema != nil {
		if err = schemalib.IsCredentialValidForVCJSONSchema(*cred, *knownSchema); err != nil {
			return nil, util.LoggingErrorMsgf(err, "credential data does not comply with the provided schema: %s", request.JSONSchema)
		}
	}

	// TODO(gabe) support Data Integrity creds too https://github.com/TBD54566975/ssi-service/issues/105
	credJWT, err := s.signCredentialJWT(ctx, request.Issuer, *cred)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not sign credential")
	}

	container := credint.Container{
		ID:            cred.ID,
		Credential:    cred,
		CredentialJWT: credJWT,
		Revoked:       false,
		Suspended:     false,
	}

	credentialStorageRequest := StoreCredentialRequest{
		Container: container,
	}

	if err = s.storage.StoreCredentialTx(ctx, tx, credentialStorageRequest); err != nil {
		return nil, util.LoggingErrorMsg(err, "failed to save vc")
	}

	response := CreateCredentialResponse{Container: container}
	return &response, nil
}

func createStatusListCredential(ctx context.Context, tx storage.Tx, s Service, statusPurpose statussdk.StatusPurpose, issuerID string, schemaID string, slcMetadata StatusListCredentialMetadata) (int, *credential.VerifiableCredential, error) {
	statusListID := fmt.Sprintf("%s/v1/credentials/status/%s", s.config.ServiceEndpoint, uuid.NewString())

	generatedStatusListCredential, err := statussdk.GenerateStatusList2021Credential(statusListID, issuerID, statusPurpose, []credential.VerifiableCredential{})
	if err != nil {
		return -1, nil, util.LoggingErrorMsg(err, "could not generate status list")
	}

	if schemaID != "" {
		credSchema := credential.CredentialSchema{
			ID:   schemaID,
			Type: SchemaLDType,
		}
		generatedStatusListCredential.CredentialSchema = &credSchema
	}

	statusListCredJWT, err := s.signCredentialJWT(ctx, issuerID, *generatedStatusListCredential)
	if err != nil {
		return -1, nil, util.LoggingErrorMsg(err, "could not sign status list credential")
	}

	statusListContainer := credint.Container{
		ID:            generatedStatusListCredential.ID,
		Credential:    generatedStatusListCredential,
		CredentialJWT: statusListCredJWT,
	}

	statusListStorageRequest := StoreCredentialRequest{
		Container: statusListContainer,
	}

	randomIndex, err := s.storage.CreateStatusListCredentialTx(ctx, tx, statusListStorageRequest, slcMetadata)
	if err != nil {
		return -1, nil, errors.Wrap(err, "creating status list credential")
	}

	return randomIndex, generatedStatusListCredential, nil
}

// signCredentialJWT signs a credential and returns it as a vc-jwt
func (s Service) signCredentialJWT(ctx context.Context, issuer string, cred credential.VerifiableCredential) (*keyaccess.JWT, error) {
	gotKey, err := s.keyStore.GetKey(ctx, keystore.GetKeyRequest{ID: issuer})
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get key for signing credential with key<%s>", issuer)
	}
	keyAccess, err := keyaccess.NewJWKKeyAccess(gotKey.ID, gotKey.Key)
	if err != nil {
		return nil, errors.Wrapf(err, "could not create key access for signing credential with key<%s>", gotKey.ID)
	}
	credToken, err := keyAccess.SignVerifiableCredential(cred)
	if err != nil {
		return nil, errors.Wrapf(err, "could not sign credential with key<%s>", gotKey.ID)
	}
	return credToken, nil
}

type VerifyCredentialRequest struct {
	DataIntegrityCredential *credential.VerifiableCredential `json:"credential,omitempty"`
	CredentialJWT           *keyaccess.JWT                   `json:"credentialJwt,omitempty"`
}

// IsValid checks if the request is valid, meaning there is at least one data integrity (with proof)
// OR jwt credential, but not both
func (vcr VerifyCredentialRequest) IsValid() error {
	if vcr.DataIntegrityCredential == nil && vcr.CredentialJWT == nil {
		return errors.New("either a credential or a credential JWT must be provided")
	}
	if (vcr.DataIntegrityCredential != nil && vcr.DataIntegrityCredential.Proof != nil) && vcr.CredentialJWT != nil {
		return errors.New("only one of credential or credential JWT can be provided")
	}
	return nil
}

type VerifyCredentialResponse struct {
	Verified bool   `json:"verified"`
	Reason   string `json:"reason,omitempty"`
}

// VerifyCredential does three levels of verification on a credential:
// 1. Makes sure the credential has a valid signature
// 2. Makes sure the credential has is not expired
// 3. Makes sure the credential complies with the VC Data Model
// 4. If the credential has a schema, makes sure its data complies with the schema
// LATER: Makes sure the credential has not been revoked, other checks.
// Note: https://github.com/TBD54566975/ssi-sdk/issues/213
func (s Service) VerifyCredential(ctx context.Context, request VerifyCredentialRequest) (*VerifyCredentialResponse, error) {

	logrus.Debugf("verifying credential: %+v", request)

	if err := request.IsValid(); err != nil {
		return nil, util.LoggingErrorMsg(err, "invalid verify credential request")
	}

	if request.CredentialJWT != nil {
		if err := s.verifier.VerifyJWTCredential(ctx, *request.CredentialJWT); err != nil {
			return &VerifyCredentialResponse{Verified: false, Reason: err.Error()}, nil
		}
	} else {
		if err := s.verifier.VerifyDataIntegrityCredential(ctx, *request.DataIntegrityCredential); err != nil {
			return &VerifyCredentialResponse{Verified: false, Reason: err.Error()}, nil
		}
	}

	return &VerifyCredentialResponse{Verified: true}, nil
}

func (s Service) GetCredential(ctx context.Context, request GetCredentialRequest) (*GetCredentialResponse, error) {

	logrus.Debugf("getting credential: %s", request.ID)

	gotCred, err := s.storage.GetCredential(ctx, request.ID)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get credential: %s", request.ID)
	}
	if !gotCred.IsValid() {
		return nil, util.LoggingNewErrorf("credential returned is not valid: %s", request.ID)
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

func (s Service) GetCredentialsByIssuer(ctx context.Context, request GetCredentialByIssuerRequest) (*GetCredentialsResponse, error) {

	logrus.Debugf("getting credential(s) for issuer: %s", util.SanitizeLog(request.Issuer))

	gotCreds, err := s.storage.GetCredentialsByIssuer(ctx, request.Issuer)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get credential(s) for issuer: %s", request.Issuer)
	}

	creds := make([]credint.Container, 0, len(gotCreds))
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

func (s Service) GetCredentialsBySubject(ctx context.Context, request GetCredentialBySubjectRequest) (*GetCredentialsResponse, error) {

	logrus.Debugf("getting credential(s) for subject: %s", util.SanitizeLog(request.Subject))

	gotCreds, err := s.storage.GetCredentialsBySubject(ctx, request.Subject)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get credential(s) for subject: %s", request.Subject)
	}

	creds := make([]credint.Container, 0, len(gotCreds))
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

func (s Service) GetCredentialsBySchema(ctx context.Context, request GetCredentialBySchemaRequest) (*GetCredentialsResponse, error) {

	logrus.Debugf("getting credential(s) for schema: %s", util.SanitizeLog(request.Schema))

	gotCreds, err := s.storage.GetCredentialsBySchema(ctx, request.Schema)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get credential(s) for schema: %s", request.Schema)
	}

	creds := make([]credint.Container, 0, len(gotCreds))
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

func (s Service) GetCredentialStatus(ctx context.Context, request GetCredentialStatusRequest) (*GetCredentialStatusResponse, error) {
	logrus.Debugf("getting credential status: %s", request.ID)

	gotCred, err := s.storage.GetCredential(ctx, request.ID)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get credential: %s", request.ID)
	}
	if !gotCred.IsValid() {
		return nil, util.LoggingNewErrorf("credential returned is not valid: %s", request.ID)
	}
	response := GetCredentialStatusResponse{
		Revoked: gotCred.Revoked,
	}
	return &response, nil
}

func (s Service) GetCredentialStatusList(ctx context.Context, request GetCredentialStatusListRequest) (*GetCredentialStatusListResponse, error) {
	logrus.Debugf("getting credential status list: %s", request.ID)

	gotCred, err := s.storage.GetStatusListCredential(ctx, request.ID)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get credential: %s", request.ID)
	}
	if !gotCred.IsValid() {
		return nil, util.LoggingNewErrorf("credential returned is not valid: %s", request.ID)
	}
	response := GetCredentialStatusListResponse{
		credint.Container{
			ID:            gotCred.CredentialID,
			Credential:    gotCred.Credential,
			CredentialJWT: gotCred.CredentialJWT,
		},
	}
	return &response, nil
}

func (s Service) UpdateCredentialStatus(ctx context.Context, request UpdateCredentialStatusRequest) (*UpdateCredentialStatusResponse, error) {
	gotCred, err := s.storage.GetCredential(ctx, request.ID)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get credential: %s", request.ID)
	}

	statusPurpose := gotCred.Credential.CredentialStatus.(map[string]any)["statusPurpose"].(string)
	if len(statusPurpose) == 0 {
		return nil, util.LoggingNewErrorf("status purpose could not be derived from credential status")
	}

	statusListCredential, err := s.storage.GetStatusListCredentialKeyData(ctx, gotCred.Issuer, gotCred.Schema, statussdk.StatusPurpose(statusPurpose))
	if err != nil {
		return nil, errors.Wrap(err, "getting status list watch key uuid data")
	}

	if statusListCredential == nil {
		return nil, errors.Wrap(err, "status list credential should exist in order to update")
	}

	statusListCredentialWatchKey := s.storage.GetStatusListCredentialWatchKey(gotCred.Issuer, gotCred.Schema, statusPurpose)

	slcMetadata := StatusListCredentialMetadata{statusListCredentialWatchKey: statusListCredentialWatchKey}

	watchKeys := []storage.WatchKey{statusListCredentialWatchKey}
	returnFunc := s.updateCredentialStatusFunc(request, slcMetadata)

	returnValue, err := s.storage.db.Execute(ctx, returnFunc, watchKeys)
	if err != nil {
		return nil, errors.Wrap(err, "execute")
	}

	credResponse, ok := returnValue.(*UpdateCredentialStatusResponse)
	if !ok {
		return nil, errors.New("casting to UpdateCredentialStatusResponse")
	}

	return credResponse, nil
}

func (s Service) updateCredentialStatusFunc(request UpdateCredentialStatusRequest, slcMetadata StatusListCredentialMetadata) storage.BusinessLogicFunc {
	return func(ctx context.Context, tx storage.Tx) (any, error) {
		return s.updateCredentialStatusBusinessLogic(ctx, tx, request, slcMetadata)
	}
}

func (s Service) updateCredentialStatusBusinessLogic(ctx context.Context, tx storage.Tx, request UpdateCredentialStatusRequest, slcMetadata StatusListCredentialMetadata) (*UpdateCredentialStatusResponse, error) {
	logrus.Debugf("updating credential status: %s to Revoked: %v", request.ID, request.Revoked)

	if request.Suspended && request.Revoked {
		return nil, util.LoggingNewErrorf("cannot update both suspended and revoked status")
	}

	gotCred, err := s.storage.GetCredential(ctx, request.ID)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get credential: %s", request.ID)
	}
	if !gotCred.IsValid() {
		return nil, util.LoggingNewErrorf("credential returned is not valid: %s", request.ID)
	}

	// if the request is the same as what the current credential is there is no action
	if gotCred.Revoked == request.Revoked && gotCred.Suspended == request.Suspended {
		logrus.Warn("request and credential have same status, no action is needed")
		response := UpdateCredentialStatusResponse{Revoked: gotCred.Revoked, Suspended: gotCred.Suspended}
		return &response, nil
	}

	container, err := updateCredentialStatus(ctx, tx, s, gotCred, request, slcMetadata)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "updating credential")
	}

	response := UpdateCredentialStatusResponse{Revoked: container.Revoked, Suspended: container.Suspended}
	return &response, nil
}

func updateCredentialStatus(ctx context.Context, tx storage.Tx, s Service, gotCred *StoredCredential, request UpdateCredentialStatusRequest, slcMetadata StatusListCredentialMetadata) (*credint.Container, error) {
	// store the credential with updated status
	container := credint.Container{
		ID:            gotCred.ID,
		Credential:    gotCred.Credential,
		CredentialJWT: gotCred.CredentialJWT,
		Revoked:       request.Revoked,
		Suspended:     request.Suspended,
	}

	storageRequest := StoreCredentialRequest{
		Container: container,
	}

	if err := s.storage.StoreCredentialTx(ctx, tx, storageRequest); err != nil {
		return nil, util.LoggingErrorMsg(err, "could not store credential")
	}

	statusListCredentialID := gotCred.Credential.CredentialStatus.(map[string]any)["statusListCredential"].(string)

	if len(statusListCredentialID) == 0 {
		return nil, util.LoggingNewErrorf("problem with getting status list credential id")
	}

	creds, err := s.storage.GetCredentialsByIssuerAndSchema(ctx, gotCred.Issuer, gotCred.Schema)
	if err != nil {
		return nil, util.LoggingNewErrorf("problem with getting status list credential for issuer: %s schema: %s", gotCred.Issuer, gotCred.Schema)
	}

	var revokedOrSuspendedStatusCreds []credential.VerifiableCredential
	for _, cred := range creds {
		// we add the current cred to the creds list based on request, not on what could be in stale database that the tx has not updated yet
		if cred.Credential.ID == gotCred.Credential.ID {
			continue
		}

		if request.Revoked && cred.Credential.CredentialStatus != nil && cred.Revoked {
			revokedOrSuspendedStatusCreds = append(revokedOrSuspendedStatusCreds, *cred.Credential)
		} else if request.Suspended && cred.Credential.CredentialStatus != nil && cred.Suspended {
			revokedOrSuspendedStatusCreds = append(revokedOrSuspendedStatusCreds, *cred.Credential)
		}
	}

	// add current one since it has not been saved yet and wont be available in the creds array
	if request.Revoked == true || request.Suspended == true {
		revokedOrSuspendedStatusCreds = append(revokedOrSuspendedStatusCreds, *gotCred.Credential)
	}

	statusPurpose := statussdk.StatusRevocation

	if request.Suspended {
		statusPurpose = statussdk.StatusSuspension
	}

	generatedStatusListCredential, err := statussdk.GenerateStatusList2021Credential(statusListCredentialID, gotCred.Issuer, statusPurpose, revokedOrSuspendedStatusCreds)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not generate status list")
	}

	generatedStatusListCredential.CredentialSchema = gotCred.Credential.CredentialSchema

	statusListCredJWT, err := s.signCredentialJWT(ctx, gotCred.Issuer, *generatedStatusListCredential)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not sign status list credential")
	}

	// store the status list credential
	statusListContainer := credint.Container{
		ID:            generatedStatusListCredential.ID,
		Credential:    generatedStatusListCredential,
		CredentialJWT: statusListCredJWT,
	}

	storageRequest = StoreCredentialRequest{
		Container: statusListContainer,
	}

	if err = s.storage.StoreStatusListCredentialTx(ctx, tx, storageRequest, slcMetadata); err != nil {
		return nil, util.LoggingErrorMsg(err, "could not store credential status list")
	}

	return &container, nil
}

func (s Service) GetCredentialsByIssuerAndSchemaWithStatus(ctx context.Context, issuer string, schema string) ([]credential.VerifiableCredential, error) {
	gotCreds, err := s.storage.GetCredentialsByIssuerAndSchema(ctx, issuer, schema)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get credential(s) for issuer: %s", issuer)
	}

	var creds []credential.VerifiableCredential
	for _, cred := range gotCreds {
		if cred.Credential.CredentialStatus != nil {
			creds = append(creds, *cred.Credential)
		}
	}

	return creds, nil
}

func (s Service) DeleteCredential(ctx context.Context, request DeleteCredentialRequest) error {

	logrus.Debugf("deleting credential: %s", request.ID)

	if err := s.storage.DeleteCredential(ctx, request.ID); err != nil {
		return util.LoggingErrorMsgf(err, "could not delete credential with id: %s", request.ID)
	}

	return nil
}
