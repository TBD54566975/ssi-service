package credential

import (
	"context"
	"fmt"
	"strconv"

	"github.com/TBD54566975/ssi-sdk/credential"
	statussdk "github.com/TBD54566975/ssi-sdk/credential/status"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/google/uuid"
	"github.com/pkg/errors"

	"github.com/tbd54566975/ssi-service/config"
	credint "github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

func (s Service) createStatusListEntryForCredential(ctx context.Context, credID string, request CreateCredentialRequest,
	tx storage.Tx, statusMetadata StatusListCredentialMetadata) (*statussdk.StatusList2021Entry, error) {
	issuerID := request.Issuer
	fullyQualifiedVerificationMethodID := request.FullyQualifiedVerificationMethodID
	schemaID := request.SchemaID

	statusPurpose := statussdk.StatusRevocation
	if request.Suspendable {
		statusPurpose = statussdk.StatusSuspension
	}

	var statusCred *credential.VerifiableCredential
	var statusListCredentialID string
	var randomIndex int
	var err error
	statusListCredential, err := s.storage.GetStatusListCredentialKeyData(ctx, issuerID, schemaID, statusPurpose)
	if err != nil {
		return nil, errors.Wrap(err, "getting status list credential key data")
	}

	if statusListCredential == nil {
		// creates status list credential with random index
		randomIndex, statusCred, err = s.createStatusListCredential(ctx, tx, statusPurpose, issuerID, fullyQualifiedVerificationMethodID, statusMetadata)
		if err != nil {
			return nil, sdkutil.LoggingErrorMsgf(err, "problem with getting status list credential")
		}

		statusListCredentialID = statusCred.ID
	} else {
		randomIndex, err = s.storage.GetNextStatusListRandomIndex(ctx, statusMetadata)
		if err != nil {
			return nil, sdkutil.LoggingErrorMsg(err, "problem with getting status list index")
		}

		statusListCredentialID = statusListCredential.Credential.ID
		if err = s.storage.IncrementStatusListIndexTx(ctx, tx, statusMetadata); err != nil {
			return nil, errors.Wrap(err, "incrementing status list index")
		}
	}

	indexStr := strconv.Itoa(randomIndex)
	return &statussdk.StatusList2021Entry{
		ID:                   fmt.Sprintf(`%s/status`, credID),
		Type:                 statussdk.StatusList2021EntryType,
		StatusPurpose:        statusPurpose,
		StatusListIndex:      indexStr,
		StatusListCredential: statusListCredentialID,
	}, nil
}

func getStatusURI(statusBase string, statusListID string) string {
	if len(statusBase) > 0 {
		return fmt.Sprintf("%s/status/%s", statusBase, statusListID)
	}
	return fmt.Sprintf("%s/status/%s", config.GetServicePath(framework.Credential), statusListID)
}

func (s Service) createStatusListCredential(ctx context.Context, tx storage.Tx, statusPurpose statussdk.StatusPurpose, issuerID, fullyQualifiedVerificationMethodID string, slcMetadata StatusListCredentialMetadata) (int, *credential.VerifiableCredential, error) {
	statusListID := uuid.NewString()
	statusListURI := getStatusURI(config.GetStatusBase(), statusListID)
	generatedStatusListCredential, err := statussdk.GenerateStatusList2021Credential(statusListURI, issuerID, statusPurpose, []credential.VerifiableCredential{})
	if err != nil {
		return -1, nil, sdkutil.LoggingErrorMsg(err, "could not generate status list")
	}

	statusListCredJWT, err := s.signCredentialJWT(ctx, fullyQualifiedVerificationMethodID, *generatedStatusListCredential)
	if err != nil {
		return -1, nil, sdkutil.LoggingErrorMsg(err, "could not sign status list credential")
	}

	statusListContainer := credint.Container{
		ID:                                 statusListID,
		FullyQualifiedVerificationMethodID: fullyQualifiedVerificationMethodID,
		Credential:                         generatedStatusListCredential,
		CredentialJWT:                      statusListCredJWT,
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
