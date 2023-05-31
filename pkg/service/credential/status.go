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

	credint "github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

func (s Service) createStatusListEntryForCredential(ctx context.Context, credID string, request CreateCredentialRequest,
	tx storage.Tx, statusMetadata StatusListCredentialMetadata) (*statussdk.StatusList2021Entry, error) {
	issuerID := request.Issuer
	issuerKID := request.IssuerKID
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
		randomIndex, statusCred, err = s.createStatusListCredential(ctx, tx, statusPurpose, issuerID, issuerKID, statusMetadata)
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

	return &statussdk.StatusList2021Entry{
		ID:                   fmt.Sprintf(`%s/%s/status`, s.config.ServiceEndpoint, credID),
		Type:                 statussdk.StatusList2021EntryType,
		StatusPurpose:        statusPurpose,
		StatusListIndex:      strconv.Itoa(randomIndex),
		StatusListCredential: statusListCredentialID,
	}, nil
}

func (s Service) createStatusListCredential(ctx context.Context, tx storage.Tx, statusPurpose statussdk.StatusPurpose, issuerID, issuerKID string, slcMetadata StatusListCredentialMetadata) (int, *credential.VerifiableCredential, error) {
	statusListID := fmt.Sprintf("%s/status/%s", s.config.ServiceEndpoint, uuid.NewString())

	generatedStatusListCredential, err := statussdk.GenerateStatusList2021Credential(statusListID, issuerID, statusPurpose, []credential.VerifiableCredential{})
	if err != nil {
		return -1, nil, sdkutil.LoggingErrorMsg(err, "could not generate status list")
	}

	statusListCredJWT, err := s.signCredentialJWT(ctx, issuerKID, *generatedStatusListCredential)
	if err != nil {
		return -1, nil, sdkutil.LoggingErrorMsg(err, "could not sign status list credential")
	}

	statusListContainer := credint.Container{
		ID:            generatedStatusListCredential.ID,
		IssuerKID:     issuerKID,
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
