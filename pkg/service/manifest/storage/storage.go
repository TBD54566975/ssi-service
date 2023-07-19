package storage

import (
	"context"

	"github.com/TBD54566975/ssi-sdk/credential/manifest"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	cred "github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/pkg/service/operation/credential"
	opstorage "github.com/tbd54566975/ssi-service/pkg/service/operation/storage"
	"github.com/tbd54566975/ssi-service/pkg/service/operation/storage/namespace"
	opsubmission "github.com/tbd54566975/ssi-service/pkg/service/operation/submission"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

const (
	manifestNamespace = "manifest"

	responseNamespace = "response"
)

type StoredManifest struct {
	ID                                 string                      `json:"id"`
	IssuerDID                          string                      `json:"issuerDid"`
	FullyQualifiedVerificationMethodID string                      `json:"fullyQualifiedVerificationMethodId"`
	Manifest                           manifest.CredentialManifest `json:"manifest"`
}

type StoredApplication struct {
	ID             string                         `json:"id"`
	Status         credential.Status              `json:"status"`
	Reason         string                         `json:"reason"`
	ManifestID     string                         `json:"manifestId"`
	ApplicantDID   string                         `json:"applicantDid"`
	Application    manifest.CredentialApplication `json:"application"`
	Credentials    []cred.Container               `json:"credentials"`
	ApplicationJWT keyaccess.JWT                  `json:"applicationJwt"`
}

type StoredResponse struct {
	ID           string                      `json:"id"`
	ManifestID   string                      `json:"manifestId"`
	ApplicantDID string                      `json:"applicantDid"`
	Response     manifest.CredentialResponse `json:"response"`
	Credentials  []cred.Container            `json:"credentials"`
	ResponseJWT  keyaccess.JWT               `json:"responseJwt"`
}

type Storage struct {
	db storage.ServiceStorage
}

func NewManifestStorage(db storage.ServiceStorage) (*Storage, error) {
	if db == nil {
		return nil, errors.New("db reference is nil")
	}
	return &Storage{db: db}, nil
}

func (ms *Storage) StoreManifest(ctx context.Context, manifest StoredManifest) error {
	id := manifest.Manifest.ID
	if id == "" {
		return sdkutil.LoggingNewError("could not store manifest without an ID")
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return sdkutil.LoggingErrorMsgf(err, "could not store manifest: %s", id)
	}
	return ms.db.Write(ctx, manifestNamespace, id, manifestBytes)
}

func (ms *Storage) GetManifest(ctx context.Context, id string) (*StoredManifest, error) {
	manifestBytes, err := ms.db.Read(ctx, manifestNamespace, id)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "getting manifest: %s", id)
	}
	if len(manifestBytes) == 0 {
		return nil, sdkutil.LoggingNewErrorf("manifest not found with id: %s", id)
	}
	var stored StoredManifest
	if err = json.Unmarshal(manifestBytes, &stored); err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "unmarshalling stored manifest: %s", id)
	}
	return &stored, nil
}

// ListManifests attempts to get all stored manifests. It will return those it can even if it has trouble with some.
func (ms *Storage) ListManifests(ctx context.Context) ([]StoredManifest, error) {
	gotManifests, err := ms.db.ReadAll(ctx, manifestNamespace)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "getting all manifests")
	}
	if len(gotManifests) == 0 {
		logrus.Info("no manifests to get")
		return nil, nil
	}
	var stored []StoredManifest
	for _, manifestBytes := range gotManifests {
		var nextManifest StoredManifest
		if err = json.Unmarshal(manifestBytes, &nextManifest); err == nil {
			stored = append(stored, nextManifest)
		} else {
			logrus.Errorf("could not unmarshal manifest while getting all manifests: %s", err.Error())
		}
	}
	return stored, nil
}

func (ms *Storage) DeleteManifest(ctx context.Context, id string) error {
	if err := ms.db.Delete(ctx, manifestNamespace, id); err != nil {
		return sdkutil.LoggingErrorMsgf(err, "deleting manifest: %s", id)
	}
	return nil
}

func (ms *Storage) StoreApplication(ctx context.Context, application StoredApplication) error {
	id := application.Application.ID
	if id == "" {
		return sdkutil.LoggingNewError("could not store application without an ID")
	}
	applicationBytes, err := json.Marshal(application)
	if err != nil {
		return sdkutil.LoggingErrorMsgf(err, "could not store application: %s", id)
	}
	return ms.db.Write(ctx, credential.ApplicationNamespace, id, applicationBytes)
}

func (ms *Storage) GetApplication(ctx context.Context, id string) (*StoredApplication, error) {
	applicationBytes, err := ms.db.Read(ctx, credential.ApplicationNamespace, id)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "could not get application: %s", id)
	}
	if len(applicationBytes) == 0 {
		return nil, sdkutil.LoggingNewErrorf("could not get application from storage; application not found with id: %s", id)
	}
	var stored StoredApplication
	if err = json.Unmarshal(applicationBytes, &stored); err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "unmarshalling stored application: %s", id)
	}
	return &stored, nil
}

// ListApplications attempts to get all stored applications. It will return those it can even if it has trouble with some.
func (ms *Storage) ListApplications(ctx context.Context) ([]StoredApplication, error) {
	gotApplications, err := ms.db.ReadAll(ctx, credential.ApplicationNamespace)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "listing all applications")
	}
	if len(gotApplications) == 0 {
		logrus.Info("no applications to list")
		return nil, nil
	}
	var stored []StoredApplication
	for appKey, applicationBytes := range gotApplications {
		var nextApplication StoredApplication
		if err = json.Unmarshal(applicationBytes, &nextApplication); err == nil {
			stored = append(stored, nextApplication)
		} else {
			logrus.WithError(err).Errorf("could not unmarshal stored application while listing all applications: %s", appKey)
		}
	}
	return stored, nil
}

func (ms *Storage) DeleteApplication(ctx context.Context, id string) error {
	if err := ms.db.Delete(ctx, credential.ApplicationNamespace, id); err != nil {
		return sdkutil.LoggingErrorMsgf(err, "deleting application: %s", id)
	}
	return nil
}

func (ms *Storage) StoreResponse(ctx context.Context, response StoredResponse) error {
	id := response.Response.ID
	if id == "" {
		return sdkutil.LoggingNewError("could not store response without an ID")
	}
	responseBytes, err := json.Marshal(response)
	if err != nil {
		return sdkutil.LoggingErrorMsgf(err, "storing response: %s", id)
	}
	return ms.db.Write(ctx, responseNamespace, id, responseBytes)
}

func (ms *Storage) GetResponse(ctx context.Context, id string) (*StoredResponse, error) {
	responseBytes, err := ms.db.Read(ctx, responseNamespace, id)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "getting response: %s", id)
	}
	if len(responseBytes) == 0 {
		return nil, sdkutil.LoggingNewErrorf("response not found with id: %s", id)
	}
	var stored StoredResponse
	if err = json.Unmarshal(responseBytes, &stored); err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "unmarshalling stored response: %s", id)
	}
	return &stored, nil
}

// ListResponses attempts to get all stored responses. It will return those it can even if it has trouble with some.
func (ms *Storage) ListResponses(ctx context.Context) ([]StoredResponse, error) {
	gotResponses, err := ms.db.ReadAll(ctx, responseNamespace)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "listing all responses")
	}
	if len(gotResponses) == 0 {
		logrus.Info("no responses to list")
		return nil, nil
	}
	var stored []StoredResponse
	for responseKey, responseBytes := range gotResponses {
		var nextResponse StoredResponse
		if err = json.Unmarshal(responseBytes, &nextResponse); err == nil {
			stored = append(stored, nextResponse)
		} else {
			logrus.WithError(err).Errorf("could not unmarshal stored response while listing all responses: %s", responseKey)
		}
	}
	return stored, nil
}

func (ms *Storage) DeleteResponse(ctx context.Context, id string) error {
	if err := ms.db.Delete(ctx, responseNamespace, id); err != nil {
		return sdkutil.LoggingErrorMsgf(err, "deleting response: %s", id)
	}
	return nil
}

// StoreReviewApplication does the following:
//  1. Updates the application status according to the approved parameter.
//  2. Creates a Credential Response corresponding to the approved parameter and with the given reason.
//  3. Marks the operation with id == opID as done, and sets operation.Response to the StoredResponse from the object
//     creates in step 2.
//
// The operation and it's response (from 3) are returned.
func (ms *Storage) StoreReviewApplication(ctx context.Context, applicationID string, approved bool, reason string, opID string, response StoredResponse) (*StoredResponse, *opstorage.StoredOperation, error) {
	// TODO: everything should be in a single Tx.
	m := map[string]any{
		"status": opsubmission.StatusDenied,
		"reason": reason,
	}
	if approved {
		m["status"] = opsubmission.StatusApproved
	}
	if _, err := ms.db.Update(ctx, credential.ApplicationNamespace, applicationID, m); err != nil {
		return nil, nil, errors.Wrap(err, "updating application")
	}

	if err := ms.StoreResponse(ctx, response); err != nil {
		return nil, nil, errors.Wrap(err, "storing credential response")
	}

	responseData, operationData, err := ms.db.UpdateValueAndOperation(ctx, responseNamespace, response.ID,
		storage.NewUpdater(m), namespace.FromID(opID), opID,
		opsubmission.OperationUpdater{UpdaterWithMap: storage.NewUpdater(map[string]any{"done": true})})
	if err != nil {
		return nil, nil, errors.Wrap(err, "updating value and operation")
	}

	var s StoredResponse
	if err = json.Unmarshal(responseData, &s); err != nil {
		return nil, nil, errors.Wrap(err, "unmarshalling written credential response")
	}
	var op opstorage.StoredOperation
	if err = json.Unmarshal(operationData, &op); err != nil {
		return nil, nil, errors.Wrap(err, "unmarshalling written operation")
	}

	return &s, &op, nil
}
