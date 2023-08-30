package presentation

import (
	"context"
	"fmt"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tbd54566975/ssi-service/pkg/service/common"
	"go.einride.tech/aip/filtering"

	opstorage "github.com/tbd54566975/ssi-service/pkg/service/operation/storage"
	"github.com/tbd54566975/ssi-service/pkg/service/operation/storage/namespace"
	opsubmission "github.com/tbd54566975/ssi-service/pkg/service/operation/submission"
	prestorage "github.com/tbd54566975/ssi-service/pkg/service/presentation/storage"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

const (
	presentationDefinitionNamespace = "presentation_definition"
)

type Storage struct {
	db storage.ServiceStorage
}

func (ps *Storage) UpdateSubmission(ctx context.Context, id string, approved bool, reason string, opID string) (prestorage.StoredSubmission, opstorage.StoredOperation, error) {
	m := map[string]any{
		"status": opsubmission.StatusDenied,
		"reason": reason,
	}
	if approved {
		m["status"] = opsubmission.StatusApproved
	}
	submissionData, operationData, err := storage.UpdateValueAndOperation(
		ctx,
		ps.db,
		opsubmission.Namespace,
		id,
		storage.NewUpdater(m),
		namespace.FromID(opID),
		opID,
		opsubmission.OperationUpdater{
			UpdaterWithMap: storage.NewUpdater(map[string]any{
				"done": true,
			}),
		})
	if err != nil {
		return prestorage.StoredSubmission{}, opstorage.StoredOperation{}, errors.Wrap(err, "updating value and operation")
	}

	var s prestorage.StoredSubmission
	if err = json.Unmarshal(submissionData, &s); err != nil {
		return prestorage.StoredSubmission{}, opstorage.StoredOperation{}, errors.Wrap(err, "unmarshalling written submission")
	}
	var op opstorage.StoredOperation
	if err = json.Unmarshal(operationData, &op); err != nil {
		return prestorage.StoredSubmission{}, opstorage.StoredOperation{}, errors.Wrap(err, "unmarshalling written operation")
	}
	return s, op, nil
}

func (ps *Storage) ListSubmissions(ctx context.Context, filter filtering.Filter, page common.Page) (*prestorage.StoredSubmissions, error) {
	token, size := page.ToStorageArgs()
	allData, nextPageToken, err := ps.db.ReadPage(ctx, opsubmission.Namespace, token, size)
	if err != nil {
		return nil, errors.Wrap(err, "reading page")
	}

	shouldInclude, err := storage.NewIncludeFunc(filter)
	if err != nil {
		return nil, err
	}
	storedSubmissions := make([]prestorage.StoredSubmission, 0, len(allData))
	for key, data := range allData {
		var ss prestorage.StoredSubmission
		if err = json.Unmarshal(data, &ss); err != nil {
			logrus.WithError(err).WithField("key", key).Error("unmarshalling submission")
		}
		include, err := shouldInclude(ss)
		// We explicitly ignore evaluation errors and simply include them in the result.
		if err != nil {
			storedSubmissions = append(storedSubmissions, ss)
			continue
		}
		if include {
			storedSubmissions = append(storedSubmissions, ss)
		}
	}
	return &prestorage.StoredSubmissions{
		Submissions:   storedSubmissions,
		NextPageToken: nextPageToken,
	}, nil
}

func NewPresentationStorage(db storage.ServiceStorage) (prestorage.Storage, error) {
	if db == nil {
		return nil, errors.New("db reference is nil")
	}
	return &Storage{db: db}, nil
}

func (ps *Storage) StoreDefinition(ctx context.Context, presentation prestorage.StoredDefinition) error {
	id := presentation.ID
	if id == "" {
		err := errors.New("could not store presentation definition without an ID")
		logrus.WithError(err).Error()
		return err
	}
	jsonBytes, err := json.Marshal(presentation)
	if err != nil {
		errMsg := fmt.Sprintf("could not store presentation definition: %s", id)
		logrus.WithError(err).Error(errMsg)
		return errors.Wrapf(err, errMsg)
	}
	return ps.db.Write(ctx, presentationDefinitionNamespace, id, jsonBytes)
}

func (ps *Storage) GetDefinition(ctx context.Context, id string) (*prestorage.StoredDefinition, error) {
	jsonBytes, err := ps.db.Read(ctx, presentationDefinitionNamespace, id)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "could not get presentation definition: %s", id)
	}
	if len(jsonBytes) == 0 {
		return nil, sdkutil.LoggingNewErrorf("presentation definition not found with id: %s", id)
	}
	var stored prestorage.StoredDefinition
	if err := json.Unmarshal(jsonBytes, &stored); err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "could not unmarshal stored presentation definition: %s", id)
	}
	return &stored, nil
}

func (ps *Storage) DeleteDefinition(ctx context.Context, id string) error {
	if err := ps.db.Delete(ctx, presentationDefinitionNamespace, id); err != nil {
		return sdkutil.LoggingNewErrorf("deleting presentation definition: %s", id)
	}
	return nil
}

func (ps *Storage) StoreSubmission(ctx context.Context, s prestorage.StoredSubmission) error {
	sub, ok := s.VerifiablePresentation.PresentationSubmission.(exchange.PresentationSubmission)
	if !ok {
		return sdkutil.LoggingNewError("asserting that field is of type exchange.PresentationSubmission")
	}
	id := sub.ID
	if id == "" {
		err := errors.New("could not store submission definition without an ID")
		logrus.WithError(err).Error()
		return err
	}
	jsonBytes, err := json.Marshal(s)
	if err != nil {
		return sdkutil.LoggingNewErrorf("could not store submission definition: %s", id)
	}
	return ps.db.Write(ctx, opsubmission.Namespace, id, jsonBytes)
}

func (ps *Storage) GetSubmission(ctx context.Context, id string) (*prestorage.StoredSubmission, error) {
	jsonBytes, err := ps.db.Read(ctx, opsubmission.Namespace, id)
	if err != nil {
		return nil, sdkutil.LoggingNewErrorf("could not get submission definition: %s", id)
	}
	if len(jsonBytes) == 0 {
		return nil, sdkutil.LoggingErrorMsgf(prestorage.ErrSubmissionNotFound, "reading submission with id: %s", id)
	}
	var stored prestorage.StoredSubmission
	if err := json.Unmarshal(jsonBytes, &stored); err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "could not unmarshal stored submission definition: %s", id)
	}
	return &stored, nil
}

func (ps *Storage) ListDefinitions(ctx context.Context) ([]prestorage.StoredDefinition, error) {
	m, err := ps.db.ReadAll(ctx, presentationDefinitionNamespace)
	if err != nil {
		return nil, errors.Wrap(err, "reading all")
	}
	ts := make([]prestorage.StoredDefinition, len(m))
	i := 0
	for k, v := range m {
		if err = json.Unmarshal(v, &ts[i]); err != nil {
			return nil, errors.Wrapf(err, "unmarshalling template with key <%s>", k)
		}
		i++
	}
	return ts, nil
}
