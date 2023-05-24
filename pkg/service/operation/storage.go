package operation

import (
	"context"
	"strings"

	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"go.einride.tech/aip/filtering"

	"github.com/tbd54566975/ssi-service/pkg/service/operation/credential"
	opstorage "github.com/tbd54566975/ssi-service/pkg/service/operation/storage"
	"github.com/tbd54566975/ssi-service/pkg/service/operation/storage/namespace"
	"github.com/tbd54566975/ssi-service/pkg/service/operation/submission"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

const (
	cancelledReason = "operation cancelled"
)

type Storage struct {
	db storage.ServiceStorage
}

func (s Storage) CancelOperation(ctx context.Context, id string) (*opstorage.StoredOperation, error) {
	var opData []byte
	var err error
	switch {
	case strings.HasPrefix(id, submission.ParentResource):
		_, opData, err = s.db.UpdateValueAndOperation(
			ctx,
			submission.Namespace, opstorage.StatusObjectID(id), storage.NewUpdater(map[string]any{
				"status": submission.StatusCancelled,
				"reason": cancelledReason,
			}),
			namespace.FromID(id), id, submission.OperationUpdater{
				UpdaterWithMap: storage.NewUpdater(map[string]any{
					"done": true,
				}),
			})
	case strings.HasPrefix(id, credential.ParentResource):
		_, opData, err = s.db.UpdateValueAndOperation(
			ctx,
			credential.ApplicationNamespace, opstorage.StatusObjectID(id), storage.NewUpdater(map[string]any{
				"status": credential.StatusCancelled,
				"reason": cancelledReason,
			}),
			namespace.FromID(id), id, submission.OperationUpdater{
				UpdaterWithMap: storage.NewUpdater(map[string]any{
					"done": true,
				}),
			},
		)
	default:
		return nil, errors.New("unrecognized id structure")
	}

	if err != nil {
		return nil, errors.Wrap(err, "updating value and op")
	}
	var op opstorage.StoredOperation
	if err = json.Unmarshal(opData, &op); err != nil {
		return nil, errors.Wrap(err, "unmarshalling data")
	}
	return &op, nil
}

func (s Storage) StoreOperation(ctx context.Context, op opstorage.StoredOperation) error {
	id := op.ID
	if id == "" {
		return sdkutil.LoggingNewError("ID is required for storing operations")
	}
	jsonBytes, err := json.Marshal(op)
	if err != nil {
		return sdkutil.LoggingErrorMsgf(err, "marshalling operation with id: %s", id)
	}
	if err = s.db.Write(ctx, namespace.FromID(id), id, jsonBytes); err != nil {
		return sdkutil.LoggingErrorMsg(err, "writing to db")
	}
	return nil
}

func (s Storage) GetOperation(ctx context.Context, id string) (opstorage.StoredOperation, error) {
	var stored opstorage.StoredOperation
	operationID := namespace.FromID(id)
	jsonBytes, err := s.db.Read(ctx, operationID, id)
	if err != nil {
		return stored, sdkutil.LoggingErrorMsgf(err, "reading operation with id: %s", id)
	}
	if len(jsonBytes) == 0 {
		return stored, sdkutil.LoggingNewErrorf("operation not found with id: %s", id)
	}
	if err := json.Unmarshal(jsonBytes, &stored); err != nil {
		return stored, sdkutil.LoggingErrorMsgf(err, "unmarshalling stored operation: %s", id)
	}
	return stored, nil
}

func (s Storage) ListOperations(ctx context.Context, parent string, filter filtering.Filter) ([]opstorage.StoredOperation, error) {
	operations, err := s.db.ReadAll(ctx, namespace.FromParent(parent))
	if err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "could not get all operations")
	}

	shouldInclude, err := storage.NewIncludeFunc(filter)
	if err != nil {
		return nil, err
	}
	stored := make([]opstorage.StoredOperation, 0, len(operations))
	for i, manifestBytes := range operations {
		var nextOp opstorage.StoredOperation
		if err = json.Unmarshal(manifestBytes, &nextOp); err != nil {
			logrus.WithError(err).WithField("idx", i).Warnf("Skipping operation")
		}
		include, err := shouldInclude(nextOp)
		// We explicitly ignore evaluation errors and simply include them in the result.
		if err != nil || include {
			stored = append(stored, nextOp)
		}
	}
	return stored, nil
}

func (s Storage) DeleteOperation(ctx context.Context, id string) error {
	if err := s.db.Delete(ctx, namespace.FromID(id), id); err != nil {
		return sdkutil.LoggingErrorMsgf(err, "deleting operation: %s", id)
	}
	return nil
}

func NewOperationStorage(db storage.ServiceStorage) (*Storage, error) {
	if db == nil {
		return nil, errors.New("bolt db reference is nil")
	}
	return &Storage{db: db}, nil
}
