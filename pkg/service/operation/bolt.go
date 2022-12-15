package operation

import (
	"strings"

	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tbd54566975/ssi-service/internal/util"
	opstorage "github.com/tbd54566975/ssi-service/pkg/service/operation/storage"
	"github.com/tbd54566975/ssi-service/pkg/service/operation/storage/namespace"
	"github.com/tbd54566975/ssi-service/pkg/service/operation/submission"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"go.einride.tech/aip/filtering"
)

const (
	cancelledReason = "operation cancelled"
)

type BoltOperationStorage struct {
	db *storage.BoltDB
}

func NewBoltOperationStorage(db *storage.BoltDB) (*BoltOperationStorage, error) {
	if db == nil {
		return nil, errors.New("bolt db reference is nil")
	}
	return &BoltOperationStorage{db: db}, nil

}

func (b BoltOperationStorage) CancelOperation(id string) (*opstorage.StoredOperation, error) {
	if strings.HasPrefix(id, submission.ParentResource) {
		_, opData, err := b.db.UpdateValueAndOperation(
			submission.Namespace, submission.ID(id), storage.NewUpdater(map[string]any{
				"status": submission.StatusCancelled,
				"reason": cancelledReason,
			}),
			namespace.FromID(id), id, submission.OperationUpdater{
				UpdaterWithMap: storage.NewUpdater(map[string]any{
					"done": true,
				}),
			})
		if err != nil {
			return nil, errors.Wrap(err, "updating value and op")
		}
		var op opstorage.StoredOperation
		if err = json.Unmarshal(opData, &op); err != nil {
			return nil, errors.Wrap(err, "unmarshalling data")
		}
		return &op, nil
	}
	return nil, errors.New("unrecognized id structure")
}

func (b BoltOperationStorage) StoreOperation(op opstorage.StoredOperation) error {
	id := op.ID
	if id == "" {
		return util.LoggingNewError("ID is required for storing operations")
	}
	jsonBytes, err := json.Marshal(op)
	if err != nil {
		return util.LoggingErrorMsgf(err, "marshalling operation with id: %s", id)
	}
	if err = b.db.Write(namespace.FromID(id), id, jsonBytes); err != nil {
		return util.LoggingErrorMsg(err, "writing to db")
	}
	return nil
}

func (b BoltOperationStorage) GetOperation(id string) (opstorage.StoredOperation, error) {
	var stored opstorage.StoredOperation
	jsonBytes, err := b.db.Read(namespace.FromID(id), id)
	if err != nil {
		return stored, util.LoggingErrorMsgf(err, "reading operation with id: %s", id)
	}
	if len(jsonBytes) == 0 {
		return stored, util.LoggingNewErrorf("operation not found with id: %s", id)
	}
	if err := json.Unmarshal(jsonBytes, &stored); err != nil {
		return stored, util.LoggingErrorMsgf(err, "unmarshalling stored operation: %s", id)
	}
	return stored, nil
}

func (b BoltOperationStorage) GetOperations(parent string, filter filtering.Filter) ([]opstorage.StoredOperation, error) {
	operations, err := b.db.ReadAll(namespace.FromParent(parent))
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get all operations")
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

func (b BoltOperationStorage) DeleteOperation(id string) error {
	if err := b.db.Delete(namespace.FromID(id), id); err != nil {
		return util.LoggingErrorMsgf(err, "deleting operation: %s", id)
	}
	return nil
}

func NewOperationStorage(s storage.ServiceStorage) (opstorage.Storage, error) {
	switch s.Type() {
	case storage.Bolt:
		gotBolt, ok := s.(*storage.BoltDB)
		if !ok {
			return nil, util.LoggingNewErrorf("trouble instantiating : %s", s.Type())
		}
		boltStorage, err := NewBoltOperationStorage(gotBolt)
		if err != nil {
			return nil, util.LoggingErrorMsg(err, "could not instantiate schema bolt storage")
		}
		return boltStorage, err
	default:
		return nil, util.LoggingNewErrorf("unsupported storage type: %s", s.Type())
	}
}
