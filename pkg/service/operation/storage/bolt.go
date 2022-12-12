package storage

import (
	"strings"

	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"go.einride.tech/aip/filtering"
)

const (
	namespace = "operation_submission"
)

const SubmissionParentResource = "/presentations/submissions"

// NamespaceFromID returns a namespace from a given operation ID. An empty string is returned when the namespace cannot
// be determined.
func NamespaceFromID(id string) string {
	i := strings.LastIndex(id, "/")
	if i == -1 {
		return ""
	}
	return namespaceFromParent(id[:i])
}

func namespaceFromParent(parent string) string {
	switch parent {
	case SubmissionParentResource:
		return namespace
	default:
		return ""
	}
}

type BoltOperationStorage struct {
	db *storage.BoltDB
}

func (b BoltOperationStorage) MarkDone(id string) (StoredOperation, error) {
	if strings.HasPrefix(id, SubmissionParentResource) {
		_, opData, err := b.db.UpdateValueAndOperation(
			SubmissionNamespace, SubmissionID(id), storage.NewUpdater(map[string]any{
				"status": 2, // TODO: should we move status elsewhere, or pass this in?
				"reason": "operation cancelled",
			}),
			NamespaceFromID(id), id, OperationUpdater{
				storage.NewUpdater(map[string]any{
					"done": true,
				}),
			})
		if err != nil {
			return StoredOperation{}, errors.Wrap(err, "updating value and op")
		}
		var op StoredOperation
		if err = json.Unmarshal(opData, &op); err != nil {
			return op, errors.Wrap(err, "unmarshalling data")
		}
		return op, nil
	}
	return StoredOperation{}, errors.New("unrecognized id structure")
}

func (b BoltOperationStorage) StoreOperation(op StoredOperation) error {
	id := op.ID
	if id == "" {
		return util.LoggingNewError("ID is required for storing operations")
	}
	jsonBytes, err := json.Marshal(op)
	if err != nil {
		return util.LoggingErrorMsgf(err, "marshalling operation with id: %s", id)
	}
	return b.db.Write(NamespaceFromID(id), id, jsonBytes)
}

func (b BoltOperationStorage) GetOperation(id string) (StoredOperation, error) {
	var stored StoredOperation
	jsonBytes, err := b.db.Read(NamespaceFromID(id), id)
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

func (b BoltOperationStorage) GetOperations(parent string, filter filtering.Filter) ([]StoredOperation, error) {
	operations, err := b.db.ReadAll(namespaceFromParent(parent))
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get all operations")
	}

	shouldInclude, err := storage.NewIncludeFunc(filter)
	if err != nil {
		return nil, err
	}
	stored := make([]StoredOperation, 0, len(operations))
	for i, manifestBytes := range operations {
		var nextOp StoredOperation
		if err = json.Unmarshal(manifestBytes, &nextOp); err != nil {
			logrus.WithError(err).WithField("idx", i).Warnf("Skipping operation")
		}
		include, err := shouldInclude(nextOp)
		// We explicitly ignore evaluation errors and simply include them in the result.
		if err != nil {
			stored = append(stored, nextOp)
			continue
		}
		if include {
			stored = append(stored, nextOp)
		}
	}
	return stored, nil
}

func (b BoltOperationStorage) DeleteOperation(id string) error {
	if err := b.db.Delete(NamespaceFromID(id), id); err != nil {
		return util.LoggingErrorMsgf(err, "deleting operation: %s", id)
	}
	return nil
}

func NewBoltOperationStorage(db *storage.BoltDB) (*BoltOperationStorage, error) {
	if db == nil {
		return nil, errors.New("bolt db reference is nil")
	}
	return &BoltOperationStorage{db: db}, nil

}
