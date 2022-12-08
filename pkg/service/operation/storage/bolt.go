package storage

import (
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"go.einride.tech/aip/filtering"
)

const (
	Namespace = "operation"
)

type BoltOperationStorage struct {
	db *storage.BoltDB
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
	return b.db.Write(Namespace, id, jsonBytes)
}

func (b BoltOperationStorage) GetOperation(id string) (StoredOperation, error) {
	var stored StoredOperation
	jsonBytes, err := b.db.Read(Namespace, id)
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

func (b BoltOperationStorage) GetOperations(filter filtering.Filter) ([]StoredOperation, error) {
	operations, err := b.db.ReadAll(Namespace)
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
	if err := b.db.Delete(Namespace, id); err != nil {
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
