package storage

import (
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

const (
	namespace = "operation"
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
	return b.db.Write(namespace, id, jsonBytes)
}

func (b BoltOperationStorage) GetOperation(id string) (*StoredOperation, error) {
	jsonBytes, err := b.db.Read(namespace, id)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "reading operation with id: %s", id)
	}
	if len(jsonBytes) == 0 {
		return nil, util.LoggingNewErrorf("operation not found with id: %s", id)
	}
	var stored StoredOperation
	if err := json.Unmarshal(jsonBytes, &stored); err != nil {
		return nil, util.LoggingErrorMsgf(err, "unmarshalling stored operation: %s", id)
	}
	return &stored, nil
}

func (b BoltOperationStorage) GetOperations() ([]StoredOperation, error) {
	operations, err := b.db.ReadAll(namespace)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get all operations")
	}
	stored := make([]StoredOperation, 0, len(operations))
	for i, manifestBytes := range operations {
		var nextOp StoredOperation
		if err = json.Unmarshal(manifestBytes, &nextOp); err != nil {
			logrus.WithError(err).WithField("idx", i).Warnf("Skipping operation")
		}
		stored = append(stored, nextOp)
	}
	return stored, nil
}

func (b BoltOperationStorage) DeleteOperation(id string) error {
	if err := b.db.Delete(namespace, id); err != nil {
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
