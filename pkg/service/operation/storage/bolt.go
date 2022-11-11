package storage

import (
	"fmt"
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
		err := errors.New("ID is required for storing operations")
		logrus.WithError(err).Error()
		return err
	}
	jsonBytes, err := json.Marshal(op)
	if err != nil {
		errMsg := fmt.Sprintf("marshalling operation with id: %s", id)
		logrus.WithError(err).Error(errMsg)
		return errors.Wrapf(err, errMsg)
	}
	return b.db.Write(namespace, id, jsonBytes)
}

func (b BoltOperationStorage) GetOperation(id string) (*StoredOperation, error) {
	jsonBytes, err := b.db.Read(namespace, id)
	if err != nil {
		errMsg := fmt.Sprintf("reading operation with id: %s", id)
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrapf(err, errMsg)
	}
	if len(jsonBytes) == 0 {
		err := fmt.Errorf("operation not found with id: %s", id)
		logrus.WithError(err).Error("found empty bytes")
		return nil, err
	}
	var stored StoredOperation
	if err := json.Unmarshal(jsonBytes, &stored); err != nil {
		errMsg := fmt.Sprintf("unmarshalling stored operation: %s", id)
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrapf(err, errMsg)
	}
	return &stored, nil
}

func (b BoltOperationStorage) GetOperations() ([]StoredOperation, error) {
	operations, err := b.db.ReadAll(namespace)
	if err != nil {
		errMsg := "reading all from db"
		logrus.WithError(err).Error("could not get all operations")
		return nil, errors.Wrap(err, errMsg)
	}
	stored := make([]StoredOperation, 0, len(operations))
	for _, manifestBytes := range operations {
		var nextOp StoredOperation
		if err = json.Unmarshal(manifestBytes, &nextOp); err == nil {
			stored = append(stored, nextOp)
		}
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
