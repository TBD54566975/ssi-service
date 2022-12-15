package operation

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

type StoredOperation struct {
	ID string `json:"id"`

	// Whether this operation has finished.
	Done bool `json:"done"`

	// Populated when there was an error with the operation.
	Error string `json:"errorResult,omitempty"`

	// Populated only when Done == true and Error == ""
	Response []byte `json:"response,omitempty"`
}

func (s StoredOperation) FilterVariablesMap() map[string]any {
	return map[string]any{
		"done": s.Done,
		// "true" and "false" are currently being parsed as identifiers, so we need to pass in the values that they
		// evaluate to. Ideally, we should change them to be parsed as constants. That requires an upstream change in
		// the filtering library.
		"true":  true,
		"false": false,
	}
}

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

type OperationStorage struct {
	db storage.ServiceStorage
}

func (os *OperationStorage) StoreOperation(op StoredOperation) error {
	id := op.ID
	if id == "" {
		return util.LoggingNewError("ID is required for storing operations")
	}
	jsonBytes, err := json.Marshal(op)
	if err != nil {
		return util.LoggingErrorMsgf(err, "marshalling operation with id: %s", id)
	}
	return os.db.Write(NamespaceFromID(id), id, jsonBytes)
}

func (os *OperationStorage) GetOperation(id string) (StoredOperation, error) {
	var stored StoredOperation
	jsonBytes, err := os.db.Read(NamespaceFromID(id), id)
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

func (os *OperationStorage) GetOperations(parent string, filter filtering.Filter) ([]StoredOperation, error) {
	operations, err := os.db.ReadAll(namespaceFromParent(parent))
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

func (os *OperationStorage) DeleteOperation(id string) error {
	if err := os.db.Delete(NamespaceFromID(id), id); err != nil {
		return util.LoggingErrorMsgf(err, "deleting operation: %s", id)
	}
	return nil
}

func NewOperationStorage(db storage.ServiceStorage) (*OperationStorage, error) {
	if db == nil {
		return nil, errors.New("bolt db reference is nil")
	}
	return &OperationStorage{db: db}, nil

}
