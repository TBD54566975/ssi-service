package submission

import (
	"fmt"

	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	opstorage "github.com/tbd54566975/ssi-service/pkg/service/operation/storage"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

// IDFromSubmissionID returns a submission operation ID from the submission ID.
func IDFromSubmissionID(id string) string {
	return fmt.Sprintf("%s/%s", ParentResource, id)
}

const (
	// Namespace is the namespace to be used for storing submissions.
	Namespace = "presentation_submission"
	// ParentResource is the prefix of the submission parent resource.
	ParentResource = "presentations/submissions"
)

// Status indicates the current state of a submission.
type Status uint8

func (s Status) String() string {
	switch s {
	case StatusPending:
		return "pending"
	case StatusDenied:
		return "denied"
	case StatusApproved:
		return "approved"
	case StatusCancelled:
		return "cancelled"
	default:
		return "unknown"
	}
}

const (
	StatusUnknown Status = iota
	StatusPending
	StatusCancelled
	StatusDenied
	StatusApproved
)

// OperationUpdater is an implementation of the storage.ResponseSettingUpdater. It's provides a way to update the
// operation and submission within a single transaction.
type OperationUpdater struct {
	storage.UpdaterWithMap
}

func (u OperationUpdater) SetUpdatedResponse(response []byte) {
	if u.UpdaterWithMap.Values == nil {
		return
	}
	u.UpdaterWithMap.Values["response"] = response
}

func (u OperationUpdater) Validate(v []byte) error {
	var op opstorage.StoredOperation
	if err := json.Unmarshal(v, &op); err != nil {
		return errors.Wrap(err, "unmarshalling operation")
	}

	if op.Done {
		return errors.New("operation already marked as done")
	}

	return nil
}

var _ storage.ResponseSettingUpdater = (*OperationUpdater)(nil)
