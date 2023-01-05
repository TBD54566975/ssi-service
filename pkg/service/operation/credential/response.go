package credential

import "fmt"

const (
	// ParentResource is the prefix of the credential application parent resource.
	ParentResource = "credentials/responses"
)

// IDFromResponseID returns an operation ID from the application ID.
func IDFromResponseID(id string) string {
	return fmt.Sprintf("%s/%s", ParentResource, id)
}

type Status uint8

func (s Status) String() string {
	switch s {
	case StatusPending:
		return "pending"
	case StatusFulfilled:
		return "fulfilled"
	case StatusRejected:
		return "rejected"
	case StatusCancelled:
		return "cancelled"
	default:
		return "unknown"
	}
}

const (
	StatusUnknown Status = iota
	StatusPending
	StatusFulfilled
	StatusRejected
	StatusCancelled
)

const ApplicationNamespace = "application"
