package namespace

import (
	"strings"

	"github.com/tbd54566975/ssi-service/pkg/service/operation/credential"
	"github.com/tbd54566975/ssi-service/pkg/service/operation/submission"
)

const (
	namespace                   = "operation_submission"
	credentialResponseNamespace = "operation_credential_response"
)

// FromID returns a namespace from a given operation ID. An empty string is returned when the namespace cannot
// be determined.
func FromID(id string) string {
	i := strings.LastIndex(id, "/")
	if i == -1 {
		return ""
	}
	return FromParent(id[:i])
}

// FromParent returns a namespace from a given parent resource name like "presentations/submissions". Empty is returned
// when the parent resource cannot be resolved.
func FromParent(parent string) string {
	switch parent {
	case submission.ParentResource:
		return namespace
	case credential.ParentResource:
		return credentialResponseNamespace
	default:
		return ""
	}
}
