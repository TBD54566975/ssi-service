package application

import "fmt"

const (
	// ParentResource is the prefix of the credential application parent resource.
	ParentResource = "credentials/applications"
)

// IDFromApplicationID returns an operation ID from the application ID.
func IDFromApplicationID(id string) string {
	return fmt.Sprintf("%s/%s", ParentResource, id)
}
