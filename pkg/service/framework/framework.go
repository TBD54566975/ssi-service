package framework

type (
	Type        string
	StatusState string
)

const (
	// List of all service

	DID        Type = "did"
	Schema     Type = "schema"
	Credential Type = "credential"
	KeyStore   Type = "keystore"
	Manifest   Type = "manifest"

	StatusReady    StatusState = "ready"
	StatusNotReady StatusState = "not_ready"
)

func (t Type) String() string {
	return string(t)
}

// Status is for service reporting on their status
type Status struct {
	Status  StatusState `json:"status,omitempty"`
	Message string      `json:"message,omitempty"`
}

// Service is an interface each service must comply with to be registered and orchestrated by the http.
type Service interface {
	Type() Type
	Status() Status
}
