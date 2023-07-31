package framework

type (
	Type        string
	StatusState string
)

const (
	// List of all service

	DID              Type = "did"
	Schema           Type = "schema"
	Issuance         Type = "issuance"
	Credential       Type = "credential"
	KeyStore         Type = "keystore"
	Manifest         Type = "manifest"
	Presentation     Type = "presentation"
	Operation        Type = "operation"
	Webhook          Type = "webhook"
	DIDConfiguration Type = "did_configuration"

	StatusReady    StatusState = "ready"
	StatusNotReady StatusState = "not_ready"
)

func (t Type) String() string {
	return string(t)
}

// Status is for service reporting on their status
type Status struct {
	// Enum of the status.
	Status StatusState `json:"status,omitempty"`

	// When `status` is `"not_ready"`, message contains an explanation of why it's not ready.
	Message string `json:"message,omitempty"`
}

func (s Status) IsReady() bool {
	return s.Status == StatusReady
}

// Service is an interface each service must comply with to be registered and orchestrated by the http.
type Service interface {
	Type() Type
	Status() Status
}
