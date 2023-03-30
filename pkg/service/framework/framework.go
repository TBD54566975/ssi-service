package framework

type (
	Type        string
	StatusState string
)

const (
	// List of all service

	DID          Type = "did"
	Schema       Type = "schema"
	Issuing      Type = "issuing"
	Credential   Type = "credential"
	KeyStore     Type = "keystore"
	Manifest     Type = "manifest"
	Presentation Type = "presentation"
	Operation    Type = "operation"
	Webhook      Type = "webhook"
	OIDC         Type = "oidc"

	StatusReady    StatusState = "ready"
	StatusNotReady StatusState = "not_ready"
)

func (t Type) String() string {
	return string(t)
}

// Status is for service reporting on their status
type Status struct {
	// Either `ready` or `not_ready`.
	Status StatusState `json:"status,omitempty"`

	// When `status` is `not_ready`, then message contains explanation of why it's not ready.
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
