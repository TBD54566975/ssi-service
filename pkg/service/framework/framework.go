package framework

type (
	Type        string
	StatusState string
)

const (
	// List of all service

	DID    Type = "did-service"
	Schema Type = "schema-service"

	StatusReady    StatusState = "ready"
	StatusNotReady StatusState = "not_ready"
)

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
