package service

type Type string

// List of all services

const (
	DID Type = "did-service"
)

type StatusState string

const (
	StatusReady    StatusState = "ready"
	StatusNotReady StatusState = "not ready"
)

// Status is for services reporting on their status
type Status struct {
	Status  StatusState
	Message string
}

// Service is an interface each service must comply with to be registered and orchestrated by the server.
type Service interface {
	Type() Type
	Status() Status
}
