package service

type Type string

const (
	DID Type = "did-service"
)

// Service is an interface each service must comply with to be registered and orchestrated by the server.
type Service interface {
	Type() Type
	Status() string
}
