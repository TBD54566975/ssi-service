package storage

type DID interface {
	CreateDID() error
	GetDID() error
	UpdateDID() error
}
