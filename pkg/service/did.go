package service

type DIDService interface {
	CreateDID() error
	GetDID() error
	UpdateDID() error
}
