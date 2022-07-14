package storage

import (
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type Storage interface {
}

func NewKeyStoreStorage(s storage.ServiceStorage) (Storage, error) {

}
