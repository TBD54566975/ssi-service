package keystore

import (
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	keystorestorage "github.com/tbd54566975/ssi-service/pkg/service/keystore/storage"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type Service struct {
	storage keystorestorage.Storage
	config  config.KeyStoreServiceConfig
}

func (s Service) Type() framework.Type {
	return framework.KeyStore
}

func (s Service) Status() framework.Status {
	if s.storage == nil {
		return framework.Status{
			Status:  framework.StatusNotReady,
			Message: "no storage",
		}
	}
	return framework.Status{Status: framework.StatusReady}
}

func (s Service) Config() config.KeyStoreServiceConfig {
	return s.config
}

func NewKeyStoreService(config config.KeyStoreServiceConfig, s storage.ServiceStorage) (*Service, error) {
	keyStoreStorage, err := keystorestorage.NewKeyStoreStorage(s, config.ServiceKeyPassword)
	if err != nil {
		errMsg := "could not instantiate storage for the keystore service"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	return &Service{
		storage: keyStoreStorage,
		config:  config,
	}, nil
}

func (s Service) StoreKey(request StoreKeyRequest) error {

	logrus.Debugf("storing key: %+v", request)

	key := keystorestorage.StoredKey{
		ID:         request.ID,
		Controller: request.Controller,
		KeyType:    request.Type,
		Key:        request.Key,
		CreatedAt:  time.Now().Format(time.RFC3339),
	}
	if err := s.storage.StoreKey(key); err != nil {
		return errors.Wrapf(err, "could not store key: %s", request.ID)
	}
	return nil
}

func (s Service) GetKeyDetails(request GetKeyDetailsRequest) (*GetKeyDetailsResponse, error) {

	logrus.Debugf("getting key: %+v", request)

	id := request.ID
	gotKeyDetails, err := s.storage.GetKeyDetails(id)
	if err != nil {
		return nil, errors.Wrapf(err, "could not get key details for key: %s", id)
	}
	if gotKeyDetails == nil {
		return nil, errors.Wrapf(err, "key with id<%s> could not be found", id)
	}
	return &GetKeyDetailsResponse{
		ID:         gotKeyDetails.ID,
		Type:       gotKeyDetails.KeyType,
		Controller: gotKeyDetails.Controller,
		CreatedAt:  gotKeyDetails.CreatedAt,
	}, nil
}
