package did

import (
	"context"

	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/google/uuid"
	"github.com/pkg/errors"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type BatchService struct {
	config  config.DIDServiceConfig
	storage *Storage

	keyStoreFactory   keystore.ServiceFactory
	didStorageFactory StorageFactory
}

func NewBatchDIDService(config config.DIDServiceConfig, s storage.ServiceStorage, factory keystore.ServiceFactory) (*BatchService, error) {
	didStorage, err := NewDIDStorage(s)
	if err != nil {
		return nil, errors.Wrap(err, "instantiating DID storage for the DID service")
	}

	service := BatchService{
		config:            config,
		storage:           didStorage,
		keyStoreFactory:   factory,
		didStorageFactory: NewDIDStorageFactory(s),
	}
	return &service, nil
}

func (s *BatchService) BatchCreateDIDs(ctx context.Context, batchReq BatchCreateDIDsRequest) (*BatchCreateDIDsResponse, error) {
	watchKey := storage.WatchKey{
		Namespace: "temporary",
		Key:       "batch-create-dids-key-" + uuid.NewString(),
	}
	if err := s.storage.db.Write(ctx, watchKey.Namespace, watchKey.Key, []byte("starting")); err != nil {
		return nil, err
	}
	returnValue, err := s.storage.db.Execute(ctx, func(ctx context.Context, tx storage.Tx) (any, error) {
		batchResponse := BatchCreateDIDsResponse{
			DIDs: make([]didsdk.Document, 0, len(batchReq.Requests)),
		}
		keyStore, err := s.keyStoreFactory(tx)
		if err != nil {
			return nil, err
		}
		didStorage, err := s.didStorageFactory(tx)
		if err != nil {
			return nil, err
		}
		handler, err := NewKeyHandler(didStorage, keyStore)
		if err != nil {
			return nil, err
		}
		// watch some new key watchKey
		// accumulate all writes
		// execute all writes s.t. if one write fails, then watchKey is written from elsewhere
		for _, request := range batchReq.Requests {
			didResponse, err := handler.CreateDID(ctx, request)
			if err != nil {
				return nil, err
			}
			batchResponse.DIDs = append(batchResponse.DIDs, didResponse.DID)
		}
		return &batchResponse, nil
	}, []storage.WatchKey{watchKey})
	if err != nil {
		return nil, err
	}

	batchResponse, ok := returnValue.(*BatchCreateDIDsResponse)
	if !ok {
		return nil, errors.New("problem casting to BatchCreateDIDsResponse")
	}
	return batchResponse, nil
}

func (s *BatchService) Config() config.DIDServiceConfig {
	return s.config
}
