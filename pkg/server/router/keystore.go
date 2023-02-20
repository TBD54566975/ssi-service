package router

import (
	"context"
	"fmt"
	"net/http"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
)

type KeyStoreRouter struct {
	service *keystore.Service
}

func NewKeyStoreRouter(s svcframework.Service) (*KeyStoreRouter, error) {
	if s == nil {
		return nil, errors.New("service cannot be nil")
	}
	keyStoreService, ok := s.(*keystore.Service)
	if !ok {
		return nil, fmt.Errorf("could not create key store router with service type: %s", s.Type())
	}
	return &KeyStoreRouter{service: keyStoreService}, nil
}

type StoreKeyRequest struct {
	ID               string         `json:"id" validate:"required"`
	Type             crypto.KeyType `json:"type,omitempty" validate:"required"`
	Controller       string         `json:"controller,omitempty" validate:"required"`
	PrivateKeyBase58 string         `json:"base58PrivateKey,omitempty" validate:"required"`
}

func (sk StoreKeyRequest) ToServiceRequest() (*keystore.StoreKeyRequest, error) {
	// make sure we can decode and re-encode the key before storing it
	privateKeyBytes, err := base58.Decode(sk.PrivateKeyBase58)
	if err != nil {
		return nil, errors.Wrap(err, "could not decode base58 private key")
	}
	if _, err = crypto.BytesToPrivKey(privateKeyBytes, sk.Type); err != nil {
		return nil, errors.Wrap(err, "could not convert bytes to private key")
	}
	return &keystore.StoreKeyRequest{
		ID:               sk.ID,
		Type:             sk.Type,
		Controller:       sk.Controller,
		PrivateKeyBase58: sk.PrivateKeyBase58,
	}, nil
}

// StoreKey godoc
//
// @Summary     Store Key
// @Description Stores a key to be used by the service
// @Tags        KeyStoreAPI
// @Accept      json
// @Produce     json
// @Param       request body StoreKeyRequest true "request body"
// @Success     201
// @Failure     400 {string} string "Bad request"
// @Failure     500 {string} string "Internal server error"
// @Router      /v1/keys [put]
func (ksr *KeyStoreRouter) StoreKey(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	var request StoreKeyRequest
	if err := framework.Decode(r, &request); err != nil {
		errMsg := "invalid store key request"
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	req, err := request.ToServiceRequest()
	if err != nil {
		errMsg := "could not process store key request"
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	if err := ksr.service.StoreKey(ctx, *req); err != nil {
		errMsg := fmt.Sprintf("could not store key: %s, %s", request.ID, err.Error())
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	return framework.Respond(ctx, w, nil, http.StatusCreated)
}

type GetKeyDetailsResponse struct {
	ID         string         `json:"id,omitempty"`
	Type       crypto.KeyType `json:"type,omitempty"`
	Controller string         `json:"controller,omitempty"`
	CreatedAt  string         `json:"createdAt,omitempty"`
}

// GetKeyDetails godoc
//
// @Summary     Get Details For Key
// @Description Get details about a stored key
// @Tags        KeyStoreAPI
// @Accept      json
// @Produce     json
// @Param       id  path     string true "ID"
// @Success     200 {object} GetKeyDetailsResponse
// @Failure     400 {string} string "Bad request"
// @Router      /v1/keys/{id} [get]
func (ksr *KeyStoreRouter) GetKeyDetails(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		errMsg := "cannot get key details without ID parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	gotKeyDetails, err := ksr.service.GetKeyDetails(ctx, keystore.GetKeyDetailsRequest{ID: *id})
	if err != nil {
		errMsg := fmt.Sprintf("could not get key details for id: %s", *id)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	resp := GetKeyDetailsResponse{
		ID:         gotKeyDetails.ID,
		Type:       gotKeyDetails.Type,
		Controller: gotKeyDetails.Controller,
		CreatedAt:  gotKeyDetails.CreatedAt,
	}
	return framework.Respond(ctx, w, resp, http.StatusOK)
}

// DeleteKey godoc
//
// @Summary     Delete Key
// @Description Delete key
// @Tags        KeyStoreAPI
// @Accept      json
// @Produce     json
// @Param       id  path     string true "ID"
// @Success     200 {object} DeleteKeyResponse
// @Failure     400 {string} string "Bad request"
// @Router      /v1/keys/{id} [delete]
func (ksr *KeyStoreRouter) DeleteKey(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		errMsg := "cannot get key details without ID parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	_, err := ksr.service.DeleteKey(ctx, keystore.DeleteKeyRequest{ID: *id})
	if err != nil {
		errMsg := fmt.Sprintf("could not delete key for id: %s", *id)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	resp := GetKeyDetailsResponse{}
	return framework.Respond(ctx, w, resp, http.StatusOK)
}
