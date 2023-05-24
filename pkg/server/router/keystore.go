package router

import (
	"fmt"
	"net/http"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/gin-gonic/gin"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"

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
	// The `id` field is the unique identifier for this object. If set to a resolvable DID, the ssi-service will use
	// the private key encoded in the `PrivateKeyBase58` field of this object to sign objects issued or authored by this
	// DID; otherwise, it will only be used to identify this object.
	ID string `json:"id" validate:"required"`

	// Identifies the cryptographic algorithm family used with the key.
	// One of the following: "Ed25519", "X25519", "secp256k1", "P-224", "P-256", "P-384", "P-521", "RSA".
	Type crypto.KeyType `json:"type,omitempty" validate:"required"`

	// See https://www.w3.org/TR/did-core/#did-controller
	Controller string `json:"controller,omitempty" validate:"required"`

	// Base58 encoding of the bytes that result from marshalling the private key using golang's implementation.
	PrivateKeyBase58 string `json:"base58PrivateKey,omitempty" validate:"required"`
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
//	@Summary		Store Key
//	@Description	Stores a key to be used by the service
//	@Tags			KeyStoreAPI
//	@Accept			json
//	@Produce		json
//	@Param			request	body	StoreKeyRequest	true	"request body"
//	@Success		201
//	@Failure		400	{string}	string	"Bad request"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/v1/keys [put]
func (ksr *KeyStoreRouter) StoreKey(c *gin.Context) {
	var request StoreKeyRequest
	if err := framework.Decode(c.Request, &request); err != nil {
		errMsg := "invalid store key request"
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
		return
	}

	req, err := request.ToServiceRequest()
	if err != nil {
		errMsg := "could not process store key request"
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
		return
	}

	if err = ksr.service.StoreKey(c, *req); err != nil {
		errMsg := fmt.Sprintf("could not store key: %s, %s", request.ID, err.Error())
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}

	framework.Respond(c, nil, http.StatusCreated)
}

type GetKeyDetailsResponse struct {
	ID         string         `json:"id,omitempty"`
	Type       crypto.KeyType `json:"type,omitempty"`
	Controller string         `json:"controller,omitempty"`

	// Represents the time at which the key was created. Encoded according to RFC3339.
	CreatedAt string `json:"createdAt,omitempty"`

	// The public key in JWK format according to RFC7517. This public key is associated with the private
	// key with the associated ID.
	PublicKeyJWK jwx.PublicKeyJWK `json:"publicKeyJwk"`
}

// GetKeyDetails godoc
//
//	@Summary		Get Details For Key
//	@Description	Get details about a stored key
//	@Tags			KeyStoreAPI
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"ID of the key to get"
//	@Success		200	{object}	GetKeyDetailsResponse
//	@Failure		400	{string}	string	"Bad request"
//	@Router			/v1/keys/{id} [get]
func (ksr *KeyStoreRouter) GetKeyDetails(c *gin.Context) {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "cannot get key details without ID parameter"
		framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
		return
	}

	gotKeyDetails, err := ksr.service.GetKeyDetails(c, keystore.GetKeyDetailsRequest{ID: *id})
	if err != nil {
		errMsg := fmt.Sprintf("could not get key details for id: %s", *id)
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
		return
	}

	resp := GetKeyDetailsResponse{
		ID:           gotKeyDetails.ID,
		Type:         gotKeyDetails.Type,
		Controller:   gotKeyDetails.Controller,
		CreatedAt:    gotKeyDetails.CreatedAt,
		PublicKeyJWK: gotKeyDetails.PublicKeyJWK,
	}
	framework.Respond(c, resp, http.StatusOK)
}

type RevokeKeyResponse struct {
	ID string `json:"id,omitempty"`
}

// RevokeKey godoc
//
//	@Summary		Revoke Key
//	@Description	Marks the stored key as being revoked, along with the timestamps of when it was revoked. NB: the key can still be used for signing. This will likely be addressed before v1 is released.
//	@Tags			KeyStoreAPI
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"ID of the key to revoke"
//	@Success		200	{object}	RevokeKeyResponse
//	@Failure		400	{string}	string	"Bad request"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/v1/keys/{id} [delete]
func (ksr *KeyStoreRouter) RevokeKey(c *gin.Context) {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "cannot delete key without ID parameter"
		framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
		return
	}

	if err := ksr.service.RevokeKey(c, keystore.RevokeKeyRequest{ID: *id}); err != nil {
		errMsg := fmt.Sprintf("could not revoke key for id: %s", *id)
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}

	resp := RevokeKeyResponse{ID: *id}
	framework.Respond(c, resp, http.StatusOK)
}
