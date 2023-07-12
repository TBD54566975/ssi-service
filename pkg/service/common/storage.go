package common

import (
	"context"

	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type StoredRequest struct {
	ID                   string   `json:"id"`
	Audience             []string `json:"audience"`
	Expiration           string   `json:"expiration"`
	IssuerDID            string   `json:"issuerId"`
	VerificationMethodID string   `json:"verificationMethodId"`
	ReferenceID          string   `json:"referenceId"`
	JWT                  string   `json:"jwt"`
	CallbackURL          string   `json:"callbackURL"`
}

type RequestStorage interface {
	StoreRequest(context.Context, StoredRequest) error
	GetRequest(context.Context, string) (*StoredRequest, error)
	ListRequests(context.Context) ([]StoredRequest, error)
	DeleteRequest(context.Context, string) error
}

type requestStorage struct {
	db        storage.ServiceStorage
	namespace string
}

func NewRequestStorage(db storage.ServiceStorage, namespace string) RequestStorage {
	return &requestStorage{db: db, namespace: namespace}
}

func (s *requestStorage) StoreRequest(ctx context.Context, request StoredRequest) error {
	id := request.ID
	if id == "" {
		return util.LoggingNewError("could not store presentation request without an ID")
	}
	jsonBytes, err := json.Marshal(request)
	if err != nil {
		return util.LoggingErrorMsgf(err, "could not store presentation request: %s", id)
	}
	return s.db.Write(ctx, s.namespace, id, jsonBytes)
}

func (s *requestStorage) GetRequest(ctx context.Context, id string) (*StoredRequest, error) {
	jsonBytes, err := s.db.Read(ctx, s.namespace, id)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get request: %s", id)
	}
	if len(jsonBytes) == 0 {
		return nil, util.LoggingNewErrorf("request not found with id: %s", id)
	}
	var stored StoredRequest
	if err := json.Unmarshal(jsonBytes, &stored); err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not unmarshal stored request: %s", id)
	}
	return &stored, nil
}

func (s *requestStorage) DeleteRequest(ctx context.Context, id string) error {
	if err := s.db.Delete(ctx, s.namespace, id); err != nil {
		return util.LoggingNewErrorf("could not delete request: %s", id)
	}
	return nil
}

func (s *requestStorage) ListRequests(ctx context.Context) ([]StoredRequest, error) {
	m, err := s.db.ReadAll(ctx, s.namespace)
	if err != nil {
		return nil, errors.Wrap(err, "reading all")
	}
	ts := make([]StoredRequest, len(m))
	i := 0
	for k, v := range m {
		if err = json.Unmarshal(v, &ts[i]); err != nil {
			return nil, errors.Wrapf(err, "unmarshalling request with key <%s>", k)
		}
		i++
	}
	return ts, nil
}
