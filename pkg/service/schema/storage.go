package schema

import (
	"context"

	"github.com/TBD54566975/ssi-sdk/credential/schema"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tbd54566975/ssi-service/pkg/service/common"

	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

const (
	namespace = "schema"
)

type StoredSchemas struct {
	Schemas       []StoredSchema
	NextPageToken string
}

type StoredSchema struct {
	ID               string                  `json:"id"`
	Type             schema.VCJSONSchemaType `json:"type"`
	Schema           *schema.JSONSchema      `json:"schema,omitempty"`
	CredentialSchema *keyaccess.JWT          `json:"credentialSchema,omitempty"`
}

type Storage struct {
	db storage.ServiceStorage
}

func NewSchemaStorage(db storage.ServiceStorage) (*Storage, error) {
	if db == nil {
		return nil, errors.New("db reference is nil")
	}
	return &Storage{db: db}, nil
}

func (s *Storage) StoreSchema(ctx context.Context, schema StoredSchema) error {
	id := schema.ID
	if id == "" {
		return util.LoggingNewError("could not store schema without an ID")
	}
	schemaBytes, err := json.Marshal(schema)
	if err != nil {
		return util.LoggingErrorMsgf(err, "could not store schema: %s", id)
	}
	return s.db.Write(ctx, namespace, id, schemaBytes)
}

func (s *Storage) GetSchema(ctx context.Context, id string) (*StoredSchema, error) {
	schemaBytes, err := s.db.Read(ctx, namespace, id)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get schema: %s", id)
	}
	if len(schemaBytes) == 0 {
		return nil, util.LoggingNewErrorf("schema not found with id: %s", id)
	}
	var stored StoredSchema
	if err = json.Unmarshal(schemaBytes, &stored); err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not unmarshal stored schema: %s", id)
	}
	return &stored, nil
}

// ListSchemas attempts to get all stored schemas. It will return those it can even if it has trouble with some.
func (s *Storage) ListSchemas(ctx context.Context, page common.Page) (*StoredSchemas, error) {
	token, size := page.ToStorageArgs()
	gotSchemas, nextPageToken, err := s.db.ReadPage(ctx, namespace, token, size)
	if err != nil {
		return nil, errors.Wrap(err, "reading page of schemas")
	}

	stored := make([]StoredSchema, 0, len(gotSchemas))
	for _, schemaBytes := range gotSchemas {
		var nextSchema StoredSchema
		if err = json.Unmarshal(schemaBytes, &nextSchema); err != nil {
			logrus.WithError(err).Errorf("could not unmarshal stored schema: %s", string(schemaBytes))
			continue
		}
		stored = append(stored, nextSchema)
	}
	return &StoredSchemas{
		Schemas:       stored,
		NextPageToken: nextPageToken,
	}, nil
}

func (s *Storage) DeleteSchema(ctx context.Context, id string) error {
	if err := s.db.Delete(ctx, namespace, id); err != nil {
		return util.LoggingErrorMsgf(err, "deleting schema: %s", id)
	}
	return nil
}
