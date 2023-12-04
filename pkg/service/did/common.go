package did

import (
	"context"
	"fmt"
	"time"

	"github.com/TBD54566975/ssi-sdk/did/resolution"
	"github.com/sirupsen/logrus"
)

func resolve(ctx context.Context, id string, storage *Storage) (*resolution.Result, error) {
	gotDID, err := storage.GetDIDDefault(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("error getting DID: %s", id)
	}
	if gotDID == nil {
		return nil, fmt.Errorf("did with id<%s> could not be found", id)
	}

	createdAt, err := time.Parse(time.RFC3339, gotDID.CreatedAt)
	if err != nil {
		logrus.WithError(err).Errorf("parsing created at")
	}
	updatedAt, err := time.Parse(time.RFC3339, gotDID.UpdatedAt)
	if err != nil {
		logrus.WithError(err).Errorf("parsing created at")
	}

	const XMLFormat = "2006-01-02T15:04:05Z"

	return &resolution.Result{
		Context:  "https://w3id.org/did-resolution/v1",
		Document: gotDID.DID,
		DocumentMetadata: &resolution.DocumentMetadata{
			Created:     createdAt.Format(XMLFormat),
			Updated:     updatedAt.Format(XMLFormat),
			Deactivated: gotDID.SoftDeleted,
		},
	}, nil
}
