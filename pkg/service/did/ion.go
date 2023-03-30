package did

import (
	"context"
	"fmt"
	"net/http"

	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/ion"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
)

func NewIONHandler(baseURL string, s *Storage, ks *keystore.Service) (MethodHandler, error) {
	if baseURL == "" {
		return nil, errors.New("baseURL cannot be empty")
	}
	if s == nil {
		return nil, errors.New("storage cannot be empty")
	}
	if ks == nil {
		return nil, errors.New("keystore cannot be empty")
	}
	r, err := ion.NewIONResolver(http.DefaultClient, baseURL)
	if err != nil {
		return nil, errors.Wrap(err, "creating ion resolver")
	}
	return &ionHandler{resolver: r, storage: s, keyStore: ks}, nil
}

type ionHandler struct {
	resolver *ion.Resolver
	storage  *Storage
	keyStore *keystore.Service
}

func (i *ionHandler) CreateDID(ctx context.Context, request CreateDIDRequest) (*CreateDIDResponse, error) {
	// TODO implement me
	panic("implement me")
}

func (i *ionHandler) GetDID(ctx context.Context, request GetDIDRequest) (*GetDIDResponse, error) {
	id := request.ID

	// TODO(gabe) as we are fully custodying ION DIDs this is fine; as we move to a more decentralized model we will
	//  need to either remove local storage or treat it as a cache with a TTL

	// first check if the DID is in the storage
	gotDID, err := i.storage.GetDID(ctx, id)
	if err == nil {
		return &GetDIDResponse{DID: gotDID.DID}, nil
	}
	logrus.WithError(err).Warnf("error getting DID from storage: %s", id)

	// if not, resolve it from the network
	resolved, err := i.resolver.Resolve(ctx, request.ID, nil)
	if err != nil {
		return nil, errors.Wrap(err, "resolving DID from network")
	}
	return &GetDIDResponse{DID: resolved.Document}, nil
}

// GetDIDs returns all DIDs we have in storage for ION, it is not feasible to get all DIDs from the network
func (i *ionHandler) GetDIDs(ctx context.Context) (*GetDIDsResponse, error) {
	logrus.Debug("getting stored did:ion DIDs")

	gotDIDs, err := i.storage.GetDIDs(ctx, did.KeyMethod.String())
	if err != nil {
		return nil, fmt.Errorf("error getting did:ion DIDs")
	}
	dids := make([]did.Document, 0, len(gotDIDs))
	for _, gotDID := range gotDIDs {
		if !gotDID.SoftDeleted {
			dids = append(dids, gotDID.DID)
		}
	}
	return &GetDIDsResponse{DIDs: dids}, nil
}

// SoftDeleteDID soft deletes a DID from storage but has no effect on the DID's state on the network
func (i *ionHandler) SoftDeleteDID(ctx context.Context, request DeleteDIDRequest) error {
	logrus.Debugf("soft deleting DID: %+v", request)

	id := request.ID
	gotStoredDID, err := i.storage.GetDID(ctx, id)
	if err != nil {
		return fmt.Errorf("error getting DID: %s", id)
	}
	if gotStoredDID == nil {
		return fmt.Errorf("did with id<%s> could not be found", id)
	}

	gotStoredDID.SoftDeleted = true

	return i.storage.StoreDID(ctx, *gotStoredDID)
}
