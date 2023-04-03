package did

import (
	"context"
	"os"
	"testing"

	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tbd54566975/ssi-service/pkg/storage"
)

func TestStorage(t *testing.T) {
	t.Run("Create bad DID - no namespace", func(tt *testing.T) {
		ds, err := NewDIDStorage(setupTestDB(tt))
		assert.NoError(tt, err)
		assert.NotEmpty(tt, ds)

		// create a did
		toStore := DefaultStoredDID{
			ID: "did:bad:test",
			DID: didsdk.Document{
				ID: "did:bad:test",
			},
			SoftDeleted: false,
		}

		// store
		err = ds.StoreDID(context.Background(), toStore)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not store DID")
	})

	t.Run("Get bad DID - namespace does not exist", func(tt *testing.T) {
		ds, err := NewDIDStorage(setupTestDB(tt))
		assert.NoError(tt, err)
		assert.NotEmpty(tt, ds)

		// store
		gotDID, err := ds.GetDIDDefault(context.Background(), "did:test:bad")
		assert.Error(tt, err)
		assert.Empty(tt, gotDID)
		assert.Contains(tt, err.Error(), "could not get DID: did:test:bad: no namespace found for DID method: test")
	})

	t.Run("Get bad DID - does not exist", func(tt *testing.T) {
		ds, err := NewDIDStorage(setupTestDB(tt))
		assert.NoError(tt, err)
		assert.NotEmpty(tt, ds)

		// store
		gotDID, err := ds.GetDIDDefault(context.Background(), "did:key:bad")
		assert.Error(tt, err)
		assert.Empty(tt, gotDID)
		assert.Contains(tt, err.Error(), "could not get DID: did:key:bad")
	})

	t.Run("Create and Get DID", func(tt *testing.T) {
		ds, err := NewDIDStorage(setupTestDB(tt))
		assert.NoError(tt, err)
		assert.NotEmpty(tt, ds)

		// create a did
		toStore := DefaultStoredDID{
			ID: "did:key:test",
			DID: didsdk.Document{
				ID: "did:key:test",
			},
			SoftDeleted: false,
		}

		// store
		err = ds.StoreDID(context.Background(), toStore)
		assert.NoError(tt, err)

		// get it back as a default
		got, err := ds.GetDIDDefault(context.Background(), "did:key:test")
		assert.NoError(tt, err)
		assert.Equal(tt, toStore, *got)

		// get it back as a did
		outDID := new(DefaultStoredDID)
		err = ds.GetDID(context.Background(), "did:key:test", outDID)
		assert.NoError(tt, err)
		assert.Equal(tt, toStore, *outDID)
	})

	t.Run("Create and Get DID of a custom type", func(tt *testing.T) {
		ds, err := NewDIDStorage(setupTestDB(tt))
		assert.NoError(tt, err)
		assert.NotEmpty(tt, ds)

		// create a did
		toStore := customStoredDID{
			ID:    "did:key:test",
			Party: false,
		}

		// store
		err = ds.StoreDID(context.Background(), toStore)
		assert.NoError(tt, err)

		// get it back as a default - which won't be equal
		got, err := ds.GetDIDDefault(context.Background(), "did:key:test")
		assert.NoError(tt, err)
		assert.NotEqual(tt, toStore, *got)

		// get it back as a custom did
		outDID := new(customStoredDID)
		err = ds.GetDID(context.Background(), "did:key:test", outDID)
		assert.NoError(tt, err)
		assert.Equal(tt, toStore, *outDID)
	})

	t.Run("Create and Get Multiple DIDs", func(tt *testing.T) {
		ds, err := NewDIDStorage(setupTestDB(tt))
		assert.NoError(tt, err)
		assert.NotEmpty(tt, ds)

		// create two dids
		toStore1 := DefaultStoredDID{
			ID: "did:key:test-1",
			DID: didsdk.Document{
				ID: "did:key:test-1",
			},
			SoftDeleted: false,
		}

		toStore2 := DefaultStoredDID{
			ID: "did:key:test-2",
			DID: didsdk.Document{
				ID: "did:key:test-2",
			},
			SoftDeleted: false,
		}

		// store
		err = ds.StoreDID(context.Background(), toStore1)
		assert.NoError(tt, err)

		err = ds.StoreDID(context.Background(), toStore2)
		assert.NoError(tt, err)

		// get both back as default
		got, err := ds.GetDIDsDefault(context.Background(), didsdk.KeyMethod.String())
		assert.NoError(tt, err)
		assert.Len(tt, got, 2)
		assert.Contains(tt, got, toStore1)
		assert.Contains(tt, got, toStore2)

		// get back as did
		gotDIDs, err := ds.GetDIDs(context.Background(), didsdk.KeyMethod.String(), new(DefaultStoredDID))
		assert.NoError(tt, err)
		assert.Len(tt, gotDIDs, 2)
		assert.Contains(tt, gotDIDs, &toStore1)
		assert.Contains(tt, gotDIDs, &toStore2)
	})

	t.Run("Soft delete DID", func(tt *testing.T) {
		ds, err := NewDIDStorage(setupTestDB(tt))
		assert.NoError(tt, err)
		assert.NotEmpty(tt, ds)

		// create two dids
		toStore1 := DefaultStoredDID{
			ID: "did:key:test-1",
			DID: didsdk.Document{
				ID: "did:key:test-1",
			},
			SoftDeleted: false,
		}

		toStore2 := DefaultStoredDID{
			ID: "did:key:test-2",
			DID: didsdk.Document{
				ID: "did:key:test-2",
			},
			SoftDeleted: false,
		}

		// store
		err = ds.StoreDID(context.Background(), toStore1)
		assert.NoError(tt, err)

		err = ds.StoreDID(context.Background(), toStore2)
		assert.NoError(tt, err)

		// get both and verify there are two
		gotDIDs, err := ds.GetDIDsDefault(context.Background(), didsdk.KeyMethod.String())
		assert.NoError(tt, err)
		assert.Len(tt, gotDIDs, 2)

		// soft delete one
		err = ds.DeleteDID(context.Background(), "did:key:test-1")
		assert.NoError(tt, err)

		// get it back
		_, err = ds.GetDIDDefault(context.Background(), "did:key:test-1")
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not get DID: did:key:test-1")

		// get both and verify there is one
		gotDIDs, err = ds.GetDIDsDefault(context.Background(), didsdk.KeyMethod.String())
		assert.NoError(tt, err)
		assert.Len(tt, gotDIDs, 1)
		assert.Contains(tt, gotDIDs, toStore2)
	})
}

func setupTestDB(t *testing.T) storage.ServiceStorage {
	file, err := os.CreateTemp("", "bolt")
	require.NoError(t, err)
	name := file.Name()
	err = file.Close()
	require.NoError(t, err)
	s, err := storage.NewStorage(storage.Bolt, name)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = s.Close()
		_ = os.Remove(s.URI())
	})
	return s
}

// new stored DID type
type customStoredDID struct {
	ID    string `json:"id,omitempty"`
	Party bool   `json:"party,omitempty"`
}

func (d customStoredDID) GetID() string {
	return d.ID
}

func (d customStoredDID) GetDocument() didsdk.Document {
	return didsdk.Document{
		ID: d.ID,
	}
}

func (d customStoredDID) IsSoftDeleted() bool {
	return d.Party
}
