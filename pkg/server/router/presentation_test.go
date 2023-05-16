package router

import (
	"context"
	"testing"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/crypto"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/presentation"
	"github.com/tbd54566975/ssi-service/pkg/service/presentation/model"
)

func TestPresentationRouter(t *testing.T) {
	t.Run("Nil Service", func(tt *testing.T) {
		pdRouter, err := NewPresentationRouter(nil)
		assert.Error(tt, err)
		assert.Empty(tt, pdRouter)
		assert.Contains(tt, err.Error(), "service cannot be nil")
	})

	t.Run("Bad Service", func(tt *testing.T) {
		pdRouter, err := NewPresentationRouter(&testService{})
		assert.Error(tt, err)
		assert.Empty(tt, pdRouter)
		assert.Contains(tt, err.Error(), "could not create presentation router with service type: test")
	})
}

func TestPresentationService(t *testing.T) {
	s := setupTestDB(t)
	assert.NotEmpty(t, s)

	keyStoreService := testKeyStoreService(t, s)
	didService := testDIDService(t, s, keyStoreService)
	schemaService := testSchemaService(t, s, keyStoreService, didService)
	authorDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
		Method:  didsdk.KeyMethod,
		KeyType: crypto.Ed25519,
	})
	require.NoError(t, err)
	pubKeyBytes, err := base58.Decode(authorDID.DID.VerificationMethod[0].PublicKeyBase58)
	require.NoError(t, err)
	pubKey, err := crypto.BytesToPubKey(pubKeyBytes, crypto.Ed25519)
	require.NoError(t, err)
	ka, err := keyaccess.NewJWKKeyAccessVerifier(authorDID.DID.ID, authorDID.DID.ID, pubKey)
	require.NoError(t, err)

	service, err := presentation.NewPresentationService(config.PresentationServiceConfig{}, s, didService.GetResolver(), schemaService, keyStoreService)
	require.NoError(t, err)

	t.Run("Create returns the created definition", func(t *testing.T) {
		pd := createPresentationDefinition(t)
		created, err := service.CreatePresentationRequest(context.Background(), model.CreatePresentationRequestRequest{
			PresentationDefinition: *pd,
			Author:                 authorDID.DID.ID,
			AuthorKID:              authorDID.DID.VerificationMethod[0].ID,
		})

		assert.NoError(t, err)
		assert.Equal(t, pd, &created.PresentationRequest.PresentationDefinition)
		assert.NoError(t, ka.Verify(created.PresentationRequestJWT))
	})

	t.Run("Get returns the created definition", func(t *testing.T) {
		pd := createPresentationDefinition(t)
		_, err := service.CreatePresentationRequest(context.Background(), model.CreatePresentationRequestRequest{
			PresentationDefinition: *pd,
			Author:                 authorDID.DID.ID,
			AuthorKID:              authorDID.DID.VerificationMethod[0].ID,
		})
		assert.NoError(t, err)

		getPd, err := service.GetPresentationRequest(context.Background(), model.GetPresentationRequestRequest{ID: pd.ID})

		assert.NoError(t, err)
		assert.Equal(t, pd.ID, getPd.ID)
		assert.Equal(t, pd, &getPd.PresentationRequest.PresentationDefinition)
		assert.NoError(t, ka.Verify(getPd.PresentationRequestJWT))
	})

	t.Run("Get does not return after deletion", func(t *testing.T) {
		pd := createPresentationDefinition(t)
		_, err := service.CreatePresentationRequest(context.Background(), model.CreatePresentationRequestRequest{
			PresentationDefinition: *pd,
			Author:                 authorDID.DID.ID,
			AuthorKID:              authorDID.DID.VerificationMethod[0].ID,
		})
		assert.NoError(t, err)

		assert.NoError(t, service.DeletePresentationRequest(context.Background(), model.DeletePresentationRequestRequest{ID: pd.ID}))

		_, err = service.GetPresentationRequest(context.Background(), model.GetPresentationRequestRequest{ID: pd.ID})
		assert.Error(t, err)
	})

	t.Run("Delete can be called with any ID", func(t *testing.T) {
		err := service.DeletePresentationRequest(context.Background(), model.DeletePresentationRequestRequest{ID: "some crazy ID"})
		assert.NoError(t, err)
	})
}

func createPresentationDefinition(t *testing.T) *exchange.PresentationDefinition {
	builder := exchange.NewPresentationDefinitionBuilder()
	assert.NoError(t, builder.SetInputDescriptors([]exchange.InputDescriptor{
		{
			ID:      "id",
			Name:    "name",
			Purpose: "purpose",
			Format: &exchange.ClaimFormat{
				JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
			},
			Constraints: &exchange.Constraints{SubjectIsIssuer: exchange.Preferred.Ptr()},
		},
	}))
	pd, err := builder.Build()
	assert.NoError(t, err)
	return pd
}
