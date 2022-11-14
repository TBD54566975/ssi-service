package router

import (
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/presentation"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"os"
	"testing"
)

func TestPresentationDefinitionRouter(t *testing.T) {
	t.Run("Nil Service", func(tt *testing.T) {
		pdRouter, err := NewPresentationDefinitionRouter(nil)
		assert.Error(tt, err)
		assert.Empty(tt, pdRouter)
		assert.Contains(tt, err.Error(), "service cannot be nil")
	})

	t.Run("Bad Service", func(tt *testing.T) {
		pdRouter, err := NewPresentationDefinitionRouter(&testService{})
		assert.Error(tt, err)
		assert.Empty(tt, pdRouter)
		assert.Contains(tt, err.Error(), "could not create presentation router with service type: test")
	})
}

func TestPresentationDefinitionService(t *testing.T) {
	t.Cleanup(func() {
		_ = os.Remove(storage.DBFile)
	})

	s, err := storage.NewStorage(storage.Bolt)
	assert.NoError(t, err)

	service, err := presentation.NewPresentationService(config.PresentationServiceConfig{}, s)
	assert.NoError(t, err)

	t.Run("Create returns the created definition", func(t *testing.T) {
		pd := createPresentationDefinition(t)
		created, err := service.CreatePresentationDefinition(presentation.CreatePresentationDefinitionRequest{PresentationDefinition: *pd})
		assert.NoError(t, err)
		assert.Equal(t, pd, &created.PresentationDefinition)
	})

	t.Run("Get returns the created definition", func(t *testing.T) {
		pd := createPresentationDefinition(t)
		_, err := service.CreatePresentationDefinition(presentation.CreatePresentationDefinitionRequest{PresentationDefinition: *pd})
		assert.NoError(t, err)

		getPd, err := service.GetPresentationDefinition(presentation.GetPresentationDefinitionRequest{ID: pd.ID})

		assert.NoError(t, err)
		assert.Equal(t, pd.ID, getPd.ID)
		assert.Equal(t, pd, &getPd.PresentationDefinition)
	})

	t.Run("Get does not return after deletion", func(t *testing.T) {
		pd := createPresentationDefinition(t)
		_, err := service.CreatePresentationDefinition(presentation.CreatePresentationDefinitionRequest{PresentationDefinition: *pd})
		assert.NoError(t, err)

		assert.NoError(t, service.DeletePresentationDefinition(presentation.DeletePresentationDefinitionRequest{ID: pd.ID}))

		_, err = service.GetPresentationDefinition(presentation.GetPresentationDefinitionRequest{ID: pd.ID})
		assert.Error(t, err)
	})

	t.Run("Delete can be called with any ID", func(t *testing.T) {
		err := service.DeletePresentationDefinition(presentation.DeletePresentationDefinitionRequest{ID: "some crazy ID"})
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
