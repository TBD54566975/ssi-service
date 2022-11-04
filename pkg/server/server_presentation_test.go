package server

import (
	"fmt"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/service/presentation"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestPresentationAPI(t *testing.T) {
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

	s, err := storage.NewStorage(storage.Bolt)
	assert.NoError(t, err)

	service, err := presentation.NewPresentationDefinitionService(config.PresentationServiceConfig{}, s)
	assert.NoError(t, err)

	pRouter, err := router.NewPresentationDefinitionRouter(service)
	assert.NoError(t, err)

	t.Cleanup(func() {
		_ = s.Close()
		_ = os.Remove(storage.DBFile)
	})

	t.Run("Create, Get, and Delete PresentationDefinition", func(t *testing.T) {
		{
			// Create returns the expected PD.
			request := router.CreatePresentationDefinitionRequest{
				PresentationDefinition: *pd,
			}
			value := newRequestValue(t, request)
			req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/presentation/definition", value)
			w := httptest.NewRecorder()

			err = pRouter.CreatePresentationDefinition(newRequestContext(), w, req)
			assert.NoError(t, err)

			var resp router.CreatePresentationDefinitionResponse
			assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
			assert.Equal(t, *pd, resp.PresentationDefinition)

			w.Flush()
		}
		{
			// We can get the PD after it's created.
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/presentation/definition/%s", pd.ID), nil)
			w := httptest.NewRecorder()
			assert.NoError(t, pRouter.GetPresentationDefinition(newRequestContextWithParams(map[string]string{"id": pd.ID}), w, req))

			var resp router.GetPresentationDefinitionResponse
			assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
			assert.Equal(t, pd.ID, resp.ID)
			assert.Equal(t, *pd, resp.PresentationDefinition)

			w.Flush()
		}
		{
			// The PD can be deleted.
			req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("https://ssi-service.com/v1/presentation/definition/%s", pd.ID), nil)
			w := httptest.NewRecorder()
			assert.NoError(t, pRouter.DeletePresentationDefinition(newRequestContextWithParams(map[string]string{"id": pd.ID}), w, req))

			w.Flush()
		}
		{
			// And we cannot get the PD after it's been deleted.
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/presentation/definition/%s", pd.ID), nil)
			w := httptest.NewRecorder()
			assert.Error(t, pRouter.GetPresentationDefinition(newRequestContextWithParams(map[string]string{"id": pd.ID}), w, req))

			w.Flush()
		}
	})

	t.Run("Create returns error with bad definition", func(t *testing.T) {
		request := router.CreatePresentationDefinitionRequest{
			PresentationDefinition: exchange.PresentationDefinition{ID: "some id"},
		}
		value := newRequestValue(t, request)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/presentation/definition", value)
		w := httptest.NewRecorder()

		err = pRouter.CreatePresentationDefinition(newRequestContext(), w, req)

		assert.Error(t, err)
		w.Flush()
	})

	t.Run("Get without and ID returns error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/presentation/definition/%s", pd.ID), nil)
		w := httptest.NewRecorder()
		assert.Error(t, pRouter.GetPresentationDefinition(newRequestContext(), w, req))
		w.Flush()
	})

	t.Run("Delete without an ID returns error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("https://ssi-service.com/v1/presentation/definition/%s", pd.ID), nil)
		w := httptest.NewRecorder()
		assert.Error(t, pRouter.DeletePresentationDefinition(newRequestContext(), w, req))
		w.Flush()
	})
}
