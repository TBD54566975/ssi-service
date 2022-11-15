package server

import (
	"fmt"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/goccy/go-json"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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
	inputDescriptors := []exchange.InputDescriptor{
		{
			ID:      "id",
			Name:    "name",
			Purpose: "purpose",
			Format: &exchange.ClaimFormat{
				JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
			},
			Constraints: &exchange.Constraints{SubjectIsIssuer: exchange.Preferred.Ptr()},
		},
	}
	assert.NoError(t, builder.SetInputDescriptors(inputDescriptors))
	assert.NoError(t, builder.SetName("name"))
	assert.NoError(t, builder.SetPurpose("purpose"))
	pd, err := builder.Build()
	assert.NoError(t, err)

	s, err := storage.NewStorage(storage.Bolt)
	assert.NoError(t, err)

	service, err := presentation.NewPresentationService(config.PresentationServiceConfig{}, s)
	assert.NoError(t, err)

	pRouter, err := router.NewPresentationRouter(service)
	assert.NoError(t, err)

	t.Cleanup(func() {
		_ = s.Close()
		_ = os.Remove(storage.DBFile)
	})

	t.Run("Create, Get, and Delete PresentationDefinition", func(t *testing.T) {
		var createdID string
		{
			// Create returns the expected PD.
			request := router.CreatePresentationDefinitionRequest{
				Name:                   "name",
				Purpose:                "purpose",
				Format:                 nil,
				SubmissionRequirements: nil,
				InputDescriptors:       inputDescriptors,
			}
			value := newRequestValue(t, request)
			req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/presentations/definitions", value)
			w := httptest.NewRecorder()

			err = pRouter.CreatePresentationDefinition(newRequestContext(), w, req)
			assert.NoError(t, err)

			var resp router.CreatePresentationDefinitionResponse
			assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
			if diff := cmp.Diff(*pd, resp.PresentationDefinition, cmpopts.IgnoreFields(exchange.PresentationDefinition{}, "ID")); diff != "" {
				t.Errorf("PresentationDefinition mismatch (-want +got):\n%s", diff)
			}

			w.Flush()
			createdID = resp.PresentationDefinition.ID
		}
		{
			// We can get the PD after it's created.
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/presentations/definitions/%s", createdID), nil)
			w := httptest.NewRecorder()
			assert.NoError(t, pRouter.GetPresentationDefinition(newRequestContextWithParams(map[string]string{"id": createdID}), w, req))

			var resp router.GetPresentationDefinitionResponse
			assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
			assert.Equal(t, createdID, resp.PresentationDefinition.ID)
			if diff := cmp.Diff(*pd, resp.PresentationDefinition, cmpopts.IgnoreFields(exchange.PresentationDefinition{}, "ID")); diff != "" {
				t.Errorf("PresentationDefinition mismatch (-want +got):\n%s", diff)
			}

			w.Flush()
		}
		{
			// The PD can be deleted.
			req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("https://ssi-service.com/v1/presentations/definitions/%s", createdID), nil)
			w := httptest.NewRecorder()
			assert.NoError(t, pRouter.DeletePresentationDefinition(newRequestContextWithParams(map[string]string{"id": createdID}), w, req))

			w.Flush()
		}
		{
			// And we cannot get the PD after it's been deleted.
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/presentations/definitions/%s", createdID), nil)
			w := httptest.NewRecorder()
			assert.Error(t, pRouter.GetPresentationDefinition(newRequestContextWithParams(map[string]string{"id": createdID}), w, req))

			w.Flush()
		}
	})

	t.Run("Create returns error without input descriptors", func(t *testing.T) {
		request := router.CreatePresentationDefinitionRequest{}
		value := newRequestValue(t, request)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/presentations/definitions", value)
		w := httptest.NewRecorder()

		err = pRouter.CreatePresentationDefinition(newRequestContext(), w, req)

		assert.Error(t, err)
		w.Flush()
	})

	t.Run("Get without an ID returns error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/presentations/definitions/%s", pd.ID), nil)
		w := httptest.NewRecorder()
		assert.Error(t, pRouter.GetPresentationDefinition(newRequestContext(), w, req))
		w.Flush()
	})

	t.Run("Delete without an ID returns error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("https://ssi-service.com/v1/presentations/definitions/%s", pd.ID), nil)
		w := httptest.NewRecorder()
		assert.Error(t, pRouter.DeletePresentationDefinition(newRequestContext(), w, req))
		w.Flush()
	})
}
