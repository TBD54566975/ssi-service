package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	manifestsdk "github.com/TBD54566975/ssi-sdk/credential/manifest"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/goccy/go-json"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/issuance"
	"github.com/tbd54566975/ssi-service/pkg/service/manifest/model"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

func TestIssuanceRouter(t *testing.T) {
	now := time.Now()
	duration := 10 * time.Second
	t.Run("CreateIssuanceTemplate", func(t *testing.T) {
		issuerResp, createdSchema, manifest, r := setupAllThings(t)
		for _, tc := range []struct {
			name    string
			request router.CreateIssuanceTemplateRequest
		}{
			{
				name: "returns a template with ID",
				request: router.CreateIssuanceTemplateRequest{
					IssuanceTemplate: issuance.IssuanceTemplate{
						CredentialManifest: manifest.Manifest.ID,
						Issuer:             issuerResp.DID.ID,
						IssuerKID:          issuerResp.DID.VerificationMethod[0].ID,
						Credentials: []issuance.CredentialTemplate{
							{
								ID:     "output_descriptor_1",
								Schema: createdSchema.Schema.ID,
								Data: issuance.ClaimTemplates{
									"foo":   "bar",
									"hello": "$.vcsomething.something",
								},
								Expiry: issuance.TimeLike{
									Time: &now,
								},
							},
						},
					},
				},
			},
			{
				name: "returns a template with ID when schema is empty",
				request: router.CreateIssuanceTemplateRequest{
					IssuanceTemplate: issuance.IssuanceTemplate{
						CredentialManifest: manifest.Manifest.ID,
						Issuer:             issuerResp.DID.ID,
						IssuerKID:          issuerResp.DID.VerificationMethod[0].ID,
						Credentials: []issuance.CredentialTemplate{
							{
								ID:     "output_descriptor_1",
								Schema: "",
								Data: issuance.ClaimTemplates{
									"foo":   "bar",
									"hello": "$.vcsomething.something",
								},
								Expiry: issuance.TimeLike{
									Time: &now,
								},
							},
						},
					},
				},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				value := newRequestValue(t, tc.request)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/issuancetemplates", value)
				w := httptest.NewRecorder()

				c := newRequestContext(w, req)
				err := r.CreateIssuanceTemplate(c)
				assert.NoError(t, err)

				var resp issuance.IssuanceTemplate
				assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
				assert.NotEmpty(t, resp.ID)
			})
		}
	})

	t.Run("CreateIssuanceTemplate returns error", func(t *testing.T) {
		issuerResp, createdSchema, manifest, r := setupAllThings(t)

		for _, tc := range []struct {
			name          string
			request       router.CreateIssuanceTemplateRequest
			expectedError string
		}{
			{
				name: "when missing output_descriptor_id",
				request: router.CreateIssuanceTemplateRequest{
					IssuanceTemplate: issuance.IssuanceTemplate{
						CredentialManifest: manifest.Manifest.ID,
						Issuer:             issuerResp.DID.ID,
						IssuerKID:          issuerResp.DID.VerificationMethod[0].ID,
						Credentials: []issuance.CredentialTemplate{
							{
								ID:     "",
								Schema: createdSchema.Schema.ID,
								Data: issuance.ClaimTemplates{
									"foo":   "bar",
									"hello": "$.vcsomething.something",
								},
								Expiry: issuance.TimeLike{
									Time: &now,
								},
							},
						},
					},
				},
				expectedError: "ID cannot be empty",
			},
			{
				name: "when both times are set",
				request: router.CreateIssuanceTemplateRequest{
					IssuanceTemplate: issuance.IssuanceTemplate{
						CredentialManifest: manifest.Manifest.ID,
						Issuer:             issuerResp.DID.ID,
						IssuerKID:          issuerResp.DID.VerificationMethod[0].ID,
						Credentials: []issuance.CredentialTemplate{
							{
								ID:     "output_descriptor_1",
								Schema: createdSchema.Schema.ID,
								Data: issuance.ClaimTemplates{
									"foo":   "bar",
									"hello": "$.vcsomething.something",
								},
								Expiry: issuance.TimeLike{
									Time:     &now,
									Duration: &duration,
								},
							},
						},
					},
				},
				expectedError: "Time and Duration cannot be both set simultaneously",
			},
			{
				name: "when credential schema does not exist",
				request: router.CreateIssuanceTemplateRequest{
					IssuanceTemplate: issuance.IssuanceTemplate{
						CredentialManifest: manifest.Manifest.ID,
						Issuer:             issuerResp.DID.ID,
						IssuerKID:          issuerResp.DID.VerificationMethod[0].ID,
						Credentials: []issuance.CredentialTemplate{
							{
								ID:     "output_descriptor_1",
								Schema: "fake schema",
								Data: issuance.ClaimTemplates{
									"foo":   "bar",
									"hello": "$.vcsomething.something",
								},
								Expiry: issuance.TimeLike{
									Time: &now,
								},
							},
						},
					},
				},
				expectedError: "schema not found",
			},
			{
				name: "when credential manifest ID is does not exist",
				request: router.CreateIssuanceTemplateRequest{
					IssuanceTemplate: issuance.IssuanceTemplate{
						CredentialManifest: "fake manifest id",
						Issuer:             issuerResp.DID.ID,
						IssuerKID:          issuerResp.DID.VerificationMethod[0].ID,
						Credentials: []issuance.CredentialTemplate{
							{
								ID:     "output_descriptor_1",
								Schema: createdSchema.ID,
								Data: issuance.ClaimTemplates{
									"foo":   "bar",
									"hello": "$.vcsomething.something",
								},
								Expiry: issuance.TimeLike{
									Time: &now,
								},
							},
						},
					},
				},
				expectedError: "manifest not found",
			},
			{
				name: "when issuer is empty",
				request: router.CreateIssuanceTemplateRequest{
					IssuanceTemplate: issuance.IssuanceTemplate{
						CredentialManifest: manifest.Manifest.ID,
						Credentials: []issuance.CredentialTemplate{
							{
								ID:     "output_descriptor_1",
								Schema: createdSchema.ID,
								Data: issuance.ClaimTemplates{
									"foo":   "bar",
									"hello": "$.vcsomething.something",
								},
								Expiry: issuance.TimeLike{
									Time: &now,
								},
							},
						},
					},
				},
				expectedError: "field validation error",
			},
		} {
			t.Run(tc.name, func(t *testing.T) {

				value := newRequestValue(t, tc.request)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/issuancetemplates", value)
				w := httptest.NewRecorder()

				c := newRequestContext(w, req)
				err := r.CreateIssuanceTemplate(c)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)

			})

		}
	})

	t.Run("Create, Get, Delete work as expected", func(t *testing.T) {
		issuerResp, createdSchema, manifest, r := setupAllThings(t)

		inputTemplate := issuance.IssuanceTemplate{
			CredentialManifest: manifest.Manifest.ID,
			Issuer:             issuerResp.DID.ID,
			IssuerKID:          issuerResp.DID.VerificationMethod[0].ID,
			Credentials: []issuance.CredentialTemplate{
				{
					ID:     "output_descriptor_1",
					Schema: createdSchema.Schema.ID,
					Data: issuance.ClaimTemplates{
						"foo":   "bar",
						"hello": "$.vcsomething.something",
					},
					Expiry: issuance.TimeLike{
						Time: &now,
					},
				},
			},
		}
		var issuanceTemplate issuance.IssuanceTemplate

		{
			request := router.CreateIssuanceTemplateRequest{
				IssuanceTemplate: inputTemplate,
			}
			value := newRequestValue(t, request)
			req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/issuancetemplates", value)
			w := httptest.NewRecorder()

			c := newRequestContext(w, req)
			err := r.CreateIssuanceTemplate(c)
			assert.NoError(t, err)

			assert.NoError(t, json.NewDecoder(w.Body).Decode(&issuanceTemplate))
			if diff := cmp.Diff(inputTemplate, issuanceTemplate, cmpopts.IgnoreFields(issuance.IssuanceTemplate{}, "ID")); diff != "" {
				t.Errorf("IssuanceTemplate mismatch (-want +got):\n%s", diff)
			}
		}

		{
			value := newRequestValue(t, nil)
			req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/issuancetemplates/"+issuanceTemplate.ID, value)
			w := httptest.NewRecorder()

			c := newRequestContextWithParams(w, req, map[string]string{"id": issuanceTemplate.ID})
			err := r.GetIssuanceTemplate(c)
			assert.NoError(t, err)

			var getIssuanceTemplate issuance.IssuanceTemplate
			assert.NoError(t, json.NewDecoder(w.Body).Decode(&getIssuanceTemplate))
			if diff := cmp.Diff(issuanceTemplate, getIssuanceTemplate); diff != "" {
				t.Errorf("IssuanceTemplate mismatch (-want +got):\n%s", diff)
			}
		}

		{
			value := newRequestValue(t, nil)
			req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/issuancetemplates/"+issuanceTemplate.ID, value)
			w := httptest.NewRecorder()
			c := newRequestContextWithParams(w, req, map[string]string{"id": issuanceTemplate.ID})
			err := r.DeleteIssuanceTemplate(c)
			assert.NoError(t, err)
		}

		{
			value := newRequestValue(t, nil)
			req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/issuancetemplates/"+issuanceTemplate.ID, value)
			w := httptest.NewRecorder()
			c := newRequestContextWithParams(w, req, map[string]string{"id": issuanceTemplate.ID})
			err := r.GetIssuanceTemplate(c)

			assert.Error(t, err)
			assert.Contains(t, err.Error(), "issuance template not found")
		}
	})

	t.Run("GetIssuanceTemplate returns error for unknown ID", func(t *testing.T) {
		s := setupTestDB(t)
		r := testIssuanceRouter(t, s)

		value := newRequestValue(t, nil)
		req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/issuancetemplates/where-is-it", value)
		w := httptest.NewRecorder()
		c := newRequestContextWithParams(w, req, map[string]string{"id": "where-is-it"})
		err := r.GetIssuanceTemplate(c)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "issuance template not found")
	})

	t.Run("ListIssuanceTemplates returns empty when there aren't templates", func(t *testing.T) {
		s := setupTestDB(t)
		r := testIssuanceRouter(t, s)

		value := newRequestValue(t, nil)
		req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/issuancetemplates", value)
		w := httptest.NewRecorder()
		c := newRequestContext(w, req)
		err := r.ListIssuanceTemplates(c)

		assert.NoError(t, err)
		var getIssuanceTemplate router.ListIssuanceTemplatesResponse
		assert.NoError(t, json.NewDecoder(w.Body).Decode(&getIssuanceTemplate))
		assert.Empty(t, getIssuanceTemplate.IssuanceTemplates)
	})

	t.Run("ListIssuanceTemplates returns all created templates", func(t *testing.T) {
		issuerResp, createdSchema, manifest, r := setupAllThings(t)

		createSimpleTemplate(t, manifest, issuerResp, createdSchema, now, r)
		createSimpleTemplate(t, manifest, issuerResp, createdSchema, now, r)

		value := newRequestValue(t, nil)
		req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/issuancetemplates", value)
		w := httptest.NewRecorder()
		c := newRequestContext(w, req)
		err := r.ListIssuanceTemplates(c)

		assert.NoError(t, err)
		var getIssuanceTemplate router.ListIssuanceTemplatesResponse
		assert.NoError(t, json.NewDecoder(w.Body).Decode(&getIssuanceTemplate))
		assert.Len(t, getIssuanceTemplate.IssuanceTemplates, 2)
	})
}

func createSimpleTemplate(t *testing.T, manifest *model.CreateManifestResponse, issuerResp *did.CreateDIDResponse, createdSchema *schema.CreateSchemaResponse, now time.Time, r *router.IssuanceRouter) {
	{
		request := router.CreateIssuanceTemplateRequest{
			IssuanceTemplate: issuance.IssuanceTemplate{
				CredentialManifest: manifest.Manifest.ID,
				Issuer:             issuerResp.DID.ID,
				IssuerKID:          issuerResp.DID.VerificationMethod[0].ID,
				Credentials: []issuance.CredentialTemplate{
					{
						ID:     "output_descriptor_1",
						Schema: createdSchema.Schema.ID,
						Data: issuance.ClaimTemplates{
							"foo":   "bar",
							"hello": "$.vcsomething.something",
						},
						Expiry: issuance.TimeLike{
							Time: &now,
						},
					},
				},
			},
		}
		value := newRequestValue(t, request)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/issuancetemplates", value)
		w := httptest.NewRecorder()

		c := newRequestContext(w, req)
		err := r.CreateIssuanceTemplate(c)
		require.NoError(t, err)
	}
}

func setupAllThings(t *testing.T) (*did.CreateDIDResponse, *schema.CreateSchemaResponse, *model.CreateManifestResponse, *router.IssuanceRouter) {
	s := setupTestDB(t)

	_, keyStoreSvc := testKeyStore(t, s)
	didSvc := testDIDService(t, s, keyStoreSvc)
	schemaSvc := testSchemaService(t, s, keyStoreSvc, didSvc)
	credSvc := testCredentialService(t, s, keyStoreSvc, didSvc, schemaSvc)
	_, manifestSvc := testManifest(t, s, keyStoreSvc, didSvc, credSvc)

	issuerResp, err := didSvc.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
		Method:  "key",
		KeyType: crypto.Ed25519,
	})
	require.NoError(t, err)

	licenseSchema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"licenseType": map[string]any{
				"type": "string",
			},
		},
		"additionalProperties": true,
	}
	keyID := issuerResp.DID.VerificationMethod[0].ID
	createdSchema, err := schemaSvc.CreateSchema(context.Background(), schema.CreateSchemaRequest{Author: issuerResp.DID.ID, AuthorKID: keyID, Name: "license schema", Schema: licenseSchema, Sign: true})
	require.NoError(t, err)

	sillyName := "some silly name"
	manifest, err := manifestSvc.CreateManifest(context.Background(), model.CreateManifestRequest{
		Name:      &sillyName,
		IssuerDID: issuerResp.DID.ID,
		IssuerKID: issuerResp.DID.VerificationMethod[0].ID,
		ClaimFormat: &exchange.ClaimFormat{
			JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
		},
		OutputDescriptors: []manifestsdk.OutputDescriptor{
			{
				ID:     "output_descriptor_1",
				Schema: createdSchema.Schema.ID,
			},
		},
	})
	require.NoError(t, err)

	r := testIssuanceRouter(t, s)
	return issuerResp, createdSchema, manifest, r
}

func testIssuanceRouter(t *testing.T, s storage.ServiceStorage) *router.IssuanceRouter {
	serviceConfig := config.IssuanceServiceConfig{BaseServiceConfig: &config.BaseServiceConfig{Name: "test-issuance"}}
	svc, err := issuance.NewIssuanceService(serviceConfig, s)
	require.NoError(t, err)

	r, err := router.NewIssuanceRouter(svc)
	require.NoError(t, err)
	return r
}
