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
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/issuance"
	"github.com/tbd54566975/ssi-service/pkg/service/manifest/model"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"github.com/tbd54566975/ssi-service/pkg/testutil"
)

func TestIssuanceRouter(t *testing.T) {
	now := time.Now()
	duration := 10 * time.Second

	for _, test := range testutil.TestDatabases {
		t.Run(test.Name, func(t *testing.T) {
			t.Run("CreateIssuanceTemplate", func(tt *testing.T) {
				issuerResp, createdSchema, manifest, r := setupAllThings(tt, test.ServiceStorage(t))
				for _, tc := range []struct {
					name    string
					request router.CreateIssuanceTemplateRequest
				}{
					{
						name: "returns a template with ID",
						request: router.CreateIssuanceTemplateRequest{
							Template: issuance.Template{
								CredentialManifest: manifest.Manifest.ID,
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
					},
					{
						name: "returns a template with ID when schema is empty",
						request: router.CreateIssuanceTemplateRequest{
							Template: issuance.Template{
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
					tt.Run(tc.name, func(t *testing.T) {
						value := newRequestValue(t, tc.request)
						req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/issuancetemplates", value)
						w := httptest.NewRecorder()

						c := newRequestContext(w, req)
						r.CreateIssuanceTemplate(c)
						assert.True(t, util.Is2xxResponse(w.Code))

						var resp issuance.Template
						assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
						assert.NotEmpty(t, resp.ID)
					})
				}
			})

			t.Run("CreateIssuanceTemplate returns error", func(tt *testing.T) {
				issuerResp, createdSchema, manifest, r := setupAllThings(tt, test.ServiceStorage(t))

				for _, tc := range []struct {
					name          string
					request       router.CreateIssuanceTemplateRequest
					expectedError string
				}{
					{
						name: "when missing output_descriptor_id",
						request: router.CreateIssuanceTemplateRequest{
							Template: issuance.Template{
								CredentialManifest: manifest.Manifest.ID,
								Issuer:             issuerResp.DID.ID,
								IssuerKID:          issuerResp.DID.VerificationMethod[0].ID,
								Credentials: []issuance.CredentialTemplate{
									{
										ID:     "",
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
						expectedError: "ID cannot be empty",
					},
					{
						name: "when both times are set",
						request: router.CreateIssuanceTemplateRequest{
							Template: issuance.Template{
								CredentialManifest: manifest.Manifest.ID,
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
							Template: issuance.Template{
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
							Template: issuance.Template{
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
							Template: issuance.Template{
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
					tt.Run(tc.name, func(ttt *testing.T) {
						value := newRequestValue(ttt, tc.request)
						req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/issuancetemplates", value)
						w := httptest.NewRecorder()

						c := newRequestContext(w, req)
						r.CreateIssuanceTemplate(c)
						assert.Contains(ttt, w.Body.String(), tc.expectedError)
					})

				}
			})

			t.Run("Create, Get, Delete work as expected", func(tt *testing.T) {
				issuerResp, createdSchema, manifest, r := setupAllThings(tt, test.ServiceStorage(t))

				inputTemplate := issuance.Template{
					CredentialManifest: manifest.Manifest.ID,
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
				}
				var issuanceTemplate issuance.Template

				{
					request := router.CreateIssuanceTemplateRequest{Template: inputTemplate}
					value := newRequestValue(t, request)
					req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/issuancetemplates", value)
					w := httptest.NewRecorder()

					c := newRequestContext(w, req)
					r.CreateIssuanceTemplate(c)
					assert.True(tt, util.Is2xxResponse(w.Code))

					assert.NoError(t, json.NewDecoder(w.Body).Decode(&issuanceTemplate))
					if diff := cmp.Diff(inputTemplate, issuanceTemplate, cmpopts.IgnoreFields(issuance.Template{}, "ID")); diff != "" {
						t.Errorf("IssuanceTemplate mismatch (-want +got):\n%s", diff)
					}
				}

				{
					value := newRequestValue(tt, nil)
					req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/issuancetemplates/"+issuanceTemplate.ID, value)
					w := httptest.NewRecorder()

					c := newRequestContextWithParams(w, req, map[string]string{"id": issuanceTemplate.ID})
					r.GetIssuanceTemplate(c)
					assert.True(tt, util.Is2xxResponse(w.Code))

					var getIssuanceTemplate issuance.Template
					assert.NoError(t, json.NewDecoder(w.Body).Decode(&getIssuanceTemplate))
					if diff := cmp.Diff(issuanceTemplate, getIssuanceTemplate); diff != "" {
						tt.Errorf("Template mismatch (-want +got):\n%s", diff)
					}
				}

				{
					value := newRequestValue(tt, nil)
					req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/issuancetemplates/"+issuanceTemplate.ID, value)
					w := httptest.NewRecorder()
					c := newRequestContextWithParams(w, req, map[string]string{"id": issuanceTemplate.ID})
					r.DeleteIssuanceTemplate(c)
					assert.True(tt, util.Is2xxResponse(w.Code))
				}

				{
					value := newRequestValue(tt, nil)
					req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/issuancetemplates/"+issuanceTemplate.ID, value)
					w := httptest.NewRecorder()
					c := newRequestContextWithParams(w, req, map[string]string{"id": issuanceTemplate.ID})
					r.GetIssuanceTemplate(c)
					assert.Contains(tt, w.Body.String(), "issuance template not found")
				}
			})

			t.Run("GetIssuanceTemplate returns error for unknown ID", func(tt *testing.T) {
				s := test.ServiceStorage(t)
				r := testIssuanceRouter(tt, s)

				value := newRequestValue(tt, nil)
				req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/issuancetemplates/where-is-it", value)
				w := httptest.NewRecorder()
				c := newRequestContextWithParams(w, req, map[string]string{"id": "where-is-it"})
				r.GetIssuanceTemplate(c)
				assert.Contains(tt, w.Body.String(), "issuance template not found")
			})

			t.Run("ListIssuanceTemplates returns empty when there aren't templates", func(tt *testing.T) {
				s := test.ServiceStorage(t)
				r := testIssuanceRouter(tt, s)

				value := newRequestValue(tt, nil)
				req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/issuancetemplates", value)
				w := httptest.NewRecorder()
				c := newRequestContext(w, req)
				r.ListIssuanceTemplates(c)
				assert.True(tt, util.Is2xxResponse(w.Code))

				var getIssuanceTemplate router.ListIssuanceTemplatesResponse
				assert.NoError(tt, json.NewDecoder(w.Body).Decode(&getIssuanceTemplate))
				assert.Empty(tt, getIssuanceTemplate.IssuanceTemplates)
			})

			t.Run("ListIssuanceTemplates returns all created templates", func(tt *testing.T) {
				issuerResp, createdSchema, manifest, r := setupAllThings(tt, test.ServiceStorage(t))

				createSimpleTemplate(tt, manifest, issuerResp, createdSchema, now, r)
				createSimpleTemplate(tt, manifest, issuerResp, createdSchema, now, r)

				value := newRequestValue(tt, nil)
				req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/issuancetemplates", value)
				w := httptest.NewRecorder()
				c := newRequestContext(w, req)
				r.ListIssuanceTemplates(c)
				assert.True(tt, util.Is2xxResponse(w.Code))

				var getIssuanceTemplate router.ListIssuanceTemplatesResponse
				assert.NoError(tt, json.NewDecoder(w.Body).Decode(&getIssuanceTemplate))
				assert.Len(tt, getIssuanceTemplate.IssuanceTemplates, 2)
			})
		})
	}
}

func createSimpleTemplate(t *testing.T, manifest *model.CreateManifestResponse, issuerResp *did.CreateDIDResponse,
	createdSchema *schema.CreateSchemaResponse, now time.Time, r *router.IssuanceRouter) {
	{
		request := router.CreateIssuanceTemplateRequest{
			Template: issuance.Template{
				CredentialManifest: manifest.Manifest.ID,
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
		}
		value := newRequestValue(t, request)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/issuancetemplates", value)
		w := httptest.NewRecorder()

		c := newRequestContext(w, req)
		r.CreateIssuanceTemplate(c)
		assert.True(t, util.Is2xxResponse(w.Code))
	}
}

func setupAllThings(t *testing.T, s storage.ServiceStorage) (*did.CreateDIDResponse, *schema.CreateSchemaResponse, *model.CreateManifestResponse, *router.IssuanceRouter) {
	//s := setupTestDB(t)

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
		"$schema": "https://json-schema.org/draft-07/schema",
		"type":    "object",
		"properties": map[string]any{
			"credentialSubject": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": map[string]any{
						"type": "string",
					},
					"licenseType": map[string]any{
						"type": "string",
					},
				},
				"required": []any{"licenseType", "id"},
			},
		},
	}
	keyID := issuerResp.DID.VerificationMethod[0].ID
	createdSchema, err := schemaSvc.CreateSchema(context.Background(), schema.CreateSchemaRequest{Issuer: issuerResp.DID.ID, IssuerKID: keyID, Name: "license schema", Schema: licenseSchema})
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
				Schema: createdSchema.ID,
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
