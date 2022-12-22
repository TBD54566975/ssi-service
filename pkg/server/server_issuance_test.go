package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	manifestsdk "github.com/TBD54566975/ssi-sdk/credential/manifest"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/issuing"
	"github.com/tbd54566975/ssi-service/pkg/service/manifest/model"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
)

func TestIssuanceRouter(t *testing.T) {
	now := time.Now()
	duration := 10 * time.Second
	t.Run("CreateIssuanceTemplate returns a template with ID", func(t *testing.T) {
		issuerResp, createdSchema, manifest, r := setupAllThings(t)

		request := router.CreateIssuanceTemplateRequest{
			IssuanceTemplate: issuing.IssuanceTemplate{
				CredentialManifest: manifest.Manifest.ID,
				Issuer:             issuerResp.DID.ID,
				Credentials: []issuing.CredentialTemplate{
					{
						ID:     "output_descriptor_1",
						Schema: createdSchema.Schema.ID,
						Data: issuing.CredentialTemplateData{
							Claims: issuing.ClaimTemplates{
								Data: map[string]any{
									"foo":   "bar",
									"hello": "$.vcsomething.something",
								},
							},
						},
						Expiry: issuing.TimeLike{
							Time: &now,
						},
					},
				},
			},
		}
		value := newRequestValue(t, request)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/issuancetemplates", value)
		w := httptest.NewRecorder()

		err := r.CreateIssuanceTemplate(newRequestContext(), w, req)
		assert.NoError(t, err)

		var resp issuing.IssuanceTemplate
		assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		assert.NotEmpty(t, resp.ID)
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
					IssuanceTemplate: issuing.IssuanceTemplate{
						CredentialManifest: manifest.Manifest.ID,
						Issuer:             issuerResp.DID.ID,
						Credentials: []issuing.CredentialTemplate{
							{
								ID:     "",
								Schema: createdSchema.Schema.ID,
								Data: issuing.CredentialTemplateData{
									Claims: issuing.ClaimTemplates{
										Data: map[string]any{
											"foo":   "bar",
											"hello": "$.vcsomething.something",
										},
									},
								},
								Expiry: issuing.TimeLike{
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
					IssuanceTemplate: issuing.IssuanceTemplate{
						CredentialManifest: manifest.Manifest.ID,
						Issuer:             issuerResp.DID.ID,
						Credentials: []issuing.CredentialTemplate{
							{
								ID:     "output_descriptor_1",
								Schema: createdSchema.Schema.ID,
								Data: issuing.CredentialTemplateData{
									Claims: issuing.ClaimTemplates{
										Data: map[string]any{
											"foo":   "bar",
											"hello": "$.vcsomething.something",
										},
									},
								},
								Expiry: issuing.TimeLike{
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
				name: "when schema does not exist",
				request: router.CreateIssuanceTemplateRequest{
					IssuanceTemplate: issuing.IssuanceTemplate{
						CredentialManifest: manifest.Manifest.ID,
						Issuer:             issuerResp.DID.ID,
						Credentials: []issuing.CredentialTemplate{
							{
								ID:     "output_descriptor_1",
								Schema: "fake schema",
								Data: issuing.CredentialTemplateData{
									Claims: issuing.ClaimTemplates{
										Data: map[string]any{
											"foo":   "bar",
											"hello": "$.vcsomething.something",
										},
									},
								},
								Expiry: issuing.TimeLike{
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
					IssuanceTemplate: issuing.IssuanceTemplate{
						CredentialManifest: "fake manifest id",
						Issuer:             issuerResp.DID.ID,
						Credentials: []issuing.CredentialTemplate{
							{
								ID:     "output_descriptor_1",
								Schema: createdSchema.ID,
								Data: issuing.CredentialTemplateData{
									Claims: issuing.ClaimTemplates{
										Data: map[string]any{
											"foo":   "bar",
											"hello": "$.vcsomething.something",
										},
									},
								},
								Expiry: issuing.TimeLike{
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
					IssuanceTemplate: issuing.IssuanceTemplate{
						CredentialManifest: manifest.Manifest.ID,
						Credentials: []issuing.CredentialTemplate{
							{
								ID:     "output_descriptor_1",
								Schema: createdSchema.ID,
								Data: issuing.CredentialTemplateData{
									Claims: issuing.ClaimTemplates{
										Data: map[string]any{
											"foo":   "bar",
											"hello": "$.vcsomething.something",
										},
									},
								},
								Expiry: issuing.TimeLike{
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

				err := r.CreateIssuanceTemplate(newRequestContext(), w, req)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)

			})

		}
	})
}

func setupAllThings(t *testing.T) (*did.CreateDIDResponse, *schema.CreateSchemaResponse, *model.CreateManifestResponse, *router.IssuanceRouter) {
	s := setupTestDB(t)

	_, keyStoreSvc := testKeyStore(t, s)
	didSvc := testDIDService(t, s, keyStoreSvc)
	schemaSvc := testSchemaService(t, s, keyStoreSvc, didSvc)
	credSvc := testCredentialService(t, s, keyStoreSvc, didSvc, schemaSvc)
	_, manifestSvc := testManifest(t, s, keyStoreSvc, didSvc, credSvc)

	issuerResp, err := didSvc.CreateDIDByMethod(did.CreateDIDRequest{
		Method:  "key",
		KeyType: crypto.Ed25519,
	})
	assert.NoError(t, err)

	licenseSchema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"licenseType": map[string]any{
				"type": "string",
			},
		},
		"additionalProperties": true,
	}
	createdSchema, err := schemaSvc.CreateSchema(schema.CreateSchemaRequest{Author: issuerResp.DID.ID, Name: "license schema", Schema: licenseSchema, Sign: true})
	assert.NoError(t, err)
	sillyName := "some silly name"
	manifest, err := manifestSvc.CreateManifest(model.CreateManifestRequest{
		Name:      &sillyName,
		IssuerDID: issuerResp.DID.ID,
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
	assert.NoError(t, err)

	svc, err := issuing.NewIssuingService(config.IssuingServiceConfig{BaseServiceConfig: &config.BaseServiceConfig{
		Name: "test-issuing",
	}}, s)
	assert.NoError(t, err)

	r, err := router.NewIssuanceRouter(svc)
	assert.NoError(t, err)
	return issuerResp, createdSchema, manifest, r
}
