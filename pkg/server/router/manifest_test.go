package router

import (
	"context"
	"testing"
	"time"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	manifestsdk "github.com/TBD54566975/ssi-sdk/credential/manifest"
	"github.com/TBD54566975/ssi-sdk/crypto"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/key"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	credmodel "github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/pkg/service/common"
	"github.com/tbd54566975/ssi-service/pkg/service/credential"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/manifest/model"
	"github.com/tbd54566975/ssi-service/pkg/service/operation/storage"
	presmodel "github.com/tbd54566975/ssi-service/pkg/service/presentation/model"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
)

func TestManifestRouter(t *testing.T) {

	t.Run("Nil Service", func(tt *testing.T) {
		manifestRouter, err := NewManifestRouter(nil)
		assert.Error(tt, err)
		assert.Empty(tt, manifestRouter)
		assert.Contains(tt, err.Error(), "service cannot be nil")
	})

	t.Run("Bad Service", func(tt *testing.T) {
		manifestRouter, err := NewManifestRouter(&testService{})
		assert.Error(tt, err)
		assert.Empty(tt, manifestRouter)
		assert.Contains(tt, err.Error(), "could not create manifest router with service type: test")
	})

	t.Run("Manifest Service Test", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		assert.NotEmpty(tt, bolt)

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credentialService := testCredentialService(tt, bolt, keyStoreService, didService, schemaService)
		presentationService := testPresentationDefinitionService(tt, bolt, didService, schemaService, keyStoreService)
		manifestService := testManifestService(tt, bolt, keyStoreService, didService, credentialService, presentationService)
		assert.NotEmpty(tt, manifestService)

		tt.Run("CreateManifest with presentation ID and value error", func(ttt *testing.T) {
			defID := "an ID I know"
			createManifestRequest := getValidManifestRequest("issuerDID", "issuerKID", "schemaID")
			createManifestRequest.PresentationDefinition.ID = &defID

			_, err := manifestService.CreateManifest(context.Background(), createManifestRequest)

			assert.Error(ttt, err)
			assert.ErrorContains(ttt, err, `only one of "id" and "value" can be provided`)
		})

		tt.Run("CreateManifest with bad presentation ID returns error", func(ttt *testing.T) {
			defID := "a bad ID"
			createManifestRequest := getValidManifestRequest("issuerDID", "issuerKID", "schemaID")
			createManifestRequest.PresentationDefinition = &model.PresentationDefinitionRef{
				ID: &defID,
			}

			_, err := manifestService.CreateManifest(context.Background(), createManifestRequest)

			assert.Error(ttt, err)
			assert.ErrorContains(ttt, err, "presentation definition not found")
		})

		tt.Run("CreateManifest with presentation ID returns manifest", func(ttt *testing.T) {
			definition := createPresentationDefinition(ttt)
			resp, err := presentationService.CreatePresentationDefinition(context.Background(), presmodel.CreatePresentationDefinitionRequest{
				PresentationDefinition: *definition,
			})
			assert.NoError(ttt, err)
			assert.NotEmpty(ttt, resp)

			createManifestRequest := getValidManifestRequest("issuerDID", "issuerKID", "schemaID")
			createManifestRequest.PresentationDefinition = &model.PresentationDefinitionRef{
				ID: &resp.PresentationDefinition.ID,
			}
			manifest, err := manifestService.CreateManifest(context.Background(), createManifestRequest)

			assert.NoError(ttt, err)
			assert.Equal(ttt, resp.PresentationDefinition, *manifest.Manifest.PresentationDefinition)
		})

		tt.Run("multiple behaviors", func(ttt *testing.T) {
			// check type and status
			assert.Equal(ttt, framework.Manifest, manifestService.Type())
			assert.Equal(ttt, framework.StatusReady, manifestService.Status().Status)

			// create issuer and applicant DIDs
			createDIDRequest := did.CreateDIDRequest{
				Method:  didsdk.KeyMethod,
				KeyType: crypto.Ed25519,
			}
			issuerDID, err := didService.CreateDIDByMethod(context.Background(), createDIDRequest)
			assert.NoError(ttt, err)
			assert.NotEmpty(ttt, issuerDID)

			applicantPrivKey, applicantDIDKey, err := key.GenerateDIDKey(crypto.Ed25519)
			assert.NoError(ttt, err)
			assert.NotEmpty(ttt, applicantPrivKey)
			assert.NotEmpty(ttt, applicantDIDKey)

			applicantDID, err := applicantDIDKey.Expand()
			assert.NoError(ttt, err)
			assert.NotEmpty(ttt, applicantDID)

			// create a schema for the creds to be issued against
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
			kid := issuerDID.DID.VerificationMethod[0].ID
			createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Issuer: issuerDID.DID.ID, IssuerKID: kid, Name: "license schema", Schema: licenseSchema})
			assert.NoError(ttt, err)
			assert.NotEmpty(ttt, createdSchema)

			// issue a credential against the schema to the subject, from the issuer
			createdCred, err := credentialService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
				Issuer:    issuerDID.DID.ID,
				IssuerKID: kid,
				Subject:   applicantDID.ID,
				SchemaID:  createdSchema.ID,
				Data:      map[string]any{"licenseType": "WA-DL-CLASS-A"},
			})
			assert.NoError(ttt, err)
			assert.NotEmpty(ttt, createdCred)

			// good manifest request, which asks for a single verifiable credential in the VC-JWT format
			createManifestRequest := getValidManifestRequest(issuerDID.DID.ID, kid, createdSchema.ID)
			createdManifest, err := manifestService.CreateManifest(context.Background(), createManifestRequest)
			assert.NoError(ttt, err)
			assert.NotEmpty(ttt, createdManifest)

			manifestRequestRequest := getValidManifestRequestRequest(issuerDID, kid, createdManifest)
			manifestRequest, err := manifestService.CreateRequest(context.Background(), manifestRequestRequest)
			assert.NoError(ttt, err)
			assert.Equal(ttt, createdManifest.Manifest.ID, manifestRequest.ManifestID)
			assert.NotEmpty(ttt, manifestRequest.CredentialManifestJWT.String())

			got, err := manifestService.GetRequest(context.Background(), &model.GetRequestRequest{ID: manifestRequest.ID})
			assert.NoError(t, err)
			assert.Equal(t, manifestRequest, got)

			err = manifestService.DeleteRequest(context.Background(), model.DeleteRequestRequest{ID: manifestRequest.ID})
			assert.NoError(t, err)

			_, err = manifestService.GetRequest(context.Background(), &model.GetRequestRequest{ID: manifestRequest.ID})
			assert.Error(t, err)
			assert.ErrorContains(t, err, "request not found")

			verificationResponse, err := manifestService.VerifyManifest(context.Background(), model.VerifyManifestRequest{ManifestJWT: manifestRequest.CredentialManifestJWT})
			assert.NoError(ttt, err)
			assert.NotEmpty(ttt, verificationResponse)
			assert.True(ttt, verificationResponse.Verified)

			m := createdManifest.Manifest
			assert.NotEmpty(ttt, m)

			// good application request
			containers := []credmodel.Container{{
				ID:            createdCred.ID,
				CredentialJWT: createdCred.CredentialJWT,
			}}
			applicationRequest := getValidApplicationRequest(m.ID, m.PresentationDefinition.ID, m.PresentationDefinition.InputDescriptors[0].ID, containers)

			// sign application
			signer, err := keyaccess.NewJWKKeyAccess(applicantDID.ID, applicantDID.VerificationMethod[0].ID, applicantPrivKey)
			assert.NoError(ttt, err)
			signed, err := signer.SignJSON(applicationRequest)
			assert.NoError(ttt, err)

			submitApplicationRequest := SubmitApplicationRequest{ApplicationJWT: *signed}
			sar, err := submitApplicationRequest.toServiceRequest()
			assert.NoError(ttt, err)
			createdApplicationResponseOp, err := manifestService.ProcessApplicationSubmission(context.Background(), *sar)
			assert.NoError(ttt, err)
			assert.False(ttt, createdApplicationResponseOp.Done)

			createdApplicationResponse, err := manifestService.ReviewApplication(context.Background(), model.ReviewApplicationRequest{
				ID:       storage.StatusObjectID(createdApplicationResponseOp.ID),
				Approved: true,
				Reason:   "ApprovalMan is here",
				CredentialOverrides: map[string]model.CredentialOverride{
					"id1": {
						Data: map[string]any{"licenseType": "Class D"},
					},
					"id2": {
						Data: map[string]any{"licenseType": "Class D"},
					},
				},
			})
			assert.NoError(ttt, err)
			assert.NotEmpty(ttt, createdManifest)
			assert.NotEmpty(ttt, createdApplicationResponse.Response.ID)
			assert.NotEmpty(ttt, createdApplicationResponse.Response.Fulfillment)
			assert.Empty(ttt, createdApplicationResponse.Response.Denial)
			assert.Equal(ttt, len(createManifestRequest.OutputDescriptors), len(createdApplicationResponse.Credentials))
		})
	})
}

func getValidManifestRequestRequest(issuerDID *did.CreateDIDResponse, kid string, createdManifest *model.CreateManifestResponse) model.CreateRequestRequest {
	return model.CreateRequestRequest{
		ManifestRequest: model.Request{
			Request: common.Request{
				Audience:   []string{"mario"},
				IssuerDID:  issuerDID.DID.ID,
				IssuerKID:  kid,
				Expiration: time.Now().Add(100 * time.Second),
			},
			ManifestID: createdManifest.Manifest.ID,
		},
	}
}

// getValidManifestRequest returns a valid manifest request, expecting a single JWT-VC EdDSA credential
func getValidManifestRequest(issuerDID, issuerKID, schemaID string) model.CreateManifestRequest {
	createManifestRequest := model.CreateManifestRequest{
		IssuerDID: issuerDID,
		IssuerKID: issuerKID,
		ClaimFormat: &exchange.ClaimFormat{
			JWTVC: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
		},
		PresentationDefinition: &model.PresentationDefinitionRef{
			PresentationDefinition: &exchange.PresentationDefinition{
				ID: "id123",
				InputDescriptors: []exchange.InputDescriptor{
					{
						ID: "license-type",
						Constraints: &exchange.Constraints{
							Fields: []exchange.Field{
								{
									Path: []string{"$.vc.credentialSubject.licenseType"},
								},
							},
						},
						Format: &exchange.ClaimFormat{
							JWTVC: &exchange.JWTType{
								Alg: []crypto.SignatureAlgorithm{crypto.EdDSA},
							},
						},
					},
				},
			},
		},
		OutputDescriptors: []manifestsdk.OutputDescriptor{
			{
				ID:          "id1",
				Schema:      schemaID,
				Name:        "good ID",
				Description: "it's all good",
			},
			{
				ID:          "id2",
				Schema:      schemaID,
				Name:        "good ID",
				Description: "it's all good",
			},
		},
	}

	return createManifestRequest
}

func getValidApplicationRequest(manifestID, presDefID, submissionDescriptorID string, credentials []credmodel.Container) manifestsdk.CredentialApplicationWrapper {
	createApplication := manifestsdk.CredentialApplication{
		ID:          uuid.New().String(),
		SpecVersion: manifestsdk.SpecVersion,
		ManifestID:  manifestID,
		Format: &exchange.ClaimFormat{
			JWTVC: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
		},
		PresentationSubmission: &exchange.PresentationSubmission{
			ID:           "psid",
			DefinitionID: presDefID,
			DescriptorMap: []exchange.SubmissionDescriptor{
				{
					ID:     submissionDescriptorID,
					Format: exchange.JWTVC.String(),
					Path:   "$.verifiableCredentials[0]",
				},
			},
		},
	}

	creds := credmodel.ContainersToInterface(credentials)
	return manifestsdk.CredentialApplicationWrapper{
		CredentialApplication: createApplication,
		Credentials:           creds,
	}
}
