package router

import (
	"context"
	"testing"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	manifestsdk "github.com/TBD54566975/ssi-sdk/credential/manifest"
	"github.com/TBD54566975/ssi-sdk/crypto"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/key"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/tbd54566975/ssi-service/pkg/service/manifest/model"
	"github.com/tbd54566975/ssi-service/pkg/service/operation/storage"

	credmodel "github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/pkg/service/credential"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
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
		assert.NotNil(tt, bolt)

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credentialService := testCredentialService(tt, bolt, keyStoreService, didService, schemaService)
		manifestService := testManifestService(tt, bolt, keyStoreService, didService, credentialService)
		assert.NotEmpty(tt, manifestService)

		// check type and status
		assert.Equal(tt, framework.Manifest, manifestService.Type())
		assert.Equal(tt, framework.StatusReady, manifestService.Status().Status)

		// create issuer and applicant DIDs
		createDIDRequest := did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		}
		issuerDID, err := didService.CreateDIDByMethod(context.Background(), createDIDRequest)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		applicantPrivKey, applicantDIDKey, err := key.GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, applicantPrivKey)
		assert.NotEmpty(tt, applicantDIDKey)

		applicantDID, err := applicantDIDKey.Expand()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, applicantDID)

		// create a schema for the creds to be issued against
		licenseSchema := map[string]any{
			"type": "object",
			"properties": map[string]any{
				"licenseType": map[string]any{
					"type": "string",
				},
			},
			"additionalProperties": true,
		}
		kid := issuerDID.DID.VerificationMethod[0].ID
		createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Author: issuerDID.DID.ID, AuthorKID: kid, Name: "license schema", Schema: licenseSchema, Sign: true})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdSchema)

		// issue a credential against the schema to the subject, from the issuer
		createdCred, err := credentialService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
			Issuer:    issuerDID.DID.ID,
			IssuerKID: kid,
			Subject:   applicantDID.ID,
			SchemaID:  createdSchema.ID,
			Data:      map[string]any{"licenseType": "WA-DL-CLASS-A"},
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdCred)

		// good manifest request, which asks for a single verifiable credential in the VC-JWT format
		createManifestRequest := getValidManifestRequest(issuerDID.DID.ID, kid, createdSchema.ID)
		createdManifest, err := manifestService.CreateManifest(context.Background(), createManifestRequest)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdManifest)

		verificationResponse, err := manifestService.VerifyManifest(context.Background(), model.VerifyManifestRequest{ManifestJWT: createdManifest.ManifestJWT})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, verificationResponse)
		assert.True(tt, verificationResponse.Verified)

		m := createdManifest.Manifest
		assert.NotEmpty(tt, m)

		// good application request
		containers := []credmodel.Container{{
			ID:            createdCred.ID,
			CredentialJWT: createdCred.CredentialJWT,
		}}
		applicationRequest := getValidApplicationRequest(m.ID, m.PresentationDefinition.ID, m.PresentationDefinition.InputDescriptors[0].ID, containers)

		// sign application
		signer, err := keyaccess.NewJWKKeyAccess(applicantDID.ID, applicantDID.VerificationMethod[0].ID, applicantPrivKey)
		assert.NoError(tt, err)
		signed, err := signer.SignJSON(applicationRequest)
		assert.NoError(tt, err)

		submitApplicationRequest := SubmitApplicationRequest{ApplicationJWT: *signed}
		sar, err := submitApplicationRequest.toServiceRequest()
		assert.NoError(tt, err)
		createdApplicationResponseOp, err := manifestService.ProcessApplicationSubmission(context.Background(), *sar)
		assert.NoError(tt, err)
		assert.False(tt, createdApplicationResponseOp.Done)

		createdApplicationResponse, err := manifestService.ReviewApplication(context.Background(), model.ReviewApplicationRequest{
			ID:       storage.StatusObjectID(createdApplicationResponseOp.ID),
			Approved: true,
			Reason:   "ApprovalMan is here",
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdManifest)
		assert.NotEmpty(tt, createdApplicationResponse.Response.ID)
		assert.NotEmpty(tt, createdApplicationResponse.Response.Fulfillment)
		assert.Empty(tt, createdApplicationResponse.Response.Denial)
		assert.Equal(tt, len(createManifestRequest.OutputDescriptors), len(createdApplicationResponse.Credentials))
	})
}

// getValidManifestRequest returns a valid manifest request, expecting a single JWT-VC EdDSA credential
func getValidManifestRequest(issuerDID, issuerKID, schemaID string) model.CreateManifestRequest {
	createManifestRequest := model.CreateManifestRequest{
		IssuerDID: issuerDID,
		IssuerKID: issuerKID,
		ClaimFormat: &exchange.ClaimFormat{
			JWTVC: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
		},
		PresentationDefinition: &exchange.PresentationDefinition{
			ID: "id123",
			InputDescriptors: []exchange.InputDescriptor{
				{
					ID: "test-id",
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
