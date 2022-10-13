package router

import (
	"os"
	"testing"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	manifestsdk "github.com/TBD54566975/ssi-sdk/credential/manifest"
	"github.com/TBD54566975/ssi-sdk/crypto"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/tbd54566975/ssi-service/config"
	credmodel "github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/pkg/service/credential"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/manifest"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

func TestManifestRouter(t *testing.T) {
	// remove the db file after the test
	t.Cleanup(func() {
		_ = os.Remove(storage.DBFile)
	})

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
		bolt, err := storage.NewBoltDB()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, bolt)

		serviceConfig := config.ManifestServiceConfig{BaseServiceConfig: &config.BaseServiceConfig{Name: "manifest"}}
		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credentialService := testCredentialService(tt, bolt, keyStoreService, didService, schemaService)
		manifestService, err := manifest.NewManifestService(serviceConfig, bolt, keyStoreService, credentialService)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, manifestService)

		// check type and status
		assert.Equal(tt, framework.Manifest, manifestService.Type())
		assert.Equal(tt, framework.StatusReady, manifestService.Status().Status)

		// create issuer and applicant DIDs
		createDIDRequest := did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		}
		issuerDID, err := didService.CreateDIDByMethod(createDIDRequest)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		applicantDID, err := didService.CreateDIDByMethod(createDIDRequest)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, applicantDID)

		// create a schema for the creds to be issued against
		licenseSchema := map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"licenseType": map[string]interface{}{
					"type": "string",
				},
			},
			"additionalProperties": true,
		}
		createdSchema, err := schemaService.CreateSchema(schema.CreateSchemaRequest{Author: issuerDID.DID.ID, Name: "license schema", Schema: licenseSchema, Sign: true})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdSchema)

		// issue a credential against the schema to the subject, from the issuer
		createdCred, err := credentialService.CreateCredential(credential.CreateCredentialRequest{
			Issuer:     issuerDID.DID.ID,
			Subject:    applicantDID.DID.ID,
			JSONSchema: createdSchema.ID,
			Data:       map[string]interface{}{"licenseType": "WA-DL-CLASS-A"},
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdCred)

		// good manifest request, which asks for a single verifiable credential in the VC-JWT format
		createManifestRequest := getValidManifestRequest(issuerDID.DID.ID, createdSchema.ID)

		createdManifest, err := manifestService.CreateManifest(createManifestRequest)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdManifest)

		m := createdManifest.Manifest
		assert.NotEmpty(tt, m)

		// good application request
		containers := []credmodel.Container{{
			ID:            createdCred.ID,
			CredentialJWT: createdCred.CredentialJWT,
		}}
		createApplicationRequest := getValidApplicationRequest(applicantDID.DID.ID, m.ID, m.PresentationDefinition.ID,
			m.PresentationDefinition.InputDescriptors[0].ID, containers)

		createdApplicationResponse, err := manifestService.ProcessApplicationSubmission(createApplicationRequest)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdManifest)
		assert.NotEmpty(tt, createdApplicationResponse.Response.ID)
		assert.Equal(tt, len(createManifestRequest.Manifest.OutputDescriptors), len(createdApplicationResponse.Credential))
	})
}

// getValidManifestRequest returns a valid manifest request, expecting a single JWT-VC EdDSA credential
func getValidManifestRequest(issuerDID, schemaID string) manifest.CreateManifestRequest {
	createManifestRequest := manifest.CreateManifestRequest{
		Manifest: manifestsdk.CredentialManifest{
			ID:          "WA-DL-CLASS-A",
			SpecVersion: manifestsdk.SpecVersion,
			Issuer: manifestsdk.Issuer{
				ID: issuerDID,
			},
			PresentationDefinition: &exchange.PresentationDefinition{
				ID: "id123",
				InputDescriptors: []exchange.InputDescriptor{
					{
						ID: "test-id",
						Constraints: &exchange.Constraints{
							Fields: []exchange.Field{
								{
									Path: []string{".verifiableCredential.id"},
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
		},
	}

	return createManifestRequest
}

func getValidApplicationRequest(applicantDID, manifestID, presDefID, submissionDescriptorID string, credentials []credmodel.Container) manifest.SubmitApplicationRequest {
	createApplication := manifestsdk.CredentialApplication{
		ID:          uuid.New().String(),
		SpecVersion: manifestsdk.SpecVersion,
		ManifestID:  manifestID,
		Format: &exchange.ClaimFormat{
			JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
		},
		PresentationSubmission: &exchange.PresentationSubmission{
			ID:           "psid",
			DefinitionID: presDefID,
			DescriptorMap: []exchange.SubmissionDescriptor{
				{
					ID:     submissionDescriptorID,
					Format: exchange.JWTVC.String(),
					Path:   "$.verifiableCredential[0]",
				},
			},
		},
	}

	// TODO(gabe) sign the request
	return manifest.SubmitApplicationRequest{
		ApplicantDID: applicantDID,
		Application:  createApplication,
		Credentials:  credentials,
	}
}
