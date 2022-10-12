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
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/manifest"
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
		testCredentialService := testCredentialService(tt, bolt, keyStoreService, didService)
		manifestService, err := manifest.NewManifestService(serviceConfig, bolt, keyStoreService, testCredentialService)
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

		// good manifest request
		createManifestRequest := getValidManifestRequest(issuerDID.DID.ID)

		createdManifest, err := manifestService.CreateManifest(createManifestRequest)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdManifest)
		assert.NotEmpty(tt, createdManifest.Manifest)

		// good application request
		createApplicationRequest := getValidApplicationRequest(applicantDID.DID.ID, createdManifest.Manifest.ID, createManifestRequest.Manifest.PresentationDefinition.InputDescriptors[0].ID)

		createdApplicationResponse, err := manifestService.ProcessApplicationSubmission(createApplicationRequest)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdManifest)
		assert.NotEmpty(tt, createdApplicationResponse.Response.ID)
		assert.Equal(tt, len(createManifestRequest.Manifest.OutputDescriptors), len(createdApplicationResponse.Credential))
	})
}

func getValidManifestRequest(issuerDID string) manifest.CreateManifestRequest {
	createManifestRequest := manifest.CreateManifestRequest{
		Manifest: manifestsdk.CredentialManifest{
			ID:          "WA-DL-CLASS-A",
			SpecVersion: "https://identity.foundation/credential-manifest/spec/v1.0.0/",
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
									Path: []string{".vc.id"},
								},
							},
						},
					},
				},
			},
			OutputDescriptors: []manifestsdk.OutputDescriptor{
				{
					ID:          "id1",
					Schema:      "https://test.com/schema",
					Name:        "good ID",
					Description: "it's all good",
				},
				{
					ID:          "id2",
					Schema:      "https://test.com/schema",
					Name:        "good ID",
					Description: "it's all good",
				},
			},
		},
	}

	return createManifestRequest
}

func getValidApplicationRequest(applicantDID, manifestID, submissionDescriptorID string) manifest.SubmitApplicationRequest {
	createApplication := manifestsdk.CredentialApplication{
		ID:          uuid.New().String(),
		SpecVersion: "https://identity.foundation/credential-manifest/spec/v1.0.0/",
		ManifestID:  manifestID,
		Format: &exchange.ClaimFormat{
			JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
		},
		PresentationSubmission: &exchange.PresentationSubmission{
			ID:           "psid",
			DefinitionID: "id123",
			DescriptorMap: []exchange.SubmissionDescriptor{
				{
					ID:     submissionDescriptorID,
					Format: "jwt",
					Path:   "$.verifiableCredential[0]",
				},
			},
		},
	}

	createApplicationRequest := manifest.SubmitApplicationRequest{
		Application:  createApplication,
		ApplicantDID: applicantDID,
	}

	return createApplicationRequest
}
