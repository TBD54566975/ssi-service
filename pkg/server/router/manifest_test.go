package router

import (
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	manifestsdk "github.com/TBD54566975/ssi-sdk/credential/manifest"
	"github.com/stretchr/testify/assert"
	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/manifest"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"os"
	"testing"
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
		manifestService, err := manifest.NewManifestService(serviceConfig, bolt)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, manifestService)

		// check type and status
		assert.Equal(tt, framework.Manifest, manifestService.Type())
		assert.Equal(tt, framework.StatusReady, manifestService.Status().Status)

		// good manifest request
		createManifestRequest := getValidManifestRequest()

		createdManifest, err := manifestService.CreateManifest(createManifestRequest)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdManifest)
		assert.NotEmpty(tt, createdManifest.Manifest)

		// good application request
		createApplicationRequest := getValidApplicationRequest(createdManifest.Manifest.ID, createManifestRequest.PresentationDefinition.InputDescriptors[0].ID)

		createdApplication, err := manifestService.SubmitApplication(createApplicationRequest)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdManifest)
		assert.NotEmpty(tt, createdApplication.Response.ID)
	})

}

func getValidManifestRequest() manifest.CreateManifestRequest {
	createManifestRequest := manifest.CreateManifestRequest{
		Issuer:  "did:abc:123",
		Context: "context123",
		PresentationDefinition: exchange.PresentationDefinition{
			ID: "pres-def-id",
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
	}

	return createManifestRequest
}

func getValidApplicationRequest(manifestId string, submissionDescriptorId string) manifest.SubmitApplicationRequest {

	createApplicationRequest := manifest.SubmitApplicationRequest{

		ManifestID:   manifestId,
		RequesterDID: "did:user:123",
		PresentationSubmission: exchange.PresentationSubmission{
			ID:           "psid",
			DefinitionID: "definitionId",
			DescriptorMap: []exchange.SubmissionDescriptor{
				{
					ID:     submissionDescriptorId,
					Format: "jwt",
					Path:   "path",
				},
			},
		},
	}

	return createApplicationRequest
}
