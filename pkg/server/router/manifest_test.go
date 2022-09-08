package router

import (
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

		pathArray := []string{"path1"}
		fieldsArray := []map[string]interface{}{}
		fieldsArray = append(fieldsArray, map[string]interface{}{"path": pathArray})
		constraintsObj := map[string]interface{}{"fields": fieldsArray}

		// good request
		createManifestRequest := manifest.CreateManifestRequest{
			Issuer:  "did:abc:123",
			Context: "context123",
			PresentationDefinition: map[string]interface{}{
				"id":                "test",
				"input_descriptors": []map[string]interface{}{constraintsObj},
			},
			OutputDescriptors: []map[string]interface{}{
				{
					"id":          "od1",
					"schema":      "https://test.com/schema",
					"name":        "good ID",
					"description": "it's all good",
				},
				{
					"id":          "od2",
					"schema":      "https://test.com/schema",
					"name":        "good ID",
					"description": "it's all good",
				},
			},
		}

		createdManifest, err := manifestService.CreateManifest(createManifestRequest)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdManifest)
		assert.NotEmpty(tt, createdManifest.Manifest)
	})
}
