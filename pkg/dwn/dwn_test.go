package dwn

import (
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	manifestsdk "github.com/TBD54566975/ssi-sdk/credential/manifest"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPublishManifest(t *testing.T) {
	t.Run("Test Publish Manifest", func(tt *testing.T) {

		resp, err := PublishManifest("test-endpoint", getValidManifest())
		assert.Nil(tt, resp)
		assert.Error(tt, err)
		assert.ErrorContains(tt, err, "problem with posting to dwn")
	})
}

func getValidManifest() manifestsdk.CredentialManifest {

	return manifestsdk.CredentialManifest{
		ID:          "WA-DL-CLASS-A",
		SpecVersion: "https://identity.foundation/credential-manifest/spec/v1.0.0/",
		Issuer: manifestsdk.Issuer{
			ID: "did:abc:123",
		},
		PresentationDefinition: &exchange.PresentationDefinition{
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
}
