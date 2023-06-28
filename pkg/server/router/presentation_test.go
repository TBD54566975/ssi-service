package router

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/crypto"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/pkg/service/common"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/presentation"
	"github.com/tbd54566975/ssi-service/pkg/service/presentation/model"
	"github.com/tbd54566975/ssi-service/pkg/testutil"
)

func TestPresentationDefinitionRouter(t *testing.T) {
	t.Run("Nil Service", func(tt *testing.T) {
		pdRouter, err := NewPresentationRouter(nil)
		assert.Error(tt, err)
		assert.Empty(tt, pdRouter)
		assert.Contains(tt, err.Error(), "service cannot be nil")
	})

	t.Run("Bad Service", func(tt *testing.T) {
		pdRouter, err := NewPresentationRouter(&testService{})
		assert.Error(tt, err)
		assert.Empty(tt, pdRouter)
		assert.Contains(tt, err.Error(), "could not create presentation router with service type: test")
	})
}

var (
	SampleExpirationTime = time.Date(2023, 10, 10, 10, 10, 10, 0, time.UTC)
	In30Seconds          = time.Now().Add(30 * time.Second)
	In100Seconds         = time.Now().Add(100 * time.Second)
)

func TestPresentationDefinitionService(t *testing.T) {
	for _, test := range testutil.TestDatabases {
		t.Run(test.Name, func(t *testing.T) {
			s := test.ServiceStorage(t)
			assert.NotEmpty(t, s)

			keyStoreService := testKeyStoreService(t, s)
			didService := testDIDService(t, s, keyStoreService)
			schemaService := testSchemaService(t, s, keyStoreService, didService)
			authorDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
				Method:  didsdk.KeyMethod,
				KeyType: crypto.Ed25519,
			})
			require.NoError(t, err)
			pubKeyJWK := authorDID.DID.VerificationMethod[0].PublicKeyJWK
			require.NotEmpty(t, pubKeyJWK)
			pubKey, err := pubKeyJWK.ToPublicKey()
			require.NoError(t, err)
			ka, err := keyaccess.NewJWKKeyAccessVerifier(authorDID.DID.ID, authorDID.DID.ID, pubKey)
			require.NoError(t, err)

			service, err := presentation.NewPresentationService(config.PresentationServiceConfig{}, s, didService.GetResolver(), schemaService, keyStoreService)
			require.NoError(t, err)

			t.Run("Create returns the created definition", func(t *testing.T) {
				pd := createPresentationDefinition(t)
				created, err := service.CreatePresentationDefinition(context.Background(), model.CreatePresentationDefinitionRequest{
					PresentationDefinition: *pd,
				})

				assert.NoError(t, err)
				assert.Equal(t, pd, &created.PresentationDefinition)
			})

			t.Run("Get returns the created definition", func(t *testing.T) {
				pd := createPresentationDefinition(t)
				_, err := service.CreatePresentationDefinition(context.Background(), model.CreatePresentationDefinitionRequest{
					PresentationDefinition: *pd,
				})
				assert.NoError(t, err)

				getPd, err := service.GetPresentationDefinition(context.Background(), model.GetPresentationDefinitionRequest{ID: pd.ID})

				assert.NoError(t, err)
				assert.Equal(t, pd.ID, getPd.PresentationDefinition.ID)
				assert.Equal(t, pd, &getPd.PresentationDefinition)
			})

			t.Run("Get does not return after deletion", func(t *testing.T) {
				pd := createPresentationDefinition(t)
				_, err := service.CreatePresentationDefinition(context.Background(), model.CreatePresentationDefinitionRequest{
					PresentationDefinition: *pd,
				})
				assert.NoError(t, err)

				assert.NoError(t, service.DeletePresentationDefinition(context.Background(), model.DeletePresentationDefinitionRequest{ID: pd.ID}))

				_, err = service.GetPresentationDefinition(context.Background(), model.GetPresentationDefinitionRequest{ID: pd.ID})
				assert.Error(t, err)
			})

			t.Run("Delete can be called with any ID", func(t *testing.T) {
				err := service.DeletePresentationDefinition(context.Background(), model.DeletePresentationDefinitionRequest{ID: "some crazy ID"})
				assert.NoError(t, err)
			})

			t.Run("Signed request is return when creating request", func(t *testing.T) {
				pd := createPresentationDefinition(t)
				_, err := service.CreatePresentationDefinition(context.Background(), model.CreatePresentationDefinitionRequest{
					PresentationDefinition: *pd,
				})
				assert.NoError(t, err)
				expectedReq := model.Request{
					Request: common.Request{
						Audience:   []string{"did:web:heman"},
						IssuerDID:  authorDID.DID.ID,
						IssuerKID:  authorDID.DID.VerificationMethod[0].ID,
						Expiration: &SampleExpirationTime,
					},
					PresentationDefinitionID: pd.ID,
				}
				req, err := service.CreateRequest(context.Background(), model.CreateRequestRequest{
					PresentationRequest: expectedReq,
				})

				assert.NoError(t, err)
				assert.NotEmpty(t, req.ID)
				assert.NotEqual(t, req.ID, pd.ID)
				assert.NoError(t, ka.Verify(req.PresentationDefinitionJWT))
				payload, err := base64.RawURLEncoding.DecodeString(strings.Split(req.PresentationDefinitionJWT.String(), ".")[1])
				assert.NoError(t, err)
				var got exchange.PresentationDefinitionEnvelope
				assert.NoError(t, json.Unmarshal(payload, &got))
				assert.Equal(t, *pd, got.PresentationDefinition)
				assert.Equal(t, expectedReq.Audience, req.Audience)
				assert.Equal(t, expectedReq.IssuerDID, req.IssuerDID)
				assert.Equal(t, expectedReq.IssuerKID, req.IssuerKID)
				assert.Equal(t, expectedReq.PresentationDefinitionID, req.PresentationDefinitionID)
				assert.Equal(t, expectedReq.Expiration, req.Expiration)
			})

			t.Run("Get request returns the created request", func(t *testing.T) {
				pd := createPresentationDefinition(t)
				_, err := service.CreatePresentationDefinition(context.Background(), model.CreatePresentationDefinitionRequest{
					PresentationDefinition: *pd,
				})
				assert.NoError(t, err)
				req, err := service.CreateRequest(context.Background(), model.CreateRequestRequest{
					PresentationRequest: model.Request{
						Request: common.Request{
							Audience:   []string{"did:web:heman"},
							IssuerDID:  authorDID.DID.ID,
							IssuerKID:  authorDID.DID.VerificationMethod[0].ID,
							Expiration: &In30Seconds,
						},
						PresentationDefinitionID: pd.ID,
					},
				})
				assert.NoError(t, err)

				got, err := service.GetRequest(context.Background(), &model.GetRequestRequest{ID: req.ID})
				assert.NoError(t, err)
				assert.Equal(t, req, got)
			})

			t.Run("Returns not found after deleting request", func(t *testing.T) {
				pd := createPresentationDefinition(t)
				_, err := service.CreatePresentationDefinition(context.Background(), model.CreatePresentationDefinitionRequest{
					PresentationDefinition: *pd,
				})
				assert.NoError(t, err)
				req, err := service.CreateRequest(context.Background(), model.CreateRequestRequest{
					PresentationRequest: model.Request{
						Request: common.Request{
							IssuerDID:  authorDID.DID.ID,
							IssuerKID:  authorDID.DID.VerificationMethod[0].ID,
							Expiration: &In30Seconds,
						},
						PresentationDefinitionID: pd.ID,
					},
				})
				assert.NoError(t, err)

				err = service.DeleteRequest(context.Background(), model.DeleteRequestRequest{ID: req.ID})
				assert.NoError(t, err)

				_, err = service.GetRequest(context.Background(), &model.GetRequestRequest{ID: req.ID})
				assert.Error(t, err)
				assert.ErrorContains(t, err, "request not found")
			})

			t.Run("Error returned when missing required fields", func(t *testing.T) {
				_, err := service.CreateRequest(context.Background(), model.CreateRequestRequest{
					PresentationRequest: model.Request{
						Request: common.Request{
							IssuerDID: "issuer id",
							IssuerKID: "kid",
						},
					},
				})
				assert.Error(t, err)
				assert.ErrorContains(t, err, "failed on the 'required' tag")

				_, err = service.CreateRequest(context.Background(), model.CreateRequestRequest{
					PresentationRequest: model.Request{
						Request: common.Request{
							IssuerDID: "issuer id",
						},
						PresentationDefinitionID: "something",
					},
				})
				assert.Error(t, err)
				assert.ErrorContains(t, err, "failed on the 'required' tag")

				_, err = service.CreateRequest(context.Background(), model.CreateRequestRequest{
					PresentationRequest: model.Request{
						Request: common.Request{
							IssuerKID: "kid",
						},
						PresentationDefinitionID: "something",
					},
				})
				assert.Error(t, err)
				assert.ErrorContains(t, err, "failed on the 'required' tag")
			})
		})
	}
}

func createPresentationDefinition(t *testing.T) *exchange.PresentationDefinition {
	builder := exchange.NewPresentationDefinitionBuilder()
	assert.NoError(t, builder.SetInputDescriptors([]exchange.InputDescriptor{
		{
			ID:      "id",
			Name:    "name",
			Purpose: "purpose",
			Format: &exchange.ClaimFormat{
				JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
			},
			Constraints: &exchange.Constraints{SubjectIsIssuer: exchange.Preferred.Ptr()},
		},
	}))
	pd, err := builder.Build()
	assert.NoError(t, err)
	return pd
}
