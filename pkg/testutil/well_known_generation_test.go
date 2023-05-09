package testutil

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	credsdk "github.com/TBD54566975/ssi-sdk/credential"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

func TestWellKnownGenerationTest(t *testing.T) {

	t.Run("Credential .WellKnown Credential Test", func(tt *testing.T) {
		// To generate a well known config remove this line
		if true {
			tt.Skip("skipping wellknown test")
		}

		origin := "https://www.tbd.website/"
		bolt := setupTestDB(tt)
		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)

		didKey, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{Method: "key", KeyType: "Ed25519"})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, didKey)

		gotKey, err := keyStoreService.GetKey(context.Background(), keystore.GetKeyRequest{ID: didKey.DID.ID})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gotKey)

		createWellKnownDIDConfiguration(tt, didKey, gotKey, origin)

		createOpts := did.CreateWebDIDOptions{DIDWebID: "did:web:tbd.website"}
		didWeb, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{Method: "web", KeyType: "Ed25519", Options: createOpts})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, didWeb)

		gotDidWebKey, err := keyStoreService.GetKey(context.Background(), keystore.GetKeyRequest{ID: didWeb.DID.ID})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gotDidWebKey)

		createWellKnownDIDConfiguration(tt, didWeb, gotDidWebKey, origin)

	})
}

func createWellKnownDIDConfiguration(tt *testing.T, didResponse *did.CreateDIDResponse, gotKey *keystore.GetKeyResponse, origin string) {
	builder := credsdk.NewVerifiableCredentialBuilder()

	err := builder.SetIssuer(didResponse.DID.ID)
	assert.NoError(tt, err)

	subjectData := map[string]interface{}{
		"id":     didResponse.DID.ID,
		"origin": origin,
	}

	subject := credsdk.CredentialSubject(subjectData)
	err = builder.SetCredentialSubject(subject)
	assert.NoError(tt, err)

	err = builder.AddContext("https://tbd.website/.well-known/did-configuration/v1")
	assert.NoError(tt, err)

	err = builder.SetExpirationDate("2051-10-05T14:48:00.000Z")
	assert.NoError(tt, err)

	err = builder.SetIssuanceDate(time.Now().Format(time.RFC3339))
	assert.NoError(tt, err)

	err = builder.AddType("DomainLinkageCredential")
	assert.NoError(tt, err)

	err = builder.SetID("")
	assert.NoError(tt, err)

	cred, err := builder.Build()
	assert.NoError(tt, err)

	keyAccess, err := keyaccess.NewJWKKeyAccess(gotKey.Controller, gotKey.ID, gotKey.Key)
	assert.NoError(tt, err)

	jwtToken := jwt.New()

	expirationVal := cred.ExpirationDate
	if expirationVal != "" {
		var expirationDate string
		unixTime, err := rfc3339ToUnix(expirationVal)
		assert.NoError(tt, err)
		expirationDate = string(unixTime)
		err = jwtToken.Set(jwt.ExpirationKey, expirationDate)
		assert.NoError(tt, err)
	}

	err = jwtToken.Set(jwt.IssuerKey, cred.Issuer)
	assert.NoError(tt, err)

	var issuanceDate string
	if unixTime, err := rfc3339ToUnix(cred.IssuanceDate); err == nil {
		issuanceDate = string(unixTime)
	} else {
		// could not convert iat to unix time; setting to present moment
		issuanceDate = strconv.FormatInt(time.Now().UTC().UnixNano(), 10)
	}

	err = jwtToken.Set(jwt.NotBeforeKey, issuanceDate)
	assert.NoError(tt, err)

	subVal := cred.CredentialSubject.GetID()
	if subVal != "" {
		err = jwtToken.Set(jwt.SubjectKey, subVal)
		assert.NoError(tt, err)
	}

	VCJWTProperty := "vc"
	err = jwtToken.Set(VCJWTProperty, cred)
	assert.NoError(tt, err)

	// TODO: Remove typ header
	// option := jwt.WithJwsHeaders()
	signedTokenBytes, err := jwt.Sign(jwtToken, jwa.SignatureAlgorithm(keyAccess.JWTSigner.GetSigningAlgorithm()), keyAccess.JWTSigner.Key)
	assert.NoError(tt, err)

	credToken := keyaccess.JWT(signedTokenBytes).Ptr()

	wellKnown := map[string]interface{}{
		"@context":    "https://tbd.website/.well-known/did-configuration/v1",
		"linked_dids": []string{credToken.String()},
	}

	jsonStr, _ := json.Marshal(wellKnown)

	fmt.Println("Created Well Known Output for DID:")
	fmt.Println(didResponse.DID.ID)

	fmt.Println("Well Known Config:")
	fmt.Println(string(jsonStr))
}

func testKeyStoreService(t *testing.T, db storage.ServiceStorage) *keystore.Service {
	serviceConfig := config.KeyStoreServiceConfig{ServiceKeyPassword: "test-password"}
	// create a keystore service
	keystoreService, err := keystore.NewKeyStoreService(serviceConfig, db)
	require.NoError(t, err)
	require.NotEmpty(t, keystoreService)
	return keystoreService
}

func testDIDService(t *testing.T, db storage.ServiceStorage, keyStore *keystore.Service) *did.Service {
	serviceConfig := config.DIDServiceConfig{
		BaseServiceConfig: &config.BaseServiceConfig{
			Name: "did",
		},
		Methods:                []string{"key", "web"},
		LocalResolutionMethods: []string{"key"},
	}
	// create a did service
	didService, err := did.NewDIDService(serviceConfig, db, keyStore)
	require.NoError(t, err)
	require.NotEmpty(t, didService)
	return didService
}

func setupTestDB(t *testing.T) storage.ServiceStorage {
	file, err := os.CreateTemp("", "bolt")
	require.NoError(t, err)
	name := file.Name()
	err = file.Close()
	require.NoError(t, err)
	s, err := storage.NewStorage(storage.Bolt, storage.Option{
		ID:     storage.BoltDBFilePathOption,
		Option: name,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = s.Close()
		_ = os.Remove(s.URI())
	})
	return s
}

// according to the spec the JWT timestamp must be a `NumericDate` property, which is a JSON Unix timestamp value.
// https://www.w3.org/TR/vc-data-model/#json-web-token
// https://datatracker.ietf.org/doc/html/rfc7519#section-2
func rfc3339ToUnix(timestamp string) ([]byte, error) {
	t, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return nil, err
	}
	unixTimestampInt := strconv.FormatInt(t.Unix(), 10)
	return []byte(unixTimestampInt), nil
}
