package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TBD54566975/ssi-sdk/crypto"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/oidc/issuance"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/require"
	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/service/credential"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/oidc"
	"github.com/tbd54566975/ssi-service/pkg/service/oidc/model"
)

func TestAuthService_CredentialEndpoint(t *testing.T) {
	bolt := setupTestDB(t)
	keyStoreService := testKeyStoreService(t, bolt)
	didService := testDIDService(t, bolt, keyStoreService)
	schemaService := testSchemaService(t, bolt, keyStoreService, didService)
	credService := testCredentialService(t, bolt, keyStoreService, didService, schemaService)
	oidcRouter, err := router.NewOIDCCredentialRouter(oidc.NewOIDCService(
		didService.GetResolver(),
		credService,
		[32]byte{
			0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
			0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		oidc.WithCNonceExpiresIn(1*time.Second),
	))
	require.NoError(t, err)

	issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
		Method:  didsdk.KeyMethod,
		KeyType: crypto.Ed25519,
	})
	require.NoError(t, err)
	require.NotEmpty(t, issuerDID)

	// Testing is easier when it's deterministic, so we use the following DID, which is associated with the JWK below it.
	// did:key:z4oJ8ceBqavcJf8ay4ZL1p6RB1NpZ7UkiqMzTAXXfd7hzCrezhU2spYik49RKtL12QgAYmJfT7AqFGMZqMyHW7geqejjD
	// {"crv":"P-256","d":"2CG0StfWMvHHR0Su02Gc1e61nxLAOgTeIWwcipA8MlE","kty":"EC","x":"jys8wRkYPAqSaMo6bf5LKQCF9_Ji7RUVTwLy7Oj3V1M","y":"Kc8Yb2dQ_5xsaBtjSAjW9Tfk7O79go44ECoOYkrBvCA"}
	jwkKey, err := jwk.ParseKey([]byte(`{"crv":"P-256","d":"2CG0StfWMvHHR0Su02Gc1e61nxLAOgTeIWwcipA8MlE","kty":"EC","x":"jys8wRkYPAqSaMo6bf5LKQCF9_Ji7RUVTwLy7Oj3V1M","y":"Kc8Yb2dQ_5xsaBtjSAjW9Tfk7O79go44ECoOYkrBvCA"}`))
	require.NoError(t, err)
	var privateKey any
	err = jwkKey.Raw(&privateKey)
	require.NoError(t, err)
	didKey := didsdk.DIDKey("did:key:z4oJ8ceBqavcJf8ay4ZL1p6RB1NpZ7UkiqMzTAXXfd7hzCrezhU2spYik49RKtL12QgAYmJfT7AqFGMZqMyHW7geqejjD")

	_, err = credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
		Issuer:  issuerDID.DID.ID,
		Subject: didKey.String(),
		Data: map[string]any{
			"firstName": "Jack",
			"lastName":  "Dorsey",
		},
		Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	})
	require.NoError(t, err)

	hdrs := jws.NewHeaders()
	require.NoError(t, hdrs.Set(jws.TypeKey, "openid4vci-proof+jwt"))
	require.NoError(t, hdrs.Set(jws.KeyIDKey, didKey.String()))

	token := jwt.New()
	require.NoError(t, token.Set(jwt.IssuerKey, didKey.String()))
	require.NoError(t, token.Set(jwt.AudienceKey, "the credential issuer url"))
	require.NoError(t, token.Set(jwt.IssuedAtKey, 1616689547))
	require.NoError(t, token.Set("nonce", "c_nonce from the issuer"))

	tokenData, err := json.Marshal(token)
	require.NoError(t, err)

	data, err := jws.Sign(tokenData, jws.WithKey(jwa.ES256, privateKey, jws.WithProtectedHeaders(hdrs)))
	require.NoError(t, err)
	req := httptest.NewRequest(
		http.MethodPost,
		"https://ssi-service.com/v1/oidc/credentials",
		strings.NewReader(`{
	 "format": "jwt_vc_json",
	 "types": [
	   "VerifiableCredential"
	 ],
	 "credentialSubject": {
	   "given_name": {},
	   "last_name": {},
	   "degree": {}
	 },
	 "proof": {
	   "proof_type": "jwt",
	   "jwt":"`+string(data)+`"
	 }
	}`))
	w := httptest.NewRecorder()

	err = oidcRouter.IssueCredential(newRequestContext(), w, req)
	require.NoError(t, err)

	// On the first try, we expect an error with the c_nonce to use
	var errorResp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&errorResp))
	require.Equal(t, "invalid_or_missing_proof", errorResp["error"].(string))
	require.NotEmpty(t, errorResp["c_nonce"])

	// Now do it all over
	require.NoError(t, token.Set("nonce", errorResp["c_nonce"].(string)))

	tokenData, err = json.Marshal(token)
	require.NoError(t, err)

	data, err = jws.Sign(tokenData, jws.WithKey(jwa.ES256, privateKey, jws.WithProtectedHeaders(hdrs)))
	require.NoError(t, err)

	req = httptest.NewRequest(
		http.MethodPost,
		"https://ssi-service.com/v1/oidc/credentials",
		strings.NewReader(`{
	 "format": "jwt_vc_json",
	 "types": [
	   "VerifiableCredential"
	 ],
	 "credentialSubject": {
	   "given_name": {},
	   "last_name": {},
	   "degree": {}
	 },
	 "proof": {
	   "proof_type": "jwt",
	   "jwt":"`+string(data)+`"
	 }
	}`))

	err = oidcRouter.IssueCredential(newRequestContext(), w, req)
	require.NoError(t, err)

	var credentialResponse model.CredentialResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&credentialResponse))

	require.Equal(t, string(issuance.JWTVCJSON), credentialResponse.Format)
	require.NotEmpty(t, credentialResponse.Credential)
	require.NotEmpty(t, credentialResponse.CNonce)
	require.Equal(t, 120, credentialResponse.CNonceExpiresIn)

	// And do it again, but after the expiration time. We should now expect an error
	<-time.After(time.Duration(int64(errorResp["c_nonce_expires_in"].(float64)) * int64(time.Second)))
	req = httptest.NewRequest(
		http.MethodPost,
		"https://ssi-service.com/v1/oidc/credentials",
		strings.NewReader(`{
	 "format": "jwt_vc_json",
	 "types": [
	   "VerifiableCredential"
	 ],
	 "credentialSubject": {
	   "given_name": {},
	   "last_name": {},
	   "degree": {}
	 },
	 "proof": {
	   "proof_type": "jwt",
	   "jwt":"`+string(data)+`"
	 }
	}`))
	err = oidcRouter.IssueCredential(newRequestContext(), w, req)
	require.NoError(t, err)

	var errResp2 map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&errResp2))
	require.Equal(t, "invalid_or_missing_proof", errResp2["error"].(string))
	require.NotEmpty(t, errResp2["c_nonce"])
	require.NotEqual(t, errorResp["c_nonce"], errResp2["c_nonce"])
}

func TestAuthService_CredentialEndpoint_ErrorResponses(t *testing.T) {
	bolt := setupTestDB(t)
	keyStoreService := testKeyStoreService(t, bolt)
	didService := testDIDService(t, bolt, keyStoreService)
	schemaService := testSchemaService(t, bolt, keyStoreService, didService)
	credService := testCredentialService(t, bolt, keyStoreService, didService, schemaService)
	oidcRouter, err := router.NewOIDCCredentialRouter(oidc.NewOIDCService(
		didService.GetResolver(),
		credService,
		[32]byte{
			0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
			0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		oidc.WithCNonceExpiresIn(12345*time.Second),
	))
	require.NoError(t, err)

	jwkKey, err := jwk.ParseKey([]byte(`{"crv":"P-256","d":"2CG0StfWMvHHR0Su02Gc1e61nxLAOgTeIWwcipA8MlE","kty":"EC","x":"jys8wRkYPAqSaMo6bf5LKQCF9_Ji7RUVTwLy7Oj3V1M","y":"Kc8Yb2dQ_5xsaBtjSAjW9Tfk7O79go44ECoOYkrBvCA"}`))
	require.NoError(t, err)
	var privateKey any
	err = jwkKey.Raw(&privateKey)
	require.NoError(t, err)
	didKey := didsdk.DIDKey("did:key:z4oJ8ceBqavcJf8ay4ZL1p6RB1NpZ7UkiqMzTAXXfd7hzCrezhU2spYik49RKtL12QgAYmJfT7AqFGMZqMyHW7geqejjD")

	hdrs := jws.NewHeaders()
	require.NoError(t, hdrs.Set(jws.TypeKey, "openid4vci-proof+jwt"))
	require.NoError(t, hdrs.Set(jws.KeyIDKey, didKey.String()))

	token := jwt.New()
	require.NoError(t, token.Set(jwt.IssuerKey, didKey.String()))
	require.NoError(t, token.Set(jwt.AudienceKey, "the credential issuer url"))
	require.NoError(t, token.Set(jwt.IssuedAtKey, 1616689547))

	tokenData, err := json.Marshal(token)
	require.NoError(t, err)

	data, err := jws.Sign(tokenData, jws.WithKey(jwa.ES256, privateKey, jws.WithProtectedHeaders(hdrs)))
	require.NoError(t, err)

	t.Run("returns invalid_request when missing parameter", func(t *testing.T) {
		req := httptest.NewRequest(
			http.MethodPost,
			"https://ssi-service.com/v1/oidc/credentials",
			strings.NewReader(`{
	 "types": [
	   "VerifiableCredential"
	 ],
	 "credentialSubject": {
	   "given_name": {},
	   "last_name": {},
	   "degree": {}
	 },
	 "proof": {
	   "proof_type": "jwt",
	   "jwt":"`+string(data)+`"
	 }
	}`))
		w := httptest.NewRecorder()
		err = oidcRouter.IssueCredential(newRequestContext(), w, req)
		require.NoError(t, err)

		assertCredentialErrorResponseEquals(t, w, `{"error": "invalid_request"}`)
	})

	t.Run("returns unsupported_credential_format when requested format is not jwt_vc_json", func(t *testing.T) {
		req := httptest.NewRequest(
			http.MethodPost,
			"https://ssi-service.com/v1/oidc/credentials",
			strings.NewReader(`{
	 "format": "my_own_format",
	 "types": [
	   "VerifiableCredential"
	 ],
	 "credentialSubject": {
	   "given_name": {},
	   "last_name": {},
	   "degree": {}
	 },
	 "proof": {
	   "proof_type": "jwt",
	   "jwt":"`+string(data)+`"
	 }
	}`))
		w := httptest.NewRecorder()
		err = oidcRouter.IssueCredential(newRequestContext(), w, req)
		require.NoError(t, err)

		assertCredentialErrorResponseEquals(t, w, `{"error": "unsupported_credential_format"}`)
	})

	t.Run("returns invalid_or_missing_proof with c_nonce when nonce is missing", func(t *testing.T) {
		req := httptest.NewRequest(
			http.MethodPost,
			"https://ssi-service.com/v1/oidc/credentials",
			strings.NewReader(`{
	 "format": "jwt_vc_json",
	 "types": [
	   "VerifiableCredential"
	 ],
	 "credentialSubject": {
	   "given_name": {},
	   "last_name": {},
	   "degree": {}
	 },
	 "proof": {
	   "proof_type": "jwt",
	   "jwt":"`+string(data)+`"
	 }
	}`))
		w := httptest.NewRecorder()
		err = oidcRouter.IssueCredential(newRequestContext(), w, req)
		require.NoError(t, err)

		var resp map[string]any
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		require.Equal(t, "invalid_or_missing_proof", resp["error"].(string))
		require.NotEmpty(t, resp["c_nonce"])
		require.Equal(t, 12345., resp["c_nonce_expires_in"].(float64))
	})

	t.Run("returns invalid_or_missing_proof when proof used nonce different from provided", func(t *testing.T) {
		require.NoError(t, token.Set("nonce", "my fake nonce"))

		tokenData, err := json.Marshal(token)
		require.NoError(t, err)

		data, err := jws.Sign(tokenData, jws.WithKey(jwa.ES256, privateKey, jws.WithProtectedHeaders(hdrs)))
		require.NoError(t, err)

		req := httptest.NewRequest(
			http.MethodPost,
			"https://ssi-service.com/v1/oidc/credentials",
			strings.NewReader(`{
	 "format": "jwt_vc_json",
	 "types": [
	   "VerifiableCredential"
	 ],
	 "credentialSubject": {
	   "given_name": {},
	   "last_name": {},
	   "degree": {}
	 },
	 "proof": {
	   "proof_type": "jwt",
	   "jwt":"`+string(data)+`"
	 }
	}`))
		w := httptest.NewRecorder()
		err = oidcRouter.IssueCredential(newRequestContext(), w, req)
		require.NoError(t, err)

		var resp map[string]any
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		require.Equal(t, "invalid_or_missing_proof", resp["error"].(string))
		require.NotEmpty(t, resp["c_nonce"])
		require.Equal(t, 12345., resp["c_nonce_expires_in"].(float64))
	})
}

func assertCredentialErrorResponseEquals(t *testing.T, w *httptest.ResponseRecorder, s string) {
	respBody, err := io.ReadAll(w.Body)
	require.NoError(t, err)
	require.JSONEq(t, s, string(respBody))
}
