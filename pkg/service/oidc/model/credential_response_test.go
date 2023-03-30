package model

import (
	_ "embed"
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/require"
)

//go:embed expected_jwt_jvc_credential_response.json
var exampleJWTVCCredentialResp []byte

func TestCredentialResponseUnmarshalAndMarshallIsLossless(t *testing.T) {
	var m CredentialResponse
	require.NoError(t, json.Unmarshal(exampleJWTVCCredentialResp, &m))

	jsonData, err := json.Marshal(m)
	require.NoError(t, err)
	require.JSONEq(t, string(exampleJWTVCCredentialResp), string(jsonData))
}
