package model

import (
	_ "embed"
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/require"
)

//go:embed expected_jwt_vc_credential_request.json
var exampleJWTVCCredentialRequest []byte

func TestCredentialRequestUnmarshalAndMarshallIsLossless(t *testing.T) {
	var m CredentialRequest
	require.NoError(t, json.Unmarshal(exampleJWTVCCredentialRequest, &m))

	jsonData, err := json.Marshal(m)
	require.NoError(t, err)
	require.JSONEq(t, string(exampleJWTVCCredentialRequest), string(jsonData))
}
