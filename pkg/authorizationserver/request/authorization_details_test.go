package request

import (
	_ "embed"
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/require"
)

//go:embed expected_authorization_details.json
var exampleAuthorizationDetails []byte

func TestUnmarshalAndMarshallIsLossless(t *testing.T) {
	var m AuthorizationDetails
	require.NoError(t, json.Unmarshal(exampleAuthorizationDetails, &m))

	jsonData, err := json.Marshal(m)
	require.NoError(t, err)
	require.JSONEq(t, string(exampleAuthorizationDetails), string(jsonData))
}
