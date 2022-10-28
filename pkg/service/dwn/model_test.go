package dwn

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFoo(t *testing.T) {
	resp := PublishManifestResponse{}
	jsonResp, err := json.Marshal(&resp)
	assert.NoError(t, err)
	assert.JSONEq(t, "{}", string(jsonResp))
}
