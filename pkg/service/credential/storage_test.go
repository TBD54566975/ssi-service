package credential

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCredentialStorage(t *testing.T) {
	t.Run("Extract UUID returns UUID", func(tt *testing.T) {

		uuid := ExtractID("/v1/credentials/status/ceccb36e-a386-494a-8bf5-d86f953485dd")
		assert.NotEmpty(tt, uuid)
		assert.Equal(tt, uuid, "ceccb36e-a386-494a-8bf5-d86f953485dd")

		uuid = ExtractID("http://localhost:1234/v1/credentials/status/ceccb36e-a386-494a-8bf5-d86f953485dd")
		assert.NotEmpty(tt, uuid)
		assert.Equal(tt, uuid, "ceccb36e-a386-494a-8bf5-d86f953485dd")

		uuid = ExtractID("ANYTHING/ceccb36e-a386-494a-8bf5-d86f953485dd")
		assert.NotEmpty(tt, uuid)
		assert.Equal(tt, uuid, "ceccb36e-a386-494a-8bf5-d86f953485dd")

		uuid = ExtractID("badinput")
		assert.Empty(tt, uuid)
	})
}
