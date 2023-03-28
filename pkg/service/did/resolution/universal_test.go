package resolution

import (
	"context"
	"testing"

	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/stretchr/testify/assert"
)

// TestUniversalResolver tests the universal resolver's dev instance. It is intentionally skipped to not run in CI.
func TestUniversalResolver(t *testing.T) {
	t.Skip("skipping integration test")
	t.Run("test get methods", func(tt *testing.T) {
		resolver, err := newUniversalResolver("https://dev.uniresolver.io")
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resolver)

		methods := resolver.Methods()
		assert.NotEmpty(tt, methods)
		assert.Contains(tt, methods, didsdk.Method("ion"))
	})

	t.Run("test get ion resolution", func(tt *testing.T) {
		resolver, err := newUniversalResolver("https://dev.uniresolver.io")
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resolver)

		resolution, err := resolver.Resolve(context.Background(), "did:ion:EiClkZMDxPKqC9c-umQfTkR8vvZ9JPhl_xLDI9Nfk38w5w")
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resolution)

		assert.Equal(tt, "did:ion:EiClkZMDxPKqC9c-umQfTkR8vvZ9JPhl_xLDI9Nfk38w5w", resolution.Document.ID)
	})
}
