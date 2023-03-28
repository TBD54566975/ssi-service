package did

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolver(t *testing.T) {
	// empty resolver
	_, err := BuildResolver(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no methods provided")

	// unsupported method
	_, err = BuildResolver([]string{"unsupported"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported method: unsupported")

	// valid method
	resolver, err := BuildResolver([]string{"key"})
	assert.NoError(t, err)
	assert.NotEmpty(t, resolver)
	resolved, err := resolver.Resolve("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
	assert.NoError(t, err)
	assert.NotEmpty(t, resolved)

	// resolution for a method that is not supported
	_, err = resolver.Resolve("did:web:example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported method: web")
}
