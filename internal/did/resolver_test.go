package did

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolver(t *testing.T) {
	// empty resolver
	_, err := BuildMultiMethodResolver(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no methods provided")

	// unsupported method
	_, err = BuildMultiMethodResolver([]string{"unsupported"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no resolvers created")

	// valid method
	resolver, err := BuildMultiMethodResolver([]string{"key"})
	assert.NoError(t, err)
	assert.NotEmpty(t, resolver)
	resolved, err := resolver.Resolve(context.Background(), "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
	assert.NoError(t, err)
	assert.NotEmpty(t, resolved)

	// resolution for a method that is not supported
	_, err = resolver.Resolve(context.Background(), "did:web:example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported method: web")
}
