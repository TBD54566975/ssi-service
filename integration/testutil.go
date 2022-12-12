package integration

import (
	"sync"

	"github.com/pkg/errors"
)

type TestContext struct {
	testName string
	values   map[string]any
}

var globalMutex sync.RWMutex

func NewTestContext(testName string) *TestContext {
	return &TestContext{
		testName: testName,
		values:   make(map[string]any),
	}
}

// SetValue sets a value in the test context.
func SetValue(ctx *TestContext, key string, value any) {
	globalMutex.RLock()
	defer globalMutex.RUnlock()
	ctx.values[key] = value
}

// GetValue retrieves a value from the test context.
func GetValue(ctx *TestContext, key string) (any, error) {
	globalMutex.RLock()
	defer globalMutex.RUnlock()
	value, ok := ctx.values[key]
	if !ok {
		return nil, errors.Errorf("value not found for key %s", key)
	}

	return value, nil
}
