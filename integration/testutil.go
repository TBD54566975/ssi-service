package integration

import (
	"sync"

	"github.com/pkg/errors"
)

type TestContext struct {
	testName string
	values   map[string]interface{}
}

var globalMutex sync.RWMutex

func NewTestContext(testName string) *TestContext {
	return &TestContext{
		testName: testName,
		values:   make(map[string]interface{}),
	}
}

// SetValue sets a value in the test context.
func SetValue(ctx *TestContext, key string, value interface{}) {
	globalMutex.RLock()
	defer globalMutex.RUnlock()
	ctx.values[key] = value
}

// GetValue retrieves a value from the test context.
func GetValue(ctx *TestContext, key string) (interface{}, error) {
	globalMutex.RLock()
	defer globalMutex.RUnlock()
	value, ok := ctx.values[key]
	if !ok {
		return nil, errors.Errorf("value not found for key %s", key)
	}

	return value, nil
}
