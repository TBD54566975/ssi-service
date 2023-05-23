package util

import (
	"reflect"
	"strings"

	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/pkg/errors"
)

// IsStructPtr checks if the given object is a pointer to a struct
func IsStructPtr(obj any) bool {
	if obj == nil {
		return false
	}
	// make sure out is a ptr to a struct
	outVal := reflect.ValueOf(obj)
	if outVal.Kind() != reflect.Ptr {
		return false
	}

	// dereference the pointer
	outValDeref := outVal.Elem()
	if outValDeref.Kind() != reflect.Struct {
		return false
	}
	return true
}

// GetMethodForDID gets a DID method from a did, the second part of the did (e.g. did:test:abcd, the method is 'test')
func GetMethodForDID(did string) (didsdk.Method, error) {
	split := strings.Split(did, ":")
	if len(split) < 3 {
		return "", errors.New("malformed did: did has fewer than three parts")
	}
	if split[0] != "did" {
		return "", errors.New("malformed did: did must start with `did`")
	}
	return didsdk.Method(split[1]), nil
}

// SanitizeLog prevents certain classes of injection attacks before logging
// https://codeql.github.com/codeql-query-help/go/go-log-injection/
func SanitizeLog(log string) string {
	escapedLog := strings.ReplaceAll(log, "\n", "")
	return strings.ReplaceAll(escapedLog, "\r", "")
}

// Is2xxResponse returns true if the given status code is a 2xx response
func Is2xxResponse(statusCode int) bool {
	return statusCode/100 == 2
}
