package util

import (
	"fmt"
	"strings"
)

// GetMethodForDID gets a DID method from a did, the second part of the did (e.g. did:test:abcd, the method is 'test')
func GetMethodForDID(did string) (string, error) {
	split := strings.Split(did, ":")
	if len(split) < 3 {
		return "", fmt.Errorf("malformed did: %s", did)
	}
	return split[1], nil
}
