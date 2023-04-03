package util

import (
	"fmt"
	"reflect"
	"strings"

	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
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

// LoggingError is a utility to combine logging an error, and returning and error
func LoggingError(err error) error {
	logrus.WithError(err).Error()
	return err
}

// LoggingNewError is a utility to create an error from a message, log it, and return it as an error
func LoggingNewError(msg string) error {
	err := errors.New(msg)
	logrus.WithError(err).Error()
	return err
}

// LoggingNewErrorf is a utility to create an error from a formatted message, log it, and return it as an error
func LoggingNewErrorf(msg string, args ...any) error {
	return LoggingNewError(fmt.Sprintf(msg, args...))
}

// LoggingErrorMsg is a utility to combine logging an error, and returning and error with a message
func LoggingErrorMsg(err error, msg string) error {
	logrus.WithError(err).Error(SanitizeLog(msg))
	return errors.Wrap(err, msg)
}

// LoggingErrorMsgf is a utility to combine logging an error, and returning and error with a formatted message
func LoggingErrorMsgf(err error, msg string, args ...any) error {
	return LoggingErrorMsg(err, fmt.Sprintf(msg, args...))
}

// SanitizeLog prevents certain classes of injection attacks before logging
// https://codeql.github.com/codeql-query-help/go/go-log-injection/
func SanitizeLog(log string) string {
	escapedLog := strings.ReplaceAll(log, "\n", "")
	return strings.ReplaceAll(escapedLog, "\r", "")
}
