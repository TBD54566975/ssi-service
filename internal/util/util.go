package util

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
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

// LoggingErrorMsg is a utility to combine logging an error, and returning and error with a message
func LoggingErrorMsg(err error, msg string) error {
	logrus.WithError(err).Error(msg)
	return errors.Wrap(err, msg)
}
