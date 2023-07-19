package common

import (
	"strings"

	"github.com/pkg/errors"
)

func ValidateVerificationMethodID(fullyQualifiedVerificationMethodID, issuerID string) error {
	if !strings.HasPrefix(fullyQualifiedVerificationMethodID, issuerID) {
		return errors.Errorf("issuer <%s> must be part of verification method <%s>", issuerID, fullyQualifiedVerificationMethodID)
	}
	return nil
}
