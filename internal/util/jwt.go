package util

import (
	"fmt"

	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"

	"github.com/tbd54566975/ssi-service/internal/keyaccess"
)

// ParseJWT parses a JWT token and returns the jws signature and jwt claims
func ParseJWT(token keyaccess.JWT) (*jws.Signature, jwt.Token, error) {
	tokenBytes := []byte(token)
	parsedJWS, err := jws.Parse(tokenBytes)
	if err != nil {
		return nil, nil, err
	}
	signatures := parsedJWS.Signatures()
	if len(signatures) != 1 {
		return nil, nil, fmt.Errorf("expected 1 signature, got %d", len(signatures))
	}
	parsedJWT, err := jwt.Parse(tokenBytes)
	if err != nil {
		return nil, nil, err
	}
	return signatures[0], parsedJWT, nil
}

func GetKeyIDFromJWT(token keyaccess.JWT) (string, error) {
	tokenBytes := []byte(token)
	parsedJWS, err := jws.Parse(tokenBytes)
	if err != nil {
		return "", err
	}
	signatures := parsedJWS.Signatures()
	if len(signatures) != 1 {
		return "", fmt.Errorf("expected 1 signature, got %d", len(signatures))
	}
	return signatures[0].ProtectedHeaders().KeyID(), nil
}
