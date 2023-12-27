package util

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"

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
	parsedJWT, err := jwt.Parse(tokenBytes, jwt.WithVerify(false))
	if err != nil {
		return nil, nil, err
	}
	return signatures[0], parsedJWT, nil
}
