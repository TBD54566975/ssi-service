package jwt

import (
	"context"

	"github.com/pkg/errors"
	didint "github.com/tbd54566975/ssi-service/internal/did"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/service/did/resolve"
)

// VerifyTokenFromDID verifies that the information in the token was digitally signed by the public key associated with
// the public key of the verification method of the did's document. The passed in resolver is used to map from the did
// to the did document.
func VerifyTokenFromDID(ctx context.Context, did string, token keyaccess.JWT, s resolve.Resolver) error {
	kid, pubKey, err := didint.ResolveKeyForDID(ctx, s, did)
	if err != nil {
		return errors.Wrapf(err, "failed to resolve applicant's did: %s", did)
	}
	verifier, err := keyaccess.NewJWKKeyAccessVerifier(kid, pubKey)
	if err != nil {
		return util.LoggingErrorMsg(err, "could not create application verifier")
	}
	if err := verifier.Verify(token); err != nil {
		return util.LoggingErrorMsg(err, "could not verify the application's signature")
	}
	return nil
}
