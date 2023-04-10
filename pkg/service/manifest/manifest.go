package manifest

import (
	"context"

	"github.com/TBD54566975/ssi-sdk/credential/manifest"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"

	didint "github.com/tbd54566975/ssi-service/internal/did"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
)

func (s Service) signManifestJWT(ctx context.Context, keyID string, m CredentialManifestContainer) (*keyaccess.JWT, error) {
	gotKey, err := s.keyStore.GetKey(ctx, keystore.GetKeyRequest{ID: keyID})
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get key for signing manifest with key<%s>", keyID)
	}
	keyAccess, err := keyaccess.NewJWKKeyAccess(gotKey.Controller, gotKey.ID, gotKey.Key)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not create key access for signing manifest with key<%s>", gotKey.ID)
	}

	// signing the manifest as a JWT
	manifestToken, err := keyAccess.SignJSON(m)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not sign manifest with key<%s>", gotKey.ID)
	}
	return manifestToken, nil
}

func (s Service) verifyManifestJWT(ctx context.Context, token keyaccess.JWT) (*manifest.CredentialManifest, error) {
	parsed, err := jwt.Parse([]byte(token))
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not parse JWT")
	}

	jwtKID, ok := parsed.Get(jws.KeyIDKey)
	if !ok {
		return nil, util.LoggingErrorMsg(err, "could not get key ID from JWT")
	}
	kid, ok := jwtKID.(string)
	if !ok {
		return nil, util.LoggingErrorMsg(err, "could not convert key ID to string")
	}

	claims := parsed.PrivateClaims()
	claimsJSONBytes, err := json.Marshal(claims)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not marshal claims")
	}

	var parsedManifest CredentialManifestContainer
	if err = json.Unmarshal(claimsJSONBytes, &parsedManifest); err != nil {
		return nil, util.LoggingErrorMsg(err, "unmarshalling claims into manifest")
	}

	if err = didint.VerifyTokenFromDID(ctx, s.didResolver, parsedManifest.Manifest.Issuer.ID, kid, token); err != nil {
		return nil, util.LoggingErrorMsg(err, "verifying manifest JWT")
	}
	return &parsedManifest.Manifest, nil
}
