package manifest

import (
	"context"

	"github.com/TBD54566975/ssi-sdk/credential/manifest"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/jwt"

	didint "github.com/tbd54566975/ssi-service/internal/did"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
)

func (s Service) signManifestJWT(ctx context.Context, m CredentialManifestContainer) (*keyaccess.JWT, error) {
	issuerID := m.Manifest.Issuer.ID
	gotKey, err := s.keyStore.GetKey(ctx, keystore.GetKeyRequest{ID: issuerID})
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get key for signing manifest with key<%s>", issuerID)
	}
	keyAccess, err := keyaccess.NewJWKKeyAccess(gotKey.ID, gotKey.Key)
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
	claims := parsed.PrivateClaims()
	claimsJSONBytes, err := json.Marshal(claims)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not marshal claims")
	}
	var parsedManifest CredentialManifestContainer
	if err = json.Unmarshal(claimsJSONBytes, &parsedManifest); err != nil {
		return nil, util.LoggingErrorMsg(err, "could not unmarshal claims into manifest")
	}
	issuer := parsedManifest.Manifest.Issuer.ID
	kid, pubKey, err := didint.ResolveKeyForDID(ctx, s.didResolver, issuer)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "failed to resolve manifest issuer's did: %s", issuer)
	}
	verifier, err := keyaccess.NewJWKKeyAccessVerifier(kid, pubKey)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not create manifest verifier")
	}
	if err = verifier.Verify(token); err != nil {
		return nil, util.LoggingErrorMsg(err, "could not verify the manifest's signature")
	}
	return &parsedManifest.Manifest, nil
}
