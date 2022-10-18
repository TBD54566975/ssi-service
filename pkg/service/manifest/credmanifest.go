package manifest

import (
	"fmt"

	"github.com/TBD54566975/ssi-sdk/credential/manifest"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	didint "github.com/tbd54566975/ssi-service/internal/did"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
)

func (s Service) signManifestJWT(m manifest.CredentialManifest) (*keyaccess.JWT, error) {
	issuerID := m.Issuer.ID
	gotKey, err := s.keyStore.GetKey(keystore.GetKeyRequest{ID: issuerID})
	if err != nil {
		errMsg := fmt.Sprintf("could not get key for signing manifest with key<%s>", issuerID)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	keyAccess, err := keyaccess.NewJWKKeyAccess(gotKey.ID, gotKey.Key)
	if err != nil {
		errMsg := fmt.Sprintf("could not create key access for signing manifest with key<%s>", gotKey.ID)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	// marshal the manifest before signing it as a JWT
	manifestBytes, err := json.Marshal(m)
	if err != nil {
		errMsg := fmt.Sprintf("could not marshal manifest<%s>", m.ID)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	var manifestJSON map[string]interface{}
	if err := json.Unmarshal(manifestBytes, &manifestJSON); err != nil {
		errMsg := fmt.Sprintf("could not unmarshal manifest<%s>", m.ID)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	manifestToken, err := keyAccess.Sign(manifestJSON)
	if err != nil {
		errMsg := fmt.Sprintf("could not sign manifest with key<%s>", gotKey.ID)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	return manifestToken, nil
}

func (s Service) verifyManifestJWT(token keyaccess.JWT) (*manifest.CredentialManifest, error) {
	parsed, err := jwt.Parse([]byte(token))
	if err != nil {
		errMsg := "could not parse JWT"
		logrus.WithError(err).Error(errMsg)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	claims := parsed.PrivateClaims()
	claimsJSONBytes, err := json.Marshal(claims)
	if err != nil {
		errMsg := "could not marshal claims"
		logrus.WithError(err).Error(errMsg)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	var parsedManifest manifest.CredentialManifest
	if err := json.Unmarshal(claimsJSONBytes, &parsedManifest); err != nil {
		errMsg := "could not unmarshal claims into manifest"
		logrus.WithError(err).Error(errMsg)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	kid, pubKey, err := didint.ResolveKeyForDID(s.didResolver, parsedManifest.Issuer.ID)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to resolve manifest issuer's did: %s", parsedManifest.Issuer.ID)
	}
	verifier, err := keyaccess.NewJWKKeyAccessVerifier(kid, pubKey)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not create manifest verifier")
	}
	if err := verifier.Verify(token); err != nil {
		return nil, util.LoggingErrorMsg(err, "could not verify the manifest's signature")
	}
	return &parsedManifest, nil
}
