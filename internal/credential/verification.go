package credential

import (
	"crypto"
	"fmt"

	credsdk "github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/signing"
	"github.com/TBD54566975/ssi-sdk/credential/verification"
	"github.com/TBD54566975/ssi-sdk/cryptosuite"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/mr-tron/base58"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-varint"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/internal/util"
)

type CredentialVerifier struct {
	verifier *verification.CredentialVerifier
	resolver *didsdk.Resolver
}

// NewCredentialVerifier creates a new credential verifier which executes both signature and static verification checks.
// In the future the set of verification checks will be configurable.
func NewCredentialVerifier(resolver *didsdk.Resolver) (*CredentialVerifier, error) {
	if resolver == nil {
		return nil, errors.New("resolver is nil")
	}
	// TODO(gabe): consider making this configurable
	verifiers := verification.KnownVerifiers
	verifier, err := verification.NewCredentialVerifier(verifiers)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create static credential verifier")
	}
	return &CredentialVerifier{
		verifier: verifier,
		resolver: resolver,
	}, nil
}

func (v CredentialVerifier) VerifyJWTCredential(token string) error {
	cred, err := signing.ParseVerifiableCredentialFromJWT(token)
	if err != nil {
		return util.LoggingErrorMsg(err, "could not parse credential from JWT")
	}
	kid, pubKey, err := v.getVerificationInformation(cred.Issuer.(string), "")
	if err != nil {
		return util.LoggingErrorMsg(err, "could not get verification from credential")
	}
	verifier, err := keyaccess.NewJWKKeyAccessVerifier(kid, pubKey)
	if err != nil {
		return util.LoggingErrorMsg(err, "could not create verifier")
	}
	if err := verifier.Verify(keyaccess.JWKToken{Token: token}); err != nil {
		return util.LoggingErrorMsg(err, "could not verify credential's signature")
	}
	return v.verifier.VerifyCredential(*cred)
}

func (v CredentialVerifier) VerifyDataIntegrityCredential(credential credsdk.VerifiableCredential) error {
	// TODO(gabe): perhaps this should be a verification method referenced on the proof object, not the issuer
	kid, pubKey, err := v.getVerificationInformation(credential.Issuer.(string), "")
	if err != nil {
		return util.LoggingErrorMsg(err, "could not get verification from credential")
	}
	verifier, err := keyaccess.NewDataIntegrityKeyAccess(kid, pubKey)
	if err != nil {
		return util.LoggingErrorMsg(err, "could not create verifier")
	}
	if err := verifier.Verify(&credential); err != nil {
		return util.LoggingErrorMsg(err, "could not verify credential's signature")
	}
	return v.verifier.VerifyCredential(credential)
}

// getVerificationInformation resolves a DID and provides a kid and public key needed for credential verification
// it is possible that a DID has multiple verification methods, in which case a kid must be provided, otherwise
// resolution will fail.
func (v CredentialVerifier) getVerificationInformation(did, maybeKID string) (kid string, pubKey crypto.PublicKey, err error) {
	resolved, err := v.resolver.Resolve(did)
	if err != nil {
		return "", nil, errors.Wrapf(err, "failed to resolve did: %s", did)
	}
	if resolved.DIDDocument.IsEmpty() {
		return "", nil, errors.Errorf("did doc: %s is empty", did)
	}
	verificationMethods := resolved.DIDDocument.VerificationMethod
	if len(verificationMethods) == 0 {
		return "", nil, errors.Errorf("did doc: %s has no verification methods", did)
	}

	// handle the case where a kid is provided && there are multiple verification methods
	if len(verificationMethods) > 1 {
		if kid == "" {
			return "", nil, errors.Errorf("kid is required for did: %s, which has multiple verification methods", did)
		}
		for _, method := range verificationMethods {
			if method.ID == kid {
				kid = did
				pubKey, err = extractKeyFromVerificationMethod(verificationMethods[0])
				return
			}
		}
	}
	// TODO(gabe): some DIDs, like did:key have KIDs that aren't used, so we need to know when to use a kid vs the DID
	kid = did
	pubKey, err = extractKeyFromVerificationMethod(verificationMethods[0])
	return
}

func extractKeyFromVerificationMethod(method didsdk.VerificationMethod) (pubKey crypto.PublicKey, err error) {
	if method.PublicKeyMultibase != "" {
		pubKeyBytes, multiBaseErr := multibaseToPubKeyBytes(method.PublicKeyMultibase)
		if multiBaseErr != nil {
			err = multiBaseErr
			return
		}
		pubKey, err = cryptosuite.PubKeyBytesToTypedKey(pubKeyBytes, method.Type)
		return
	} else if method.PublicKeyBase58 != "" {
		pubKeyDecoded, b58Err := base58.Decode(method.PublicKeyBase58)
		if b58Err != nil {
			err = b58Err
			return
		}
		pubKey, err = cryptosuite.PubKeyBytesToTypedKey(pubKeyDecoded, method.Type)
		return
	} else if method.PublicKeyJWK != nil {
		jwkBytes, jwkErr := json.Marshal(method.PublicKeyJWK)
		if err != nil {
			err = jwkErr
			return
		}
		pubKey, err = jwk.ParseKey(jwkBytes)
		return
	}
	err = errors.New("no public key found in verification method")
	return
}

// multibaseToPubKey converts a multibase encoded public key to public key bytes for known multibase encodings
func multibaseToPubKeyBytes(mb string) ([]byte, error) {
	if mb == "" {
		err := fmt.Errorf("could not decode value: %s", mb)
		logrus.WithError(err).Error()
		return nil, err
	}

	encoding, decoded, err := multibase.Decode(mb)
	if err != nil {
		logrus.WithError(err).Error("could not decode did:key")
		return nil, err
	}
	if encoding != didsdk.Base58BTCMultiBase {
		err := fmt.Errorf("expected %d encoding but found %d", didsdk.Base58BTCMultiBase, encoding)
		logrus.WithError(err).Error()
		return nil, err
	}

	// n = # bytes for the int, which we expect to be two from our multicodec
	_, n, err := varint.FromUvarint(decoded)
	if err != nil {
		return nil, err
	}
	if n != 2 {
		return nil, errors.New("error parsing did:key varint")
	}
	pubKeyBytes := decoded[n:]
	return pubKeyBytes, nil
}
