package did

import (
	"context"
	"crypto"
	"fmt"

	"github.com/TBD54566975/ssi-sdk/cryptosuite"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/mr-tron/base58"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-varint"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/pkg/service/did/resolve"
)

// GetVerificationInformation resolves a DID and provides a kid and public key needed for data verification
// it is possible that a DID has multiple verification method, in which case a kid must be provided, otherwise
// resolution will fail.
func GetVerificationInformation(did didsdk.DIDDocument, maybeKID string) (kid string, pubKey crypto.PublicKey, err error) {
	if did.IsEmpty() {
		return "", nil, errors.Errorf("did doc: %+v is empty", did)
	}
	verificationMethods := did.VerificationMethod
	if len(verificationMethods) == 0 {
		return "", nil, errors.Errorf("did doc: %s has no verification method", did.ID)
	}

	// handle the case where a kid is provided && there are multiple verification method
	if len(verificationMethods) > 1 {
		if maybeKID == "" {
			return "", nil, errors.Errorf("kid is required for did: %s, which has multiple verification method", did.ID)
		}
		for _, method := range verificationMethods {
			if method.ID == maybeKID {
				kid = method.ID
				pubKey, err = extractKeyFromVerificationMethod(method)
				return
			}
		}
	}
	// TODO(gabe): some DIDs, like did:key have KIDs that aren't used, so we need to know when to use a kid vs the DID
	kid = did.ID
	pubKey, err = extractKeyFromVerificationMethod(verificationMethods[0])
	return
}

func extractKeyFromVerificationMethod(method didsdk.VerificationMethod) (pubKey crypto.PublicKey, err error) {
	switch {
	case method.PublicKeyMultibase != "":
		pubKeyBytes, multiBaseErr := multibaseToPubKeyBytes(method.PublicKeyMultibase)
		if multiBaseErr != nil {
			err = multiBaseErr
			return
		}
		pubKey, err = cryptosuite.PubKeyBytesToTypedKey(pubKeyBytes, method.Type)
		return
	case method.PublicKeyBase58 != "":
		pubKeyDecoded, b58Err := base58.Decode(method.PublicKeyBase58)
		if b58Err != nil {
			err = b58Err
			return
		}
		pubKey, err = cryptosuite.PubKeyBytesToTypedKey(pubKeyDecoded, method.Type)
		return
	case method.PublicKeyJWK != nil:
		jwkBytes, jwkErr := json.Marshal(method.PublicKeyJWK)
		if jwkErr != nil {
			err = jwkErr
			return
		}
		parsed, parseErr := jwk.ParseKey(jwkBytes)
		if parseErr != nil {
			err = parseErr
			return
		}
		if err = parsed.Raw(&pubKey); err != nil {
			return
		}

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

// ResolveKeyForDID resolves a public key from a DID.
func ResolveKeyForDID(ctx context.Context, resolver resolve.Resolver, did string) (kid string, pubKey crypto.PublicKey, err error) {
	resolved, err := resolver.Resolve(ctx, did, nil)
	if err != nil {
		err = errors.Wrapf(err, "failed to resolve did: %s", did)
		return
	}

	// next, get the verification information (key) from the did document
	kid, pubKey, err = GetVerificationInformation(resolved.DIDDocument, "")
	if err != nil {
		err = errors.Wrapf(err, "failed to get verification information from the did document: %s", did)
		return
	}
	return
}
