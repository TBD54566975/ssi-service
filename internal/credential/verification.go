package credential

import (
	"context"
	"crypto"
	"fmt"

	credsdk "github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/signing"
	"github.com/TBD54566975/ssi-sdk/credential/verification"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"

	didint "github.com/tbd54566975/ssi-service/internal/did"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/internal/schema"
	"github.com/tbd54566975/ssi-service/internal/util"
)

type Verifier struct {
	verifier       *verification.CredentialVerifier
	didResolver    didsdk.Resolver
	schemaResolver schema.Resolution
}

// NewCredentialVerifier creates a new credential verifier which executes both signature and static verification checks.
// In the future the set of verification checks will be configurable.
func NewCredentialVerifier(didResolver didsdk.Resolver, schemaResolver schema.Resolution) (*Verifier, error) {
	if didResolver == nil {
		return nil, errors.New("didResolver cannot be nil")
	}
	if schemaResolver == nil {
		return nil, errors.New("schemaResolver cannot be nil")
	}
	// TODO(gabe): consider making this configurable
	verifiers := verification.KnownVerifiers
	verifier, err := verification.NewCredentialVerifier(verifiers)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create static credential verifier")
	}
	return &Verifier{
		verifier:       verifier,
		didResolver:    didResolver,
		schemaResolver: schemaResolver,
	}, nil
}

// TODO(gabe) consider moving this verification logic to the sdk https://github.com/TBD54566975/ssi-service/issues/122

// VerifyJWTCredential first parses and checks the signature on the given JWT credential. Next, it runs
// a set of static verification checks on the credential as per the credential service's configuration.
func (v Verifier) VerifyJWTCredential(ctx context.Context, token keyaccess.JWT) error {
	// first, parse the token to see if it contains a valid verifiable credential
	cred, err := signing.ParseVerifiableCredentialFromJWT(token.String())
	if err != nil {
		return util.LoggingErrorMsg(err, "could not parse credential from JWT")
	}

	// TODO(gabe) support resolving keys by ID
	jwtKID, err := util.GetKeyIDFromJWT(token)
	if err != nil {
		return util.LoggingErrorMsg(err, "could not get key ID from JWT")
	}

	// resolve the issuer's key material
	kid, pubKey, err := v.resolveCredentialIssuerKey(ctx, *cred)
	if err != nil {
		return util.LoggingError(err)
	}

	if jwtKID != kid {
		errMsg := fmt.Sprintf("JWT<%s> and credential<%s> key IDs do not match", jwtKID, kid)
		return util.LoggingErrorMsg(err, errMsg)
	}

	// construct a signature verifier from the verification information
	verifier, err := keyaccess.NewJWKKeyAccessVerifier(kid, pubKey)
	if err != nil {
		return util.LoggingErrorMsg(err, "could not create verifier")
	}

	// verify the signature on the credential
	if err = verifier.Verify(token); err != nil {
		return util.LoggingErrorMsg(err, "could not verify credential's signature")
	}

	return v.staticVerificationChecks(ctx, *cred)
}

// VerifyDataIntegrityCredential first checks the signature on the given data integrity credential. Next, it runs
// a set of static verification checks on the credential as per the credential service's configuration.
func (v Verifier) VerifyDataIntegrityCredential(ctx context.Context, credential credsdk.VerifiableCredential) error {
	// resolve the issuer's key material
	kid, pubKey, err := v.resolveCredentialIssuerKey(ctx, credential)
	if err != nil {
		return util.LoggingError(err)
	}

	// construct a signature verifier from the verification information
	verifier, err := keyaccess.NewDataIntegrityKeyAccess(kid, pubKey)
	if err != nil {
		errMsg := fmt.Sprintf("could not create verifier for kid %s", kid)
		return util.LoggingErrorMsg(err, errMsg)
	}

	// verify the signature on the credential
	if err = verifier.Verify(&credential); err != nil {
		return util.LoggingErrorMsg(err, "could not verify the credential's signature")
	}

	return v.staticVerificationChecks(ctx, credential)
}

func (v Verifier) VerifyJWT(ctx context.Context, did string, token keyaccess.JWT) error {
	// resolve the did's key material
	kid, pubKey, err := v.resolveKeyForDID(ctx, did)
	if err != nil {
		return util.LoggingError(err)
	}

	// construct a signature verifier from the verification information
	verifier, err := keyaccess.NewJWKKeyAccessVerifier(kid, pubKey)
	if err != nil {
		return util.LoggingErrorMsgf(err, "could not create verifier for kid %s", kid)
	}

	// verify the signature on the credential
	if err = verifier.Verify(token); err != nil {
		return util.LoggingErrorMsg(err, "could not verify the JWT signature")
	}

	return nil
}

// resolveCredentialIssuerKey resolves the issuer's public key from the credential's issuer DID.
// TODO(gabe): perhaps this should be a verification method referenced on the proof object, not the issuer
// TODO(gabe): support issuers that are not strings, but objects
func (v Verifier) resolveCredentialIssuerKey(ctx context.Context, credential credsdk.VerifiableCredential) (kid string, pubKey crypto.PublicKey, err error) {
	issuerDID := credential.Issuer.(string)
	return v.resolveKeyForDID(ctx, issuerDID)
}

// resolveKeyForDID combines the resolution of a DID document with the extraction of the verification information
func (v Verifier) resolveKeyForDID(ctx context.Context, did string) (kid string, pubKey crypto.PublicKey, err error) {
	// resolve DID document
	resolved, err := v.didResolver.Resolve(ctx, did)
	if err != nil {
		err = errors.Wrapf(err, "resolving DID: %s", did)
		return kid, pubKey, err
	}

	// get the verification information from the DID document
	kid, pubKey, err = didint.GetVerificationInformation(resolved.Document, "")
	if err != nil {
		err = errors.Wrapf(err, "getting verification information from the DID document: %s", did)
		return kid, pubKey, err
	}

	return kid, pubKey, nil
}

// staticVerificationChecks runs a set of static verification checks on the credential as per the credential
// service's configuration, such as checking the credential's schema, expiration, and object validity.
func (v Verifier) staticVerificationChecks(ctx context.Context, credential credsdk.VerifiableCredential) error {
	// if the credential has a schema, resolve it before it is to be used in verification
	var verificationOpts []verification.VerificationOption
	if credential.CredentialSchema != nil {
		schemaID := credential.CredentialSchema.ID
		resolvedSchema, err := v.schemaResolver.Resolve(ctx, schemaID)
		if err != nil {
			return errors.Wrapf(err, "for credential<%s> failed to resolve schemas: %s", credential.ID, schemaID)
		}
		schemaBytes, err := json.Marshal(resolvedSchema)
		if err != nil {
			return errors.Wrapf(err, "for credential<%s> failed to marshal schema: %s", credential.ID, schemaID)
		}
		verificationOpts = append(verificationOpts, verification.WithSchema(string(schemaBytes)))
	}

	// run the configured static checks on the credential
	if err := v.verifier.VerifyCredential(credential, verificationOpts...); err != nil {
		return util.LoggingErrorMsg(err, "static credential verification failed")
	}

	return nil
}
