package credential

import (
	"crypto"

	credsdk "github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/signing"
	"github.com/TBD54566975/ssi-sdk/credential/verification"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"

	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/internal/schema"
	"github.com/tbd54566975/ssi-service/internal/util"
)

type Verifier struct {
	verifier       *verification.CredentialVerifier
	didResolver    *didsdk.Resolver
	schemaResolver schema.Resolution
}

// NewCredentialVerifier creates a new credential verifier which executes both signature and static verification checks.
// In the future the set of verification checks will be configurable.
func NewCredentialVerifier(didResolver *didsdk.Resolver, schemaResolver schema.Resolution) (*Verifier, error) {
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
func (v Verifier) VerifyJWTCredential(token CredentialJWT) error {
	// first, parse the token to see if it contains a valid verifiable credential
	cred, err := signing.ParseVerifiableCredentialFromJWT(token.String())
	if err != nil {
		return util.LoggingErrorMsg(err, "could not parse credential from JWT")
	}

	// resolve the issuer's key material
	kid, pubKey, err := v.resolveIssuerKey(*cred)
	if err != nil {
		return util.LoggingError(err)
	}

	// construct a signature verifier from the verification information
	verifier, err := keyaccess.NewJWKKeyAccessVerifier(kid, pubKey)
	if err != nil {
		return util.LoggingErrorMsg(err, "could not create verifier")
	}

	// verify the signature on the credential
	if err := verifier.Verify(keyaccess.JWKToken{Token: token.String()}); err != nil {
		return util.LoggingErrorMsg(err, "could not verify credential's signature")
	}

	return v.staticVerificationChecks(*cred)
}

// VerifyDataIntegrityCredential first checks the signature on the given data integrity credential. Next, it runs
// a set of static verification checks on the credential as per the credential service's configuration.
func (v Verifier) VerifyDataIntegrityCredential(credential credsdk.VerifiableCredential) error {
	// resolve the issuer's key material
	kid, pubKey, err := v.resolveIssuerKey(credential)
	if err != nil {
		return util.LoggingError(err)
	}

	// construct a signature verifier from the verification information
	verifier, err := keyaccess.NewDataIntegrityKeyAccess(kid, pubKey)
	if err != nil {
		return util.LoggingErrorMsg(err, "could not create verifier")
	}

	// verify the signature on the credential
	if err := verifier.Verify(&credential); err != nil {
		return util.LoggingErrorMsg(err, "could not verify the credential's signature")
	}

	return v.staticVerificationChecks(credential)
}

// resolveIssuerKey resolves the issuer's public key from the credential's issuer DID.
// TODO(gabe): perhaps this should be a verification method referenced on the proof object, not the issuer
// TODO(gabe): support issuers that are not strings, but objects
func (v Verifier) resolveIssuerKey(credential credsdk.VerifiableCredential) (kid string, pubKey crypto.PublicKey, err error) {
	issuerDID := credential.Issuer.(string)
	resolved, err := v.didResolver.Resolve(issuerDID, nil)
	if err != nil {
		err = errors.Wrapf(err, "failed to resolve did: %s", issuerDID)
		return
	}

	// next, get the verification information (key) from the did document of the issuer
	kid, pubKey, err = keyaccess.GetVerificationInformation(resolved.DIDDocument, "")
	if err != nil {
		err = errors.Wrapf(err, "failed to get verification information from the issuer's did document: %s", issuerDID)
		return
	}
	return
}

// staticVerificationChecks runs a set of static verification checks on the credential as per the credential
// service's configuration, such as checking the credential's schema, expiration, and object validity.
func (v Verifier) staticVerificationChecks(credential credsdk.VerifiableCredential) error {
	// if the credential has a schema, resolve it before it is to be used in verification
	var verificationOpts []verification.VerificationOption
	if credential.CredentialSchema != nil {
		schemaID := credential.CredentialSchema.ID
		resolvedSchema, err := v.schemaResolver.Resolve(schemaID)
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
