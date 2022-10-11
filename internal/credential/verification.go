package credential

import (
	credsdk "github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/signing"
	"github.com/TBD54566975/ssi-sdk/credential/verification"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/pkg/errors"

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

// TODO(gabe) consider moving this verification logic to the sdk https://github.com/TBD54566975/ssi-service/issues/122

// VerifyJWTCredential first parses and checks the signature on the given JWT credential. Next, it runs
// a set of static verification checks on the credential as per the credential service's configuration.
func (v CredentialVerifier) VerifyJWTCredential(token string) error {
	cred, err := signing.ParseVerifiableCredentialFromJWT(token)
	if err != nil {
		return util.LoggingErrorMsg(err, "could not parse credential from JWT")
	}
	issuerDID := cred.Issuer.(string)
	resolved, err := v.resolver.Resolve(issuerDID)
	if err != nil {
		return errors.Wrapf(err, "failed to resolve did: %s", issuerDID)
	}
	kid, pubKey, err := keyaccess.GetVerificationInformation(resolved.DIDDocument, "")
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
	if err = v.verifier.VerifyCredential(*cred); err != nil {
		return util.LoggingErrorMsg(err, "static credential verification failed")
	}
	return err
}

// VerifyDataIntegrityCredential first checks the signature on the given data integrity credential. Next, it runs
// a set of static verification checks on the credential as per the credential service's configuration.
func (v CredentialVerifier) VerifyDataIntegrityCredential(credential credsdk.VerifiableCredential) error {
	// TODO(gabe): perhaps this should be a verification method referenced on the proof object, not the issuer
	issuerDID := credential.Issuer.(string)
	resolved, err := v.resolver.Resolve(issuerDID)
	if err != nil {
		return errors.Wrapf(err, "failed to resolve did: %s", issuerDID)
	}
	kid, pubKey, err := keyaccess.GetVerificationInformation(resolved.DIDDocument, "")
	if err != nil {
		return util.LoggingErrorMsg(err, "could not get verification information from credential")
	}
	verifier, err := keyaccess.NewDataIntegrityKeyAccess(kid, pubKey)
	if err != nil {
		return util.LoggingErrorMsg(err, "could not create verifier")
	}
	if err := verifier.Verify(&credential); err != nil {
		return util.LoggingErrorMsg(err, "could not verify the credential's signature")
	}
	if err = v.verifier.VerifyCredential(credential); err != nil {
		return util.LoggingErrorMsg(err, "static credential verification failed")
	}
	return err
}
