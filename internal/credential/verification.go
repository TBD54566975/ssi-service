package credential

import (
	"context"
	"fmt"

	credsdk "github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/verification"
	"github.com/TBD54566975/ssi-sdk/crypto"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/pkg/errors"

	didint "github.com/tbd54566975/ssi-service/internal/did"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/internal/schema"
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
	verifiers := verification.GetKnownVerifiers()
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
	gotHeaders, _, cred, err := credsdk.ParseVerifiableCredentialFromJWT(token.String())
	if err != nil {
		return sdkutil.LoggingErrorMsg(err, "could not parse credential from JWT")
	}

	kid, ok := gotHeaders.Get(jws.KeyIDKey)
	if !ok {
		return sdkutil.LoggingNewError("could not find key ID in JWT headers")
	}
	jwtKID, ok := kid.(string)
	if !ok {
		return sdkutil.LoggingNewErrorf("could not convert key ID to string: %v", kid)
	}

	// resolve the issuer's key material
	issuerDID, ok := cred.Issuer.(string)
	if !ok {
		return sdkutil.LoggingNewErrorf("could not convert issuer to string: %v", cred.Issuer)
	}
	pubKey, err := didint.ResolveKeyForDID(ctx, v.didResolver, issuerDID, jwtKID)
	if err != nil {
		return sdkutil.LoggingError(err)
	}

	// construct a signature verifier from the verification information
	verifier, err := keyaccess.NewJWKKeyAccessVerifier(issuerDID, jwtKID, pubKey)
	if err != nil {
		return sdkutil.LoggingErrorMsg(err, "could not create verifier")
	}

	// verify the signature on the credential
	if err = verifier.Verify(token); err != nil {
		return sdkutil.LoggingErrorMsg(err, "could not verify credential's signature")
	}

	return v.staticVerificationChecks(ctx, *cred)
}

// VerifyDataIntegrityCredential first checks the signature on the given data integrity credential. Next, it runs
// a set of static verification checks on the credential as per the credential service's configuration.
func (v Verifier) VerifyDataIntegrityCredential(ctx context.Context, credential credsdk.VerifiableCredential) error {
	// resolve the issuer's key material
	issuer, ok := credential.Issuer.(string)
	if !ok {
		return sdkutil.LoggingNewErrorf("could not convert issuer to string: %v", credential.Issuer)
	}

	maybeVerificationMethod, err := getKeyFromProof(*credential.Proof, "verificationMethod")
	if err != nil {
		return sdkutil.LoggingErrorMsg(err, "could not get verification method from proof")
	}
	verificationMethod, ok := maybeVerificationMethod.(string)
	if !ok {
		return sdkutil.LoggingNewErrorf("could not convert verification method to string: %v", maybeVerificationMethod)
	}

	pubKey, err := didint.ResolveKeyForDID(ctx, v.didResolver, issuer, verificationMethod)
	if err != nil {
		return sdkutil.LoggingError(err)
	}

	// construct a signature verifier from the verification information
	verifier, err := keyaccess.NewDataIntegrityKeyAccess(issuer, verificationMethod, pubKey)
	if err != nil {
		errMsg := fmt.Sprintf("could not create verifier for kid %s", verificationMethod)
		return sdkutil.LoggingErrorMsg(err, errMsg)
	}

	// verify the signature on the credential
	if err = verifier.Verify(&credential); err != nil {
		return sdkutil.LoggingErrorMsg(err, "could not verify the credential's signature")
	}

	return v.staticVerificationChecks(ctx, credential)
}

func getKeyFromProof(proof crypto.Proof, key string) (any, error) {
	proofBytes, err := json.Marshal(proof)
	if err != nil {
		return nil, err
	}
	var proofMap map[string]any
	if err = json.Unmarshal(proofBytes, &proofMap); err != nil {
		return nil, err
	}
	return proofMap[key], nil
}

func (v Verifier) VerifyJWT(ctx context.Context, did string, token keyaccess.JWT) error {
	// parse headers
	headers, err := keyaccess.GetJWTHeaders([]byte(token))
	if err != nil {
		return sdkutil.LoggingErrorMsg(err, "could not parse JWT headers")
	}
	jwtKID, ok := headers.Get(jws.KeyIDKey)
	if !ok {
		return sdkutil.LoggingNewError("JWT does not contain a kid")
	}
	kid, ok := jwtKID.(string)
	if !ok {
		return sdkutil.LoggingNewError("JWT kid is not a string")
	}

	// resolve key material from the DID
	pubKey, err := didint.ResolveKeyForDID(ctx, v.didResolver, did, kid)
	if err != nil {
		return sdkutil.LoggingError(err)
	}

	// construct a signature verifier from the verification information
	verifier, err := keyaccess.NewJWKKeyAccessVerifier(did, kid, pubKey)
	if err != nil {
		return sdkutil.LoggingErrorMsgf(err, "could not create verifier for kid %s", kid)
	}

	// verify the signature on the credential
	if err = verifier.Verify(token); err != nil {
		return sdkutil.LoggingErrorMsg(err, "could not verify the JWT signature")
	}

	return nil
}

// staticVerificationChecks runs a set of static verification checks on the credential as per the credential
// service's configuration, such as checking the credential's schema, expiration, and object validity.
func (v Verifier) staticVerificationChecks(ctx context.Context, credential credsdk.VerifiableCredential) error {
	// if the credential has a schema, resolve it before it is to be used in verification
	var verificationOpts []verification.Option
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
		return sdkutil.LoggingErrorMsg(err, "static credential verification failed")
	}

	return nil
}
