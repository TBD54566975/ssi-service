package verification

import (
	"context"
	"fmt"

	credsdk "github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/integrity"
	"github.com/TBD54566975/ssi-sdk/credential/validation"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/cryptosuite/jws2020"
	"github.com/TBD54566975/ssi-sdk/did/resolution"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"

	"github.com/tbd54566975/ssi-service/internal/credential"
	didint "github.com/tbd54566975/ssi-service/internal/did"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/internal/schema"
)

type Verifier struct {
	validator      *validation.CredentialValidator
	didResolver    resolution.Resolver
	schemaResolver schema.Resolution
}

// NewVerifiableDataVerifier creates a new verifier for both verifiable credentials and verifiable presentations. The verifier
// executes both signature and static verification checks. In the future the set of verification checks will be configurable.
func NewVerifiableDataVerifier(didResolver resolution.Resolver, schemaResolver schema.Resolution) (*Verifier, error) {
	if didResolver == nil {
		return nil, errors.New("didResolver cannot be nil")
	}
	if schemaResolver == nil {
		return nil, errors.New("schemaResolver cannot be nil")
	}
	// TODO(gabe): consider making this configurable
	validators := validation.GetKnownVerifiers()
	validator, err := validation.NewCredentialValidator(validators)
	if err != nil {
		return nil, errors.Wrap(err, "creating static validator")
	}
	return &Verifier{
		validator:      validator,
		didResolver:    didResolver,
		schemaResolver: schemaResolver,
	}, nil
}

// VerifyCredential first parses and checks the signature on the given credential. Next, it runs
// a set of static verification checks on the credential as per the service's configuration.
// Works for both JWT and LD securing mechanisms.
func (v Verifier) VerifyCredential(ctx context.Context, credential credential.Container) error {
	if credential.HasJWTCredential() {
		err := v.VerifyJWTCredential(ctx, *credential.CredentialJWT)
		if err != nil {
			return err
		}
	} else {
		if err := v.VerifyDataIntegrityCredential(ctx, *credential.Credential); err != nil {
			return err
		}
	}
	return nil
}

// VerifyJWTCredential first parses and checks the signature on the given JWT verification. Next, it runs
// a set of static verification checks on the credential as per the service's configuration.
func (v Verifier) VerifyJWTCredential(ctx context.Context, token keyaccess.JWT) error {
	_, err := integrity.VerifyJWTCredential(ctx, token.String(), v.didResolver)
	if err != nil {
		return errors.Wrap(err, "verifying JWT credential")
	}
	_, _, cred, err := integrity.ParseVerifiableCredentialFromJWT(token.String())
	if err != nil {
		return errors.Wrap(err, "parsing vc from jwt")
	}
	return v.staticValidationChecks(ctx, *cred)
}

// VerifyDataIntegrityCredential first checks the signature on the given data integrity verification. Next, it runs
// a set of static verification checks on the credential as per the service's configuration.
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

	// construct a signature validator from the verification information
	publicKeyJWK, err := jwx.PublicKeyToPublicKeyJWK(verificationMethod, pubKey)
	if err != nil {
		return sdkutil.LoggingErrorMsgf(err, "could not convert private key to JWK: %s", verificationMethod)
	}
	verifier, err := jws2020.NewJSONWebKeyVerifier(issuer, *publicKeyJWK)
	if err != nil {
		errMsg := fmt.Sprintf("could not create validator for kid %s", verificationMethod)
		return sdkutil.LoggingErrorMsg(err, errMsg)
	}

	cryptoSuite := jws2020.GetJSONWebSignature2020Suite()
	// verify the signature on the credential
	if err = cryptoSuite.Verify(verifier, &credential); err != nil {
		return sdkutil.LoggingErrorMsg(err, "could not verify the credential's signature")
	}

	return v.staticValidationChecks(ctx, credential)
}

// VerifyJWTPresentation first parses and checks the signature on the given JWT presentation. Next, it runs
// a set of static verification checks on the presentation's credentials as per the service's configuration.
func (v Verifier) VerifyJWTPresentation(ctx context.Context, token keyaccess.JWT) error {
	_, err := integrity.VerifyJWTPresentation(ctx, token.String(), v.didResolver)
	if err != nil {
		return errors.Wrap(err, "verifying JWT presentation")
	}
	_, _, pres, err := integrity.ParseVerifiablePresentationFromJWT(token.String())
	if err != nil {
		return errors.Wrap(err, "parsing vc from jwt")
	}
	// for each credential in the presentation, run a set of static verification checks
	creds, err := credential.NewCredentialContainerFromArray(pres.VerifiableCredential)
	if err != nil {
		return errors.Wrapf(err, "error parsing credentials in presentation<%s>", pres.ID)
	}
	for _, cred := range creds {
		if err = v.staticValidationChecks(ctx, *cred.Credential); err != nil {
			return errors.Wrapf(err, "error running static validation checks on credential in presentation<%v>", cred.ID)
		}
	}
	return nil
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

// staticValidationChecks runs a set of static validation checks on the credential as per the
// service's configuration, such as checking the verification's schema, expiration, and object validity.
func (v Verifier) staticValidationChecks(ctx context.Context, credential credsdk.VerifiableCredential) error {
	// if the credential has a schema, resolve it before it is to be used in verification
	var validationOpts []validation.Option
	if credential.CredentialSchema != nil {
		schemaID := credential.CredentialSchema.ID
		resolvedSchema, _, err := v.schemaResolver.Resolve(ctx, schemaID)
		if err != nil {
			return errors.Wrapf(err, "for credential<%s> failed to resolve schemas: %s", credential.ID, schemaID)
		}
		schemaBytes, err := json.Marshal(resolvedSchema)
		if err != nil {
			return errors.Wrapf(err, "for credential<%s> failed to marshal schema: %s", credential.ID, schemaID)
		}
		validationOpts = append(validationOpts, validation.WithSchema(string(schemaBytes)))
	}

	// run the configured static checks on the credential
	if err := v.validator.ValidateCredential(credential, validationOpts...); err != nil {
		return sdkutil.LoggingErrorMsg(err, "static credential validation failed")
	}

	return nil
}
