package manifest

import (
	"fmt"

	"github.com/TBD54566975/ssi-sdk/credential/manifest"
	"github.com/pkg/errors"

	didint "github.com/tbd54566975/ssi-service/internal/did"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/service/credential"
)

func (s Service) verifyApplicationJWT(did string, token keyaccess.JWT) error {
	kid, pubKey, err := didint.ResolveKeyForDID(s.didResolver, did)
	if err != nil {
		return errors.Wrapf(err, "failed to resolve applicant's did: %s", did)
	}
	verifier, err := keyaccess.NewJWKKeyAccessVerifier(kid, pubKey)
	if err != nil {
		return util.LoggingErrorMsg(err, "could not create application verifier")
	}
	if err := verifier.Verify(token); err != nil {
		return util.LoggingErrorMsg(err, "could not verify the application's signature")
	}
	return nil
}

// validateCredentialApplication validates the credential application's signature(s) in addition to making sure it
// is a valid credential application, and complies with its corresponding manifest
// TODO: this should also (optionally) return the failed input descriptor(s)
func (s Service) validateCredentialApplication(credManifest manifest.CredentialManifest, request SubmitApplicationRequest) error {
	// validate the payload's signature
	if err := s.verifyApplicationJWT(request.ApplicantDID, request.ApplicationJWT); err != nil {
		errMsg := fmt.Sprintf("could not verify application<%s>'s signature", request.Application.ID)
		return util.LoggingErrorMsg(err, errMsg)
	}

	// validate the application
	credApp := request.Application
	if err := credApp.IsValid(); err != nil {
		return util.LoggingErrorMsg(err, "application is not valid")
	}

	// next, validate that the credential(s) provided in the application are valid
	if _, err := manifest.IsValidCredentialApplicationForManifest(credManifest, request.ApplicationJSON); err != nil {
		errMsg := fmt.Sprintf("could not validate application: %s", credApp.ID)
		return util.LoggingErrorMsg(err, errMsg)
	}

	// signature and validity checks for each credential submitted with the application
	for _, credentialContainer := range request.Credentials {
		verificationResult, err := s.credential.VerifyCredential(credential.VerifyCredentialRequest{
			DataIntegrityCredential: credentialContainer.Credential,
			CredentialJWT:           credentialContainer.CredentialJWT,
		})
		if err != nil {
			errMsg := fmt.Sprintf("could not verify credential: %s", credentialContainer.Credential.ID)
			return util.LoggingNewError(errMsg)
		}
		if !verificationResult.Verified {
			errMsg := fmt.Sprintf("submitted credential<%s> is not valid: %s", credentialContainer.Credential.ID, verificationResult.Reason)
			return util.LoggingNewError(errMsg)
		}
	}
	return nil
}
