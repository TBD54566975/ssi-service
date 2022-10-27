package manifest

import (
	"fmt"
	"strings"

	"github.com/TBD54566975/ssi-sdk/credential/manifest"
	errresp "github.com/TBD54566975/ssi-sdk/error"
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
// is a valid credential application, and complies with its corresponding manifest. it returns the ids of unfulfilled
// input descriptors along with an error if validation fails.
func (s Service) validateCredentialApplication(credManifest manifest.CredentialManifest, request SubmitApplicationRequest) (inputDescriptorIDs []string, err error) {
	// validate the payload's signature
	if verificationErr := s.verifyApplicationJWT(request.ApplicantDID, request.ApplicationJWT); verificationErr != nil {
		errMsg := fmt.Sprintf("could not verify application<%s>'s signature", request.Application.ID)
		err = util.LoggingErrorMsg(err, errMsg)
		return
	}

	// validate the application
	credApp := request.Application
	if credErr := credApp.IsValid(); credErr != nil {
		err = util.LoggingErrorMsg(credErr, "application is not valid")
		return
	}

	// next, validate that the credential(s) provided in the application are valid
	unfulfilledInputDescriptorIDs, validationErr := manifest.IsValidCredentialApplicationForManifest(credManifest, request.ApplicationJSON)
	if validationErr != nil {
		resp := errresp.GetErrorResponse(validationErr)
		// a valid error response means this is an application level error, and we should return a credential denial
		if resp.Valid {
			if len(unfulfilledInputDescriptorIDs) > 0 {
				var reasons []string
				for id, reason := range unfulfilledInputDescriptorIDs {
					inputDescriptorIDs = append(inputDescriptorIDs, id)
					reasons = append(reasons, fmt.Sprintf("%s: %s", id, reason))
				}
				err = errresp.NewErrorResponsef(DenialResponse, "unfilled input descriptor(s): %s", strings.Join(reasons, ", "))
				return
			}
			err = errresp.NewErrorResponseWithError(DenialResponse, resp.Err)
			return
		}

		// otherwise, we have an internal error and  set the error to the value of the errResp's error
		errMsg := fmt.Sprintf("could not validate application: %s", credApp.ID)
		err = util.LoggingErrorMsg(resp.Err, errMsg)
		return
	}

	// signature and validity checks for each credential submitted with the application
	for _, credentialContainer := range request.Credentials {
		verificationResult, verificationErr := s.credential.VerifyCredential(credential.VerifyCredentialRequest{
			DataIntegrityCredential: credentialContainer.Credential,
			CredentialJWT:           credentialContainer.CredentialJWT,
		})

		if verificationErr != nil {
			errMsg := fmt.Sprintf("could not verify credential: %s", credentialContainer.Credential.ID)
			err = util.LoggingNewError(errMsg)
			return
		}

		if !verificationResult.Verified {
			errMsg := fmt.Sprintf("submitted credential<%s> is not valid: %s", credentialContainer.Credential.ID, verificationResult.Reason)
			err = util.LoggingNewError(errMsg)
			return
		}
	}
	return
}
