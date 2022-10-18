package manifest

import (
	"fmt"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/credential/manifest"
	"github.com/goccy/go-json"

	cred "github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/service/credential"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
)

func (s Service) signResponseJWT(signingDID string, r CredentialResponseContainer) (*keyaccess.JWT, error) {
	id := r.Response.ID
	gotKey, err := s.keyStore.GetKey(keystore.GetKeyRequest{ID: signingDID})
	if err != nil {
		errMsg := fmt.Sprintf("could not get key for signing response with key<%s>", signingDID)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	keyAccess, err := keyaccess.NewJWKKeyAccess(gotKey.ID, gotKey.Key)
	if err != nil {
		errMsg := fmt.Sprintf("could not create key access for signing response with key<%s>", gotKey.ID)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	// marshal the response before signing it as a JWT
	responseBytes, err := json.Marshal(r)
	if err != nil {
		errMsg := fmt.Sprintf("could not marshal response<%s>", id)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	responseJSON := make(map[string]interface{})
	if err = json.Unmarshal(responseBytes, &responseJSON); err != nil {
		errMsg := fmt.Sprintf("could not unmarshal response<%s>", id)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	responseToken, err := keyAccess.Sign(responseJSON)
	if err != nil {
		errMsg := fmt.Sprintf("could not sign response with key<%s>", gotKey.ID)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	return responseToken, nil
}

func (s Service) buildCredentialResponse(applicantDID, manifestID, applicationID string, credManifest manifest.CredentialManifest) (*manifest.CredentialResponse, []cred.Container, error) {
	// TODO(gabe) need to check if this can be fulfilled and conditionally return success/denial
	responseBuilder := manifest.NewCredentialResponseBuilder(manifestID)
	if err := responseBuilder.SetApplicationID(applicationID); err != nil {
		errMsg := fmt.Sprintf("could not fulfill credential application: could not set application id: %s", applicationID)
		return nil, nil, util.LoggingErrorMsg(err, errMsg)
	}

	var creds []cred.Container
	for _, od := range credManifest.OutputDescriptors {
		credentialRequest := credential.CreateCredentialRequest{
			Issuer:     credManifest.Issuer.ID,
			Subject:    applicantDID,
			JSONSchema: od.Schema,
			// TODO(gabe) need to add in data here to match the request + schema
			Data: make(map[string]interface{}),
		}

		credentialResponse, err := s.credential.CreateCredential(credentialRequest)
		if err != nil {
			return nil, nil, util.LoggingErrorMsg(err, "could not create credential")
		}

		creds = append(creds, credentialResponse.Container)
	}

	// build descriptor map based on credential type
	var descriptors []exchange.SubmissionDescriptor
	for i, c := range creds {
		var format string
		if c.HasDataIntegrityCredential() {
			format = string(exchange.LDPVC)
		}
		if c.HasJWTCredential() {
			format = string(exchange.JWTVC)
		}
		descriptors = append(descriptors, exchange.SubmissionDescriptor{
			ID:     c.ID,
			Format: format,
			Path:   fmt.Sprintf("$.verifiableCredentials[%d]", i),
		})
	}

	// set the information for the fulfilled credentials in the response
	if err := responseBuilder.SetFulfillment(descriptors); err != nil {
		return nil, nil, util.LoggingErrorMsg(err, "could not fulfill credential application: could not set fulfillment")
	}
	credRes, err := responseBuilder.Build()
	if err != nil {
		return nil, nil, util.LoggingErrorMsg(err, "could not build response")
	}
	return credRes, creds, nil
}

func buildDenialCredentialResponse(manifestID, applicationID, reason string, failedOutputDescriptorIDs ...string) (*manifest.CredentialResponse, error) {
	builder := manifest.NewCredentialResponseBuilder(manifestID)
	if err := builder.SetApplicationID(applicationID); err != nil {
		return nil, err
	}
	if err := builder.SetDenial(reason, failedOutputDescriptorIDs); err != nil {
		return nil, err
	}
	return builder.Build()
}
