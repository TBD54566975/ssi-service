package manifest

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/credential/manifest"
	"github.com/TBD54566975/ssi-sdk/credential/parsing"
	"github.com/TBD54566975/ssi-sdk/did"
	errresp "github.com/TBD54566975/ssi-sdk/error"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/oliveagle/jsonpath"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	cred "github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/pkg/service/credential"
	"github.com/tbd54566975/ssi-service/pkg/service/issuance"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	"github.com/tbd54566975/ssi-service/pkg/service/manifest/model"
)

const (
	// DenialResponse is an error response corresponding to a credential denial
	DenialResponse errresp.Type = "DenialResponse"
)

func (s Service) signCredentialResponse(ctx context.Context, keyStoreID string, r CredentialResponseContainer) (*keyaccess.JWT, error) {
	gotKey, err := s.keyStore.GetKey(ctx, keystore.GetKeyRequest{ID: keyStoreID})
	if err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "getting key for signing response with key<%s>", keyStoreID)
	}
	if gotKey.Revoked {
		return nil, sdkutil.LoggingNewErrorf("cannot use revoked key<%s>", gotKey.ID)
	}
	keyAccess, err := keyaccess.NewJWKKeyAccess(gotKey.Controller, gotKey.ID, gotKey.Key)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "creating key access for signing response with key<%s>", gotKey.ID)
	}

	// signing the response as a JWT
	responseToken, err := keyAccess.SignJSON(r)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "could not sign response with key<%s>", gotKey.ID)
	}
	return responseToken, nil
}

// buildFulfillmentCredentialResponseFromTemplate builds a credential response from a template
func (s Service) buildFulfillmentCredentialResponseFromTemplate(ctx context.Context,
	applicantDID, manifestID, fullyQualifiedVerificationMethodID string, credManifest manifest.CredentialManifest,
	template issuance.Template, application manifest.CredentialApplication,
	applicationJSON map[string]any) (*manifest.CredentialResponse, []cred.Container, error) {
	if err := template.IsValid(); err != nil {
		return nil, nil, errors.Wrap(err, "validating template")
	}

	templateMap := make(map[string]issuance.CredentialTemplate)
	qualifiedVerificationMethodID := fullyQualifiedVerificationMethodID
	if template.VerificationMethodID != "" {
		qualifiedVerificationMethodID = did.FullyQualifiedVerificationMethodID(template.Issuer, template.VerificationMethodID)
	}
	for _, templateCred := range template.Credentials {
		templateCred := templateCred
		templateMap[templateCred.ID] = templateCred
	}

	responseBuilder := manifest.NewCredentialResponseBuilder(manifestID)
	if err := responseBuilder.SetApplicationID(application.ID); err != nil {
		return nil, nil, sdkutil.LoggingErrorMsgf(err, "could not fulfill credential application<%s> from template", application.ID)
	}
	if err := responseBuilder.SetApplicantID(applicantDID); err != nil {
		return nil, nil, sdkutil.LoggingErrorMsgf(err, "could not fulfill credential application<%s> from template", application.ID)
	}

	return s.fulfillmentCredentialResponse(ctx, responseBuilder, applicantDID, qualifiedVerificationMethodID, credManifest, &application, templateMap, applicationJSON, nil)
}

// buildFulfillmentCredentialResponseFromOverrides builds a credential response from overrides
func (s Service) buildFulfillmentCredentialResponse(ctx context.Context, applicantDID, applicationID, manifestID, fullyQualifiedVerificationMethodID string,
	credManifest manifest.CredentialManifest, overrides map[string]model.CredentialOverride) (*manifest.CredentialResponse, []cred.Container, error) {

	responseBuilder := manifest.NewCredentialResponseBuilder(manifestID)
	if err := responseBuilder.SetApplicationID(applicationID); err != nil {
		return nil, nil, sdkutil.LoggingErrorMsgf(err, "could not fulfill credential application<%s>", applicationID)
	}
	if err := responseBuilder.SetApplicantID(applicantDID); err != nil {
		return nil, nil, sdkutil.LoggingErrorMsgf(err, "could not fulfill credential application<%s>", applicationID)
	}

	return s.fulfillmentCredentialResponse(ctx, responseBuilder, applicantDID, fullyQualifiedVerificationMethodID, credManifest, nil, nil, nil, overrides)
}

// unifies both templated and override paths for building a credential response
func (s Service) fulfillmentCredentialResponse(ctx context.Context, responseBuilder manifest.CredentialResponseBuilder,
	applicantDID, fullyQualifiedVerificationMethodID string, credManifest manifest.CredentialManifest, application *manifest.CredentialApplication,
	templateMap map[string]issuance.CredentialTemplate, applicationJSON map[string]any,
	credentialOverrides map[string]model.CredentialOverride) (*manifest.CredentialResponse, []cred.Container, error) {

	creds := make([]cred.Container, 0, len(credManifest.OutputDescriptors))
	for _, od := range credManifest.OutputDescriptors {
		createCredentialRequest := credential.CreateCredentialRequest{
			Issuer:                             credManifest.Issuer.ID,
			FullyQualifiedVerificationMethodID: fullyQualifiedVerificationMethodID,
			Subject:                            applicantDID,
			SchemaID:                           od.Schema,
			// TODO(gabe) need to add in data here to match the request + schema
			Data: make(map[string]any),
		}

		// apply issuance template and then overrides
		if len(templateMap) != 0 {
			template, ok := templateMap[od.ID]
			if !ok {
				logrus.Warnf("Did not find output_descriptor with ID \"%s\" in template. Skipping application.", od.ID)
				continue
			}
			templatedCredentialRequest, err := s.applyIssuanceTemplate(createCredentialRequest, template, applicationJSON, credManifest, *application.PresentationSubmission)
			if err != nil {
				return nil, nil, err
			}
			createCredentialRequest = *templatedCredentialRequest
		}
		if len(credentialOverrides) != 0 {
			if credentialOverride, ok := credentialOverrides[od.ID]; ok {
				createCredentialRequest = s.applyCredentialOverrides(createCredentialRequest, credentialOverride)
			} else {
				logrus.Warnf("Did not find output_descriptor with ID \"%s\" in overrides. Skipping overrides.", od.ID)
			}
		}

		credentialResponse, err := s.credential.CreateCredential(ctx, createCredentialRequest)
		if err != nil {
			return nil, nil, sdkutil.LoggingErrorMsg(err, "could not create credential")
		}
		creds = append(creds, credentialResponse.Container)
	}

	// build descriptor map based on credential type
	descriptors := make([]exchange.SubmissionDescriptor, 0, len(creds))
	for i, c := range creds {
		var format string
		if c.HasDataIntegrityCredential() {
			format = string(exchange.LDPVC)
		}
		if c.HasJWTCredential() {
			format = string(exchange.JWTVC)
		}
		descriptors = append(descriptors, exchange.SubmissionDescriptor{
			ID:     c.Credential.ID,
			Format: format,
			Path:   fmt.Sprintf("$.verifiableCredentials[%d]", i),
		})
	}

	// set the information for the fulfilled credentials in the response
	if err := responseBuilder.SetFulfillment(descriptors); err != nil {
		return nil, nil, sdkutil.LoggingErrorMsg(err, "could not fulfill credential credentials: could not set fulfillment")
	}
	credRes, err := responseBuilder.Build()
	if err != nil {
		return nil, nil, sdkutil.LoggingErrorMsg(err, "could not build response")
	}
	return credRes, creds, nil
}

func (s Service) applyIssuanceTemplate(credentialRequest credential.CreateCredentialRequest, template issuance.CredentialTemplate,
	applicationJSON map[string]any, credManifest manifest.CredentialManifest, submission exchange.PresentationSubmission) (*credential.CreateCredentialRequest, error) {
	credentialForInputDescriptor, err := getCredentialForInputDescriptor(applicationJSON, template.CredentialInputDescriptor, credManifest, submission)
	if err != nil {
		return nil, err
	}
	for k, v := range template.Data {
		claimValue := v
		if vs, ok := v.(string); ok {
			if strings.HasPrefix(vs, "$") {
				claimValue, err = jsonpath.JsonPathLookup(credentialForInputDescriptor, vs)
				if err != nil {
					return nil, errors.Wrapf(err, "looking up json path \"%s\" for key=\"%s\"", vs, k)
				}
			}
		}
		credentialRequest.Data[k] = claimValue
	}

	if template.Expiry.Time != nil {
		credentialRequest.Expiry = template.Expiry.Time.Format(time.RFC3339)
	}

	if template.Expiry.Duration != nil {
		credentialRequest.Expiry = s.Clock.Now().Add(*template.Expiry.Duration).Format(time.RFC3339)
	}

	credentialRequest.Revocable = template.Revocable
	return &credentialRequest, nil
}

// applyCredentialOverrides applies the overrides to the credential request
func (s Service) applyCredentialOverrides(credentialRequest credential.CreateCredentialRequest, credentialOverride model.CredentialOverride) credential.CreateCredentialRequest {
	for k, v := range credentialOverride.Data {
		if len(credentialRequest.Data) == 0 {
			credentialRequest.Data = make(map[string]any)
		}
		credentialRequest.Data[k] = v
	}

	if credentialOverride.Expiry != nil {
		credentialRequest.Expiry = credentialOverride.Expiry.Format(time.RFC3339)
	}
	credentialRequest.Revocable = credentialOverride.Revocable
	return credentialRequest
}

// getCredentialForInputDescriptor returns the credential as JSON for the given input descriptor.
func getCredentialForInputDescriptor(applicationJSON map[string]any, templateInputDescriptorID string,
	credManifest manifest.CredentialManifest, submission exchange.PresentationSubmission) (map[string]any, error) {
	if templateInputDescriptorID == "" {
		return nil, errors.New("cannot provide input descriptor when the credential template does not have input descriptor")
	}

	if credManifest.PresentationDefinition.IsEmpty() {
		return nil, errors.New("cannot provide input descriptor when the manifest does not have presentation definition")
	}

	// Lookup the claim that's sent in the submission.
	for _, descriptor := range submission.DescriptorMap {
		if descriptor.ID == templateInputDescriptorID {
			c, err := jsonpath.JsonPathLookup(applicationJSON, descriptor.Path)
			if err != nil {
				return nil, errors.Wrapf(err, "looking up json path \"%s\" for submission=\"%s\"", descriptor.Path, descriptor.ID)
			}

			return toCredentialJSON(c)
		}
	}
	return nil, errors.Errorf("could not find credential for input_descriptor=\"%s\"", templateInputDescriptorID)
}

func toCredentialJSON(c any) (map[string]any, error) {
	_, _, genericCredential, err := parsing.ToCredential(c)
	if err != nil {
		return nil, errors.Wrapf(err, "converting credential to json")
	}
	credBytes, err := json.Marshal(genericCredential)
	if err != nil {
		return nil, errors.Wrapf(err, "marshalling credential to json")
	}
	var credJSON map[string]any
	if err = json.Unmarshal(credBytes, &credJSON); err != nil {
		return nil, errors.Wrapf(err, "unmarshalling credential to json")
	}
	return credJSON, nil
}

// TODO(gabe) add applicant to response id once https://github.com/TBD54566975/ssi-sdk/issues/372 is in
func buildDenialCredentialResponse(manifestID, applicantDID, applicationID, reason string, failedOutputDescriptorIDs ...string) (*manifest.CredentialResponse, error) {
	builder := manifest.NewCredentialResponseBuilder(manifestID)
	if err := builder.SetApplicationID(applicationID); err != nil {
		return nil, err
	}
	if err := builder.SetApplicantID(applicantDID); err != nil {
		return nil, err
	}
	if err := builder.SetDenial(reason, failedOutputDescriptorIDs...); err != nil {
		return nil, err
	}
	return builder.Build()
}
