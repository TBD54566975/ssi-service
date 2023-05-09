package manifest

import (
	"context"
	"fmt"
	"strings"
	"time"

	credsdk "github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/credential/manifest"
	errresp "github.com/TBD54566975/ssi-sdk/error"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/oliveagle/jsonpath"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	cred "github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/pkg/service/credential"
	"github.com/tbd54566975/ssi-service/pkg/service/issuing"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	"github.com/tbd54566975/ssi-service/pkg/service/manifest/model"
)

const (
	// DenialResponse is an error response corresponding to a credential denial
	DenialResponse errresp.Type = "DenialResponse"
)

func (s Service) signCredentialResponse(ctx context.Context, issuerKID string, r CredentialResponseContainer) (*keyaccess.JWT, error) {
	gotKey, err := s.keyStore.GetKey(ctx, keystore.GetKeyRequest{ID: issuerKID})
	if err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "getting key for signing response with key<%s>", issuerKID)
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
	applicantDID, manifestID, issuerKID string, credManifest manifest.CredentialManifest,
	template issuing.IssuanceTemplate, application manifest.CredentialApplication,
	applicationJSON map[string]any) (*manifest.CredentialResponse, []cred.Container, error) {
	if template.IsValid() {
		return nil, nil, errors.New("issuance template is not valid")
	}

	templateMap := make(map[string]issuing.CredentialTemplate)
	issuingKID := issuerKID
	if template.IssuerKID != "" {
		issuingKID = template.IssuerKID
	}
	for _, templateCred := range template.Credentials {
		templateCred := templateCred
		templateMap[templateCred.ID] = templateCred
	}
	return s.fulfillmentCredentialResponse(ctx, application.ID, applicantDID, manifestID, issuingKID, credManifest, &application, templateMap, applicationJSON, nil)
}

// buildFulfillmentCredentialResponseFromOverrides builds a credential response from overrides
func (s Service) buildFulfillmentCredentialResponse(ctx context.Context, applicantDID, applicationID, manifestID, issuerKID string,
	credManifest manifest.CredentialManifest, overrides map[string]model.CredentialOverride) (*manifest.CredentialResponse, []cred.Container, error) {
	return s.fulfillmentCredentialResponse(ctx, applicationID, applicantDID, manifestID, issuerKID, credManifest, nil, nil, nil, overrides)
}

// TODO(gabe) add applicant id to response once https://github.com/TBD54566975/ssi-sdk/issues/372 is in
// unifies both templated and override paths for building a credential response
func (s Service) fulfillmentCredentialResponse(ctx context.Context,
	applicationID, applicantDID, manifestID, issuerKID string, credManifest manifest.CredentialManifest,
	application *manifest.CredentialApplication,
	templateMap map[string]issuing.CredentialTemplate,
	applicationJSON map[string]any,
	credentialOverrides map[string]model.CredentialOverride) (*manifest.CredentialResponse, []cred.Container, error) {
	responseBuilder := manifest.NewCredentialResponseBuilder(manifestID)
	if err := responseBuilder.SetApplicationID(applicationID); err != nil {
		return nil, nil, sdkutil.LoggingErrorMsgf(err, "could not fulfill credential credentials: could not set credentials id: %s", applicationID)
	}

	creds := make([]cred.Container, 0, len(credManifest.OutputDescriptors))
	for _, od := range credManifest.OutputDescriptors {
		createCredentialRequest := credential.CreateCredentialRequest{
			Issuer:    credManifest.Issuer.ID,
			IssuerKID: issuerKID,
			Subject:   applicantDID,
			SchemaID:  od.Schema,
			// TODO(gabe) need to add in data here to match the request + schema
			Data: make(map[string]any),
		}

		// apply issuance template and then overrides
		if len(templateMap) != 0 {
			templatedCredentialRequest, err := s.applyIssuanceTemplate(createCredentialRequest, templateMap, od, applicationJSON, credManifest, *application.PresentationSubmission)
			if err != nil {
				return nil, nil, err
			}
			createCredentialRequest = *templatedCredentialRequest
		}
		if len(credentialOverrides) != 0 {
			createCredentialRequest = s.applyCredentialOverrides(createCredentialRequest, credentialOverrides, od)
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
			ID:     c.ID,
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

func (s Service) applyIssuanceTemplate(credentialRequest credential.CreateCredentialRequest,
	templateMap map[string]issuing.CredentialTemplate, od manifest.OutputDescriptor,
	applicationJSON map[string]any, credManifest manifest.CredentialManifest, submission exchange.PresentationSubmission) (*credential.CreateCredentialRequest, error) {
	ct, ok := templateMap[od.ID]
	if !ok {
		logrus.Warnf("Did not find output_descriptor with ID \"%s\" in template. Skipping application.", od.ID)
		return nil, nil
	}
	c, err := getCredentialJSON(applicationJSON, ct, credManifest, submission)
	if err != nil {
		return nil, err
	}
	for k, v := range ct.Data {
		claimValue := v
		if vs, ok := v.(string); ok {
			if strings.HasPrefix(vs, "$") {
				claimValue, err = jsonpath.JsonPathLookup(c, vs)
				if err != nil {
					return nil, errors.Wrapf(err, "looking up json path \"%s\" for key=\"%s\"", vs, k)
				}
			}
		}
		credentialRequest.Data[k] = claimValue
	}

	if ct.Expiry.Time != nil {
		credentialRequest.Expiry = ct.Expiry.Time.Format(time.RFC3339)
	}

	if ct.Expiry.Duration != nil {
		credentialRequest.Expiry = s.Clock.Now().Add(*ct.Expiry.Duration).Format(time.RFC3339)
	}

	credentialRequest.Revocable = ct.Revocable
	return &credentialRequest, nil
}

func (s Service) applyCredentialOverrides(credentialRequest credential.CreateCredentialRequest, credentialOverrides map[string]model.CredentialOverride, od manifest.OutputDescriptor) credential.CreateCredentialRequest {
	if credentialOverride, ok := credentialOverrides[od.ID]; ok {
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
	}
	return credentialRequest
}

func getCredentialJSON(applicationJSON map[string]any, ct issuing.CredentialTemplate,
	credManifest manifest.CredentialManifest, submission exchange.PresentationSubmission) (any, error) {
	if ct.CredentialInputDescriptor == "" {
		return nil, errors.New("cannot provide input descriptor when credential template does not have input descriptor")
	}

	if credManifest.PresentationDefinition.IsEmpty() {
		return nil, errors.New("cannot provide input descriptor when manifest does not have presentation definition")
	}

	// Lookup the claim that's sent in the submission.
	for _, descriptor := range submission.DescriptorMap {
		if descriptor.ID == ct.CredentialInputDescriptor {
			c, err := jsonpath.JsonPathLookup(applicationJSON, descriptor.Path)
			if err != nil {
				return nil, errors.Wrapf(err, "looking up json path \"%s\" for submission=\"%s\"", descriptor.Path, descriptor.ID)
			}
			return credsdk.ToCredentialJSONMap(c)
		}
	}
	return nil, errors.Errorf("could not find credential for input_descriptor=\"%s\"", ct.CredentialInputDescriptor)
}

// TODO(gabe) add applicant to response id once https://github.com/TBD54566975/ssi-sdk/issues/372 is in
func buildDenialCredentialResponse(manifestID, applicationID, reason string, failedOutputDescriptorIDs ...string) (*manifest.CredentialResponse, error) {
	builder := manifest.NewCredentialResponseBuilder(manifestID)
	if err := builder.SetApplicationID(applicationID); err != nil {
		return nil, err
	}
	if err := builder.SetDenial(reason, failedOutputDescriptorIDs...); err != nil {
		return nil, err
	}
	return builder.Build()
}
