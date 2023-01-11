package manifest

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/credential/manifest"
	errresp "github.com/TBD54566975/ssi-sdk/error"
	"github.com/oliveagle/jsonpath"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	cred "github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/service/credential"
	"github.com/tbd54566975/ssi-service/pkg/service/issuing"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
)

const (
	// DenialResponse is an error response corresponding to a credential denial
	DenialResponse errresp.Type = "DenialResponse"
)

func (s Service) signCredentialResponseJWT(ctx context.Context, signingDID string, r CredentialResponseContainer) (*keyaccess.JWT, error) {
	gotKey, err := s.keyStore.GetKey(ctx, keystore.GetKeyRequest{ID: signingDID})
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get key for signing response with key<%s>", signingDID)
	}
	keyAccess, err := keyaccess.NewJWKKeyAccess(gotKey.ID, gotKey.Key)
	if err != nil {
		return nil, util.LoggingErrorMsgf(
			err,
			"could not create key access for signing response with key<%s>",
			gotKey.ID,
		)
	}

	// signing the response as a JWT
	responseToken, err := keyAccess.SignJSON(r)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not sign response with key<%s>", gotKey.ID)
	}
	return responseToken, nil
}

func (s Service) buildCredentialResponse(
	ctx context.Context, applicantDID, manifestID string,
	credManifest manifest.CredentialManifest,
	approved bool,
	reason string,
	template *issuing.IssuanceTemplate,
	application manifest.CredentialApplication,
	applicationJSON map[string]any,
) (*manifest.CredentialResponse, []cred.Container, error) {
	// TODO(gabe) need to check if this can be fulfilled and conditionally return success/denial
	applicationID := application.ID
	responseBuilder := manifest.NewCredentialResponseBuilder(manifestID)
	if err := responseBuilder.SetApplicationID(applicationID); err != nil {
		return nil, nil, util.LoggingErrorMsgf(
			err,
			"could not fulfill credential credentials: could not set credentials id: %s",
			applicationID,
		)
	}

	templateMap := make(map[string]*issuing.CredentialTemplate)
	if template != nil {
		for _, v := range template.Credentials {
			v := v
			templateMap[v.ID] = &v
		}
	}
	creds := make([]cred.Container, 0, len(credManifest.OutputDescriptors))
	for _, od := range credManifest.OutputDescriptors {
		credentialRequest := credential.CreateCredentialRequest{
			Issuer:     credManifest.Issuer.ID,
			Subject:    applicantDID,
			JSONSchema: od.Schema,
			// TODO(gabe) need to add in data here to match the request + schema
			Data: make(map[string]any),
		}
		if template != nil {
			err := applyIssuanceTemplate(
				&credentialRequest,
				template,
				templateMap,
				od,
				applicationJSON,
				credManifest,
				application,
			)
			if err != nil {
				return nil, nil, err
			}
		}

		credentialResponse, err := s.credential.CreateCredential(ctx, credentialRequest)
		if err != nil {
			return nil, nil, util.LoggingErrorMsg(err, "could not create credential")
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
		descriptors = append(
			descriptors, exchange.SubmissionDescriptor{
				ID:     c.ID,
				Format: format,
				Path:   fmt.Sprintf("$.verifiableCredentials[%d]", i),
			},
		)
	}

	// set the information for the fulfilled credentials in the response
	if approved {
		if err := responseBuilder.SetFulfillment(descriptors); err != nil {
			return nil, nil, util.LoggingErrorMsg(
				err,
				"could not fulfill credential credentials: could not set fulfillment",
			)
		}
	} else {
		if err := responseBuilder.SetDenial(reason); err != nil {
			return nil, nil, errors.Wrap(err, "setting denial")
		}
	}
	credRes, err := responseBuilder.Build()
	if err != nil {
		return nil, nil, util.LoggingErrorMsg(err, "could not build response")
	}
	return credRes, creds, nil
}

func applyIssuanceTemplate(
	credentialRequest *credential.CreateCredentialRequest,
	template *issuing.IssuanceTemplate,
	templateMap map[string]*issuing.CredentialTemplate,
	od manifest.OutputDescriptor,
	applicationJSON map[string]any,
	credManifest manifest.CredentialManifest,
	application manifest.CredentialApplication,
) error {
	credentialRequest.Issuer = template.Issuer

	ct, ok := templateMap[od.ID]
	if !ok {
		logrus.Warnf("Did not find output_descriptor with ID \"%s\" in template. Skipping application.", od.ID)
		return nil
	}
	c, err := getCredential(applicationJSON, ct, credManifest, application.PresentationSubmission)
	if err != nil {
		return err
	}
	for k, v := range ct.Data.Claims.Data {
		claimValue := v
		switch vs := v.(type) {
		case string:
			if strings.HasPrefix(vs, "$") {
				claimValue, err = jsonpath.JsonPathLookup(c, vs)
				if err != nil {
					return errors.Wrapf(err, "looking up json path \"%s\" for key=\"%s\"", vs, k)
				}
			}
		}
		credentialRequest.Data[k] = claimValue
	}

	if ct.Expiry.Time != nil {
		credentialRequest.Expiry = ct.Expiry.Time.Format(time.RFC3339)
	}

	if ct.Expiry.Duration != nil {
		credentialRequest.Expiry = time.Now().Add(*ct.Expiry.Duration).Format(time.RFC3339)
	}

	credentialRequest.Revocable = ct.Revocable
	return nil
}

func getCredential(
	applicationJSON map[string]any,
	ct *issuing.CredentialTemplate,
	credManifest manifest.CredentialManifest,
	submission *exchange.PresentationSubmission,
) (any, error) {
	if ct.Data.CredentialInputDescriptor != "" {
		if credManifest.PresentationDefinition == nil {
			return nil, errors.New("cannot provide input descriptor when manifest does not have presentation definition")
		}

		// Lookup the claim that's sent in the submission.
		for _, descriptor := range submission.DescriptorMap {
			if descriptor.ID == ct.Data.CredentialInputDescriptor {
				c, err := jsonpath.JsonPathLookup(applicationJSON, descriptor.Path)
				if err != nil {
					return nil, errors.Wrapf(
						err,
						"looking up json path \"%s\" for submission=\"%s\"",
						descriptor.Path,
						descriptor.ID,
					)
				}
				claim, err := fromFormat(exchange.JWTFormat(descriptor.Format), c)
				if err != nil {
					return nil, err
				}
				return claim, nil
			}
		}
		return nil, errors.Errorf(
			"could not find credential for input_descriptor=\"%s\"",
			ct.Data.CredentialInputDescriptor,
		)
	}
	return nil, nil
}

func fromFormat(format exchange.JWTFormat, claim any) (any, error) {
	switch format {
	case exchange.JWTVC:
		_, token, err := util.ParseJWT(keyaccess.JWT(claim.(string)))
		if err != nil {
			return nil, errors.Wrapf(err, "parsing jwt as %s", exchange.JWTVC)
		}
		return token.PrivateClaims()["vc"], nil
	default:
		return nil, errors.Errorf("unsupported format %s", format)
	}
}

func buildDenialCredentialResponse(
	manifestID, applicationID, reason string,
	failedOutputDescriptorIDs ...string,
) (*manifest.CredentialResponse, error) {
	builder := manifest.NewCredentialResponseBuilder(manifestID)
	if err := builder.SetApplicationID(applicationID); err != nil {
		return nil, err
	}
	if err := builder.SetDenial(reason, failedOutputDescriptorIDs...); err != nil {
		return nil, err
	}
	return builder.Build()
}
