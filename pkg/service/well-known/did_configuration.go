package wellknown

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/integrity"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/resolution"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	credint "github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/util"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

type DIDConfigurationService struct {
	keyStoreService *keystore.Service
	validator       *credint.Validator

	HTTPClient *http.Client
}

func NewDIDConfigurationService(keyStoreService *keystore.Service, didResolver resolution.Resolver, schema *schema.Service) (*DIDConfigurationService, error) {
	client := &http.Client{Transport: otelhttp.NewTransport(http.DefaultTransport)}
	validator, err := credint.NewCredentialValidator(didResolver, schema)
	if err != nil {
		return nil, errors.Wrap(err, "could not instantiate validator for the credential service")
	}

	return &DIDConfigurationService{
		keyStoreService: keyStoreService,
		validator:       validator,
		HTTPClient:      client,
	}, nil
}

func (s DIDConfigurationService) Type() svcframework.Type {
	return svcframework.DIDConfiguration
}

func (s DIDConfigurationService) Status() svcframework.Status {
	return svcframework.Status{
		Status: svcframework.StatusReady,
	}
}

var _ svcframework.Service = (*DIDConfigurationService)(nil)

func (s DIDConfigurationService) VerifyDIDConfiguration(ctx context.Context, req *VerifyDIDConfigurationRequest) (*VerifyDIDConfigurationResponse, error) {
	location := req.Origin + DIDConfigurationLocationSuffix
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return nil, errors.Wrap(err, "creating http request")
	}
	if httpReq.URL.Scheme != "https" {
		return nil, errors.Errorf("origin expected to be https but got %s", req.Origin)
	}

	httpResponse, err := s.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, errors.Wrap(err, "performing http request")
	}
	defer func() {
		_ = httpResponse.Body.Close()
	}()

	if !util.Is2xxResponse(httpResponse.StatusCode) {
		return nil, errors.Errorf("expected 2xx code, got %d", httpResponse.StatusCode)
	}

	bodyCopy := new(bytes.Buffer)
	bodyTeeReader := io.TeeReader(httpResponse.Body, bodyCopy)

	var didConfiguration DIDConfiguration
	if err := json.NewDecoder(bodyTeeReader).Decode(&didConfiguration); err != nil {
		return nil, errors.Wrap(err, "decoding body")
	}

	response := VerifyDIDConfigurationResponse{
		DIDConfiguration: bodyCopy.String(),
	}
	for _, domainLinkageCredential := range didConfiguration.LinkedDIDs {
		// For a Domain Linkage Credential to be deemed valid, it MUST be successfully processed in accordance with the following steps:
		//
		// 1. The credentialSubject.id MUST be a DID, and the value MUST be equal to both the Subject and Issuer of the Domain Linkage Credential.
		credentialSubjectID := domainLinkageCredential.Credential.CredentialSubject["id"].(string)
		if !strings.HasPrefix(credentialSubjectID, "did:") {
			response.Reason = fmt.Sprintf("The credentialSubject.id MUST be a DID, but got <%s>", credentialSubjectID)
			return &response, nil
		}

		if credentialSubjectID != domainLinkageCredential.Credential.IssuerID() {
			response.Reason = fmt.Sprintf("The credentialSubject.id MUST be equal to both the Subject and Issuer of the Domain Linkage Credential")
			return &response, nil
		}

		// 2. The Domain Linkage Credential must be in either a Linked Data Proof Format or JSON Web Token Proof Format
		if !domainLinkageCredential.HasSignedCredential() {
			response.Reason = fmt.Sprintf("The Domain Linkage Credential must be in either a Linked Data Proof Format or JSON Web Token Proof Format")
			return &response, nil
		}

		// 3. The credentialSubject.origin property MUST be present, and its value MUST match the origin the resource was requested from.
		credentialSubjectOrigin := domainLinkageCredential.Credential.CredentialSubject["origin"].(string)
		requestedURL := httpReq.URL.String()
		if !originMatches(requestedURL, credentialSubjectOrigin) {
			response.Reason = fmt.Sprintf("The credentialSubject.origin property MUST be present, and its value MUST match the origin the resource was requested from")
			return &response, nil
		}

		// 4. The implementer MUST perform DID resolution on the DID specified in the Issuer of the Domain Linkage Credential to obtain the associated DID document.
		// 5. Using the retrieved DID document, the implementer MUST validate the signature of the Domain Linkage Credential against key material referenced in the assertionMethod section of the DID document.
		if err := s.validator.Verify(ctx, domainLinkageCredential); err != nil {
			response.Reason = err.Error()
			return &response, nil
		}

		// 6. If Domain Linkage Credential verification is successfull, a Verifier SHOULD consider the entity controlling the origin and the Controller of the DID to be the same entity.
	}

	response.Verified = true
	return &response, nil
}

func originMatches(requestedURL string, credentialSubjectOrigin string) bool {
	return strings.Contains(requestedURL, credentialSubjectOrigin)
}

func (s DIDConfigurationService) CreateDIDConfiguration(ctx context.Context, req *CreateDIDConfigurationRequest) (*CreateDIDConfigurationResponse, error) {
	builder := credential.NewVerifiableCredentialBuilder()
	if err := builder.SetIssuer(req.IssuerDID); err != nil {
		return nil, errors.Wrap(err, "setting issuer")
	}

	subjectData := map[string]interface{}{
		"id":     req.IssuerDID,
		"origin": req.Origin,
	}

	subject := credential.CredentialSubject(subjectData)
	if err := builder.SetCredentialSubject(subject); err != nil {
		return nil, errors.Wrap(err, "setting credentialSubject")
	}

	if err := builder.AddContext(DIDConfigurationContext); err != nil {
		return nil, errors.Wrap(err, "adding context")
	}

	if err := builder.SetID(""); err != nil {
		return nil, errors.Wrap(err, "setting empty id")
	}

	if err := builder.SetExpirationDate(req.ExpirationDate); err != nil {
		return nil, errors.Wrap(err, "setting expirationDate")
	}

	issuanceDate := req.IssuanceDate
	if issuanceDate == "" {
		issuanceDate = time.Now().Format(time.RFC3339)
	}
	if err := builder.SetIssuanceDate(issuanceDate); err != nil {
		return nil, errors.Wrap(err, "setting issuanceDate")
	}

	if err := builder.AddType("DomainLinkageCredential"); err != nil {
		return nil, errors.Wrap(err, "adding type")
	}
	unsignedLinkageCredential, err := builder.Build()
	if err != nil {
		return nil, errors.Wrap(err, "building credential")
	}

	jwtClaimSet, err := integrity.JWTClaimSetFromVC(*unsignedLinkageCredential)
	if err != nil {
		return nil, errors.Wrap(err, "gathering jwt claimset from VC")
	}

	keyStoreID := did.FullyQualifiedVerificationMethodID(req.IssuerDID, req.VerificationMethodID)
	signedLinkageCredential, err := s.keyStoreService.Sign(ctx, keyStoreID, jwtClaimSet)
	if err != nil {
		return nil, errors.Wrap(err, "signing claimset")
	}

	linkageCredential, err := credint.NewCredentialContainerFromJWT(signedLinkageCredential.String())
	if err != nil {
		return nil, errors.Wrap(err, "creating credential container from JWT")
	}
	response := CreateDIDConfigurationResponse{
		DIDConfiguration: DIDConfiguration{
			Context:    DIDConfigurationContext,
			LinkedDIDs: []credint.Container{*linkageCredential},
		},
		WellKnownLocation: req.Origin + DIDConfigurationLocationSuffix,
	}
	return &response, nil
}
