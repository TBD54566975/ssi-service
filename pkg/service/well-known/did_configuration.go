package wellknown

import (
	"context"
	"time"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/integrity"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/pkg/errors"
	credint "github.com/tbd54566975/ssi-service/internal/credential"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
)

type DIDConfigurationService struct {
	keyStoreService *keystore.Service
}

func NewDIDConfigurationService(keyStoreService *keystore.Service) *DIDConfigurationService {
	return &DIDConfigurationService{keyStoreService: keyStoreService}
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

type DomainLinkageCredential struct{}

type DIDConfiguration struct {
	Context    any                 `json:"@context" validate:"required"`
	LinkedDIDs []credint.Container `json:"linked_dids" validate:"required"`
}

type CreateDIDConfigurationResponse struct {
	DIDConfiguration  DIDConfiguration `json:"didConfiguration"`
	WellKnownLocation string           `json:"wellKnownLocation"`
}

const (
	DIDConfigurationContext        = "https://identity.foundation/.well-known/did-configuration/v1"
	DIDConfigurationLocationSuffix = "/.well-known/did-configuration.json"
)

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

type CreateDIDConfigurationRequest struct {
	IssuerDID            string
	VerificationMethodID string
	Origin               string

	ExpirationDate string
	IssuanceDate   string
}
