package router

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
	wellknown "github.com/tbd54566975/ssi-service/pkg/service/well-known"
)

type DIDConfigurationRouter struct {
	Service *wellknown.DIDConfigurationService
}

type CreateDIDConfigurationRequest struct {
	// DID that identifies who the issuer of the credential(s) will be.
	// Required.
	IssuerDID string `json:"issuerDid" validate:"required" example:"did:key:z6MkkZDjunoN4gyPMx5TSy7Mfzw22D2RZQZUcx46bii53Ex3"`

	// The id of the verificationMethod (see https://www.w3.org/TR/did-core/#verification-methods) who's privateKey is
	// stored in ssi-service. The verificationMethod must be part of the did document associated with `issuer`.
	// The private key associated with the verificationMethod's publicKey will be used to sign the domain linkage credential.
	// Required.
	VerificationMethodID string `json:"verificationMethodId" validate:"required" example:"did:key:z6MkkZDjunoN4gyPMx5TSy7Mfzw22D2RZQZUcx46bii53Ex3#z6MkkZDjunoN4gyPMx5TSy7Mfzw22D2RZQZUcx46bii53Ex3"`

	// Serialization of an origin as described in https://html.spec.whatwg.org/multipage/browsers.html#origin. Represents
	// the origin that the IssuerDID controls, which will be included in the `DomainLinkageCredential.credentialSubject.origin`
	// value.
	// Required.
	Origin string `json:"origin" validate:"required" example:"https://www.tbd.website/"`

	// Will be used to set the `DomainLinkageCredential.credentialSubject.expirationDate`. Required.
	ExpirationDate string `json:"expirationDate" validate:"required" example:"2051-10-05T14:48:00.000Z"`

	// Will be used to set the `DomainLinkageCredential.credentialSubject.issuanceDate`. If left empty, then the current
	// time will be used.
	// Optional.
	IssuanceDate string `json:"issuanceDate" example:"2021-10-05T14:48:00.000Z"`
}

func (r CreateDIDConfigurationRequest) toServiceRequest() *wellknown.CreateDIDConfigurationRequest {
	return &wellknown.CreateDIDConfigurationRequest{
		IssuerDID:            r.IssuerDID,
		VerificationMethodID: r.VerificationMethodID,
		Origin:               r.Origin,
		ExpirationDate:       r.ExpirationDate,
		IssuanceDate:         r.IssuanceDate,
	}
}

type DIDConfiguration struct {
	Context    any   `json:"@context" validate:"required"`
	LinkedDIDs []any `json:"linked_dids" validate:"required"`
}

type CreateDIDConfigurationResponse struct {
	// The location in which the `didConfiguration` value should be hosted.
	WellKnownLocation string `json:"wellKnownLocation"`

	// The DID Configuration Resource according to https://identity.foundation/.well-known/resources/did-configuration/#did-configuration-resource
	DIDConfiguration DIDConfiguration `json:"didConfiguration"`
}

// CreateDIDConfiguration godoc
//
//	@Summary		Create DIDConfiguration
//	@Description	Creates a DID Configuration Resource which conforms to https://identity.foundation/.well-known/resources/did-configuration/#did-configuration-resource
//	@Description	The `didConfiguration` can be hosted at the `wellKnownLocation` specified in the response.
//	@Tags			DIDConfigurationAPI
//	@Accept			json
//	@Produce		json
//	@Param			request	body		CreateDIDConfigurationRequest	true	"request body"
//	@Success		201		{object}	CreateDIDConfigurationResponse
//	@Failure		400		{string}	string	"Bad request"
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/v1/did-configurations [put]
func (wr DIDConfigurationRouter) CreateDIDConfiguration(c *gin.Context) {
	var request CreateDIDConfigurationRequest
	invalidCreateDIDConfigurationRequest := "invalid create did configuration request"
	if err := framework.Decode(c.Request, &request); err != nil {
		framework.LoggingRespondErrWithMsg(c, err, invalidCreateDIDConfigurationRequest, http.StatusBadRequest)
		return
	}

	if err := framework.ValidateRequest(request); err != nil {
		framework.LoggingRespondErrWithMsg(c, err, invalidCreateDIDConfigurationRequest, http.StatusBadRequest)
		return
	}

	req := request.toServiceRequest()

	createDIDConfigurationResponse, err := wr.Service.CreateDIDConfiguration(c, req)
	if err != nil {
		errMsg := "could not create did configuration"
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}

	resp := CreateDIDConfigurationResponse{
		DIDConfiguration: DIDConfiguration{
			Context:    createDIDConfigurationResponse.DIDConfiguration.Context,
			LinkedDIDs: credential.ContainersToInterface(createDIDConfigurationResponse.DIDConfiguration.LinkedDIDs),
		},
		WellKnownLocation: createDIDConfigurationResponse.WellKnownLocation,
	}
	framework.Respond(c, resp, http.StatusCreated)
	return
}

// VerifyDIDConfiguration godoc
//
//	@Summary		Verifies a DID Configuration Resource
//	@Description	Verifies a DID Configuration Resource according to https://identity.foundation/.well-known/resources/did-configuration/#did-configuration-resource-verification
//	@Tags			DIDConfigurationAPI
//	@Accept			json
//	@Produce		json
//	@Param			request	body		wellknown.VerifyDIDConfigurationRequest	true	"request body"
//	@Success		201		{object}	wellknown.VerifyDIDConfigurationResponse
//	@Failure		400		{string}	string	"Bad request"
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/v1/did-configurations/verification [put]
func (wr DIDConfigurationRouter) VerifyDIDConfiguration(c *gin.Context) {
	var request wellknown.VerifyDIDConfigurationRequest
	invalidRequest := "invalid verify did configuration resource request"
	if err := framework.Decode(c.Request, &request); err != nil {
		framework.LoggingRespondErrWithMsg(c, err, invalidRequest, http.StatusBadRequest)
		return
	}

	if err := framework.ValidateRequest(request); err != nil {
		framework.LoggingRespondErrWithMsg(c, err, invalidRequest, http.StatusBadRequest)
		return
	}

	response, err := wr.Service.VerifyDIDConfiguration(c, &request)
	if err != nil {
		errMsg := "could not verify did configuration"
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}
	framework.Respond(c, response, http.StatusCreated)
}
func NewDIDConfigurationsRouter(svc svcframework.Service) (*DIDConfigurationRouter, error) {
	return &DIDConfigurationRouter{Service: svc.(*wellknown.DIDConfigurationService)}, nil
}
