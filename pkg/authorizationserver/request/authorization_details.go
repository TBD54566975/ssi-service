package request

import (
	"github.com/TBD54566975/ssi-sdk/oidc/issuance"
	"github.com/pkg/errors"
)

type AuthorizationDetail struct {
	// Type is the type of the requested authorization, e.g., "payment_initiation".
	Type string `json:"type"`

	// Locations is an array of strings representing the locations
	// of the resources to be accessed.
	// E.g., ["https://example.com/payments"]
	Locations []string `json:"locations,omitempty"`

	// Actions is an array of strings representing the actions to be performed on the resources.
	// E.g., ["read", "initiate", "status"]
	Actions []string `json:"actions,omitempty"`

	// Datatypes is an array of strings representing the data types that should be disclosed.
	// E.g., ["account_number", "amount", "transaction_details"]
	Datatypes []string `json:"datatypes,omitempty"`

	// Identifier is a string representing a unique identifier for the requested authorization details.
	Identifier string `json:"identifier,omitempty"`

	// The format in which the Credential is requested to be issued.
	// Required when type=="openid_credential".
	Format *issuance.Format `json:"format,omitempty"`

	// Present when type == openid_credential && format == jwt_vc_json
	*JWTVCDetails

	// Present when type == openid_credential && format == ldp_json
	CredentialDefinition *CredentialDefinition `json:"credential_definition,omitempty"`
}

type JWTVCDetails struct {
	// The type values the Wallet requests authorization for at the issuer
	Types []string `json:"types"`

	// A list of key value pairs, where the key identifies the claim offered in the Credential. Indicates the claims the
	// Wallet would like to turn up in the credential to be issued.
	CredentialSubject map[string]any `json:"credentialSubject,omitempty"`
}

type CredentialDefinition struct {
	Context []any `json:"@context" validate:"required"`

	// Either a string or a set of strings https://www.w3.org/TR/2021/REC-vc-data-model-20211109/#types
	Types []any `json:"types" validate:"required"`
}

func (d AuthorizationDetail) IsValid() error {
	if d.Type == "" {
		return errors.New("type is required")
	}

	if d.Type == "openid_credential" {
		if d.Format == nil {
			return errors.New("format is required when type is `openid_credential`")
		}
	}

	return nil
}

type AuthorizationDetails []AuthorizationDetail

func (ds AuthorizationDetails) IsValid() error {
	for _, d := range ds {
		if err := d.IsValid(); err != nil {
			return err
		}
	}
	return nil
}
