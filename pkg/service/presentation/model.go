package presentation

import (
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/util"
)

const (
	Version1 string = "1.0"
)

type CreatePresentationDefinitionRequest struct {
	PresentationDefinition exchange.PresentationDefinition `json:"presentation_definition" validate:"required"`
}

func (csr CreatePresentationDefinitionRequest) IsValid() bool {
	return util.IsValidStruct(csr) == nil
}

type CreatePresentationDefinitionResponse struct {
	PresentationDefinition exchange.PresentationDefinition `json:"presentation_definition"`
}

type GetPresentationDefinitionRequest struct {
	ID string `json:"id" validate:"required"`
}

type GetPresentationDefinitionResponse struct {
	ID                     string                          `json:"id"`
	PresentationDefinition exchange.PresentationDefinition `json:"presentation_definition"`
}

type DeletePresentationDefinitionRequest struct {
	ID string `json:"id" validate:"required"`
}
