package integration

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/tbd54566975/ssi-service/pkg/service/operation/storage"
)

var presentationExchangeContext = NewTestContext("PresentationExchange")

func TestCreateParticipants(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	didKeyOutput, err := CreateDIDKey()
	assert.NoError(t, err)

	issuerDID, err := getJSONElement(didKeyOutput, "$.did.id")
	assert.NoError(t, err)
	assert.Contains(t, issuerDID, "did:key")
	SetValue(presentationExchangeContext, "issuerDID", issuerDID)

	issuerKID, err := getJSONElement(didKeyOutput, "$.did.verificationMethod[0].id")
	assert.NoError(t, err)
	assert.NotEmpty(t, issuerKID)
	SetValue(presentationExchangeContext, "issuerKID", issuerKID)

	holderPrivateKey, holderDIDKey, err := didsdk.GenerateDIDKey(crypto.Ed25519)
	assert.NoError(t, err)
	assert.NotEmpty(t, holderPrivateKey)
	assert.NotEmpty(t, holderDIDKey)

	holderDID, err := holderDIDKey.Expand()
	assert.NoError(t, err)
	assert.NotEmpty(t, holderDID)
	SetValue(presentationExchangeContext, "holderDID", holderDID.ID)

	holderKID := holderDID.VerificationMethod[0].ID
	assert.NotEmpty(t, holderKID)
	SetValue(presentationExchangeContext, "holderKID", holderKID)
	SetValue(presentationExchangeContext, "holderPrivateKey", holderPrivateKey)

	verifierOutput, err := CreateDIDKey()
	assert.NoError(t, err)

	verifierDID, err := getJSONElement(verifierOutput, "$.did.id")
	assert.NoError(t, err)
	assert.Contains(t, holderDID, "did:key")
	SetValue(presentationExchangeContext, "verifierDID", verifierDID)

	verifierKID, err := getJSONElement(verifierOutput, "$.did.verificationMethod[0].id")
	assert.NoError(t, err)
	assert.NotEmpty(t, verifierKID)
	SetValue(presentationExchangeContext, "verifierKID", verifierKID)
}

func TestCreatePresentationDefinition(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	verifierDID, err := GetValue(presentationExchangeContext, "verifierDID")
	assert.NoError(t, err)

	verifierKID, err := GetValue(presentationExchangeContext, "verifierKID")
	assert.NoError(t, err)

	definition, err := CreatePresentationDefinition(definitionParams{
		Author:    verifierDID.(string),
		AuthorKID: verifierKID.(string),
	})
	assert.NoError(t, err)

	definitionID, err := getJSONElement(definition, "$.presentation_definition.id")
	assert.NoError(t, err)
	SetValue(presentationExchangeContext, "definitionID", definitionID)
}

func TestSubmissionFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	definitionID, err := GetValue(presentationExchangeContext, "definitionID")
	assert.NoError(t, err)

	holderDID, err := GetValue(presentationExchangeContext, "holderDID")
	assert.NoError(t, err)

	holderKID, err := GetValue(presentationExchangeContext, "holderKID")
	assert.NoError(t, err)

	holderPrivateKey, err := GetValue(presentationExchangeContext, "holderPrivateKey")
	assert.NoError(t, err)

	issuerDID, err := GetValue(presentationExchangeContext, "issuerDID")
	assert.NoError(t, err)

	issuerKID, err := GetValue(presentationExchangeContext, "issuerKID")
	assert.NoError(t, err)

	credOutput, err := CreateSubmissionCredential(credInputParams{
		IssuerID:  issuerDID.(string),
		IssuerKID: issuerKID.(string),
		SubjectID: holderDID.(string),
	})
	assert.NoError(t, err)

	credentialJWT, err := getJSONElement(credOutput, "$.credentialJwt")
	assert.NoError(t, err)

	toBeCancelledOp, err := CreateSubmission(submissionParams{
		HolderID:      holderDID.(string),
		HolderKID:     holderKID.(string),
		DefinitionID:  definitionID.(string),
		CredentialJWT: credentialJWT,
		SubmissionID:  uuid.NewString(),
	}, holderPrivateKey)
	assert.NoError(t, err)

	cancelOpID, err := getJSONElement(toBeCancelledOp, "$.id")
	assert.NoError(t, err)
	cancelOutput, err := put(endpoint+version+"operations/cancel/"+cancelOpID, "{}")
	assert.NoError(t, err)
	cancelDone, err := getJSONElement(cancelOutput, "$.done")
	assert.NoError(t, err)
	assert.Equal(t, "true", cancelDone)

	submissionOpOutput, err := CreateSubmission(submissionParams{
		HolderID:      holderDID.(string),
		HolderKID:     holderKID.(string),
		DefinitionID:  definitionID.(string),
		CredentialJWT: credentialJWT,
		SubmissionID:  uuid.NewString(),
	}, holderPrivateKey)
	assert.NoError(t, err)

	opID, err := getJSONElement(submissionOpOutput, "$.id")
	assert.NoError(t, err)

	operationOutput, err := get(endpoint + version + "operations/" + opID)
	assert.NoError(t, err)
	done, err := getJSONElement(operationOutput, "$.done")
	assert.NoError(t, err)
	assert.Equal(t, "false", done)

	reviewOutput, err := ReviewSubmission(storage.StatusObjectID(opID))
	assert.NoError(t, err)
	status, err := getJSONElement(reviewOutput, "$.status")
	assert.NoError(t, err)
	assert.Equal(t, "approved", status)

	reason, err := getJSONElement(reviewOutput, "$.reason")
	assert.NoError(t, err)
	assert.Equal(t, "because I want to", reason)

	operationOutput, err = get(endpoint + version + "operations/" + opID)
	assert.NoError(t, err)
	done, err = getJSONElement(operationOutput, "$.done")
	assert.NoError(t, err)
	assert.Equal(t, "true", done)
	opResponse, err := getJSONElement(operationOutput, "$.result.response")
	assert.NoError(t, err)
	s, _ := getJSONElement(reviewOutput, "$")
	assert.Equal(t, s, opResponse)
}
