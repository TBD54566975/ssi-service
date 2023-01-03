package integration

import (
	"testing"

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

	holderOutput, err := CreateDIDKey()
	assert.NoError(t, err)

	holderDID, err := getJSONElement(holderOutput, "$.did.id")
	assert.NoError(t, err)
	assert.Contains(t, holderDID, "did:key")

	holderPrivateKey, err := getJSONElement(holderOutput, "$.privateKeyBase58")
	assert.NoError(t, err)

	SetValue(presentationExchangeContext, "issuerDID", issuerDID)
	SetValue(presentationExchangeContext, "holderDID", holderDID)
	SetValue(presentationExchangeContext, "holderPrivateKey", holderPrivateKey)
}

func TestCreatePresentationDefinition(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	definition, err := CreatePresentationDefinition()
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

	holderPrivateKey, err := GetValue(presentationExchangeContext, "holderPrivateKey")
	assert.NoError(t, err)

	issuerDID, err := GetValue(presentationExchangeContext, "issuerDID")
	assert.NoError(t, err)

	credOutput, err := CreateSubmissionCredential(credInputParams{
		IssuerID:  issuerDID.(string),
		SubjectID: holderDID.(string),
	})
	assert.NoError(t, err)

	credentialJWT, err := getJSONElement(credOutput, "$.credentialJwt")
	assert.NoError(t, err)

	toBeCancelledOp, err := CreateSubmission(submissionParams{
		HolderID:      holderDID.(string),
		DefinitionID:  definitionID.(string),
		CredentialJWT: credentialJWT,
		SubmissionID:  uuid.NewString(),
	}, holderPrivateKey.(string))
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
		DefinitionID:  definitionID.(string),
		CredentialJWT: credentialJWT,
		SubmissionID:  uuid.NewString(),
	}, holderPrivateKey.(string))
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
