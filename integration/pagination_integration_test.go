package integration

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestListSchemaIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	// In this test we create a couple of schemas, fetch them all using pagination, and validate that the created ones
	// were returned in any of the results.
	schema1, err := CreateKYCSchema()
	assert.NoError(t, err)

	schema1ID, err := getJSONElement(schema1, "$.id")
	assert.NoError(t, err)

	schema2, err := CreateKYCSchema()
	assert.NoError(t, err)

	schema2ID, err := getJSONElement(schema2, "$.id")
	assert.NoError(t, err)

	schemasPage, err := get(endpoint + version + "schemas?pageSize=1")
	assert.NoError(t, err)

	var allSchemaIDs string
	allSchemaIDs = schemasPage

	nextPageToken, err := getJSONElement(schemasPage, "$.nextPageToken")
	assert.NoError(t, err)

	for nextPageToken != "" {
		schemasPage, err := get(endpoint + version + "schemas?pageSize=1&pageToken=" + nextPageToken)
		assert.NoError(t, err)

		allSchemaIDs += schemasPage

		nextPageToken, err = getJSONElement(schemasPage, "$.nextPageToken")
		assert.NoError(t, err)
	}

	assert.Contains(t, allSchemaIDs, schema1ID)
	assert.Contains(t, allSchemaIDs, schema2ID)
}
