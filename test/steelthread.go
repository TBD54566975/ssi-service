package steelthread

import (
	"bytes"
	"embed"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/goccy/go-json"
	"github.com/oliveagle/jsonpath"
	"github.com/pkg/errors"
)

const (
	endpoint = "http://localhost:8080/"
	version  = "v1/"
)

var (
	//go:embed testdata
	testVectors embed.FS
)

func RunTest() error {
	fmt.Println("Start end to end test")

	// Make sure service is up and running
	output, err := get(endpoint + "readiness")
	if err != nil {
		return errors.Wrapf(err, "problem with readiness endpoint with output: %s", output)
	}

	fmt.Println(output)

	// Create a did for the issuer
	fmt.Println("\n\nCreate a did for the issuer:")
	output, err = put(endpoint+version+"dids/key", getJSONFromFile("did-input.json"))
	if err != nil {
		return errors.Wrapf(err, "problem with dids/key endpoint with output: %s", output)
	}

	fmt.Println(output)
	issuerDID, err := getJSONElement(output, "$.did.id")
	if err != nil {
		return errors.Wrap(err, "problem with getting json element")
	}

	// Create a schema to be used in CM
	fmt.Println("\n\nCreate a schema to be used in CM:")
	output, err = put(endpoint+version+"schemas", getJSONFromFile("schema-input.json"))
	if err != nil {
		return errors.Wrapf(err, "problem with schema endpoint with output: %s", output)
	}

	fmt.Println(output)
	schemaID, err := getJSONElement(output, "$.id")
	if err != nil {
		return errors.Wrap(err, "problem getting json element")
	}

	// Create a credential
	fmt.Println("\n\nCreate a credential to be used in CA:")
	credentialJSON := getJSONFromFile("credential-input.json")
	credentialJSON = strings.Replace(credentialJSON, "<CREDISSUERID>", issuerDID, -1)
	credentialJSON = strings.Replace(credentialJSON, "<CREDSUBJECTID>", issuerDID, -1)
	credentialJSON = strings.Replace(credentialJSON, "<SCHEMAID>", schemaID, -1)
	output, err = put(endpoint+version+"credentials", credentialJSON)
	if err != nil {
		return errors.Wrapf(err, "problem with credentials endpoint with output: %s", output)
	}

	fmt.Println(output)
	credentialJWT, err := getJSONElement(output, "$.credentialJwt")
	if err != nil {
		return errors.Wrap(err, "problem getting json element")
	}

	// Create our Credential Manifest
	fmt.Println("\n\nCreate our Credential Manifest:")
	manifestJSON := getJSONFromFile("manifest-input.json")
	manifestJSON = strings.Replace(manifestJSON, "<SCHEMAID>", schemaID, -1)
	manifestJSON = strings.Replace(manifestJSON, "<ISSUERID>", issuerDID, -1)
	output, err = put(endpoint+version+"manifests", manifestJSON)
	if err != nil {
		return errors.Wrapf(err, "problem with manifest endpoint with output: %s", output)
	}

	fmt.Println(output)
	presentationDefinitionID, err := getJSONElement(output, "$.credential_manifest.presentation_definition.id")
	if err != nil {
		return errors.Wrap(err, "problem getting json element")
	}

	// Submit an application
	fmt.Println("\n\nSubmit an Application:")
	applicationJSON := getJSONFromFile("application-input.json")
	applicationJSON = strings.Replace(applicationJSON, "<DEFINITIONID>", presentationDefinitionID, -1)
	applicationJSON = strings.Replace(applicationJSON, "<VCJWT>", credentialJWT, -1)

	// sign the application as a jwt

	output, err = put(endpoint+version+"manifests/applications", applicationJSON)
	if err != nil {
		return errors.Wrapf(err, "problem with application endpoint with output: %s", output)
	}

	fmt.Println(output)

	return err
}

func getJSONElement(jsonString string, jsonPath string) (string, error) {
	jsonMap := make(map[string]interface{})
	if err := json.Unmarshal([]byte(jsonString), &jsonMap); err != nil {
		return "", errors.Wrap(err, "problem with unmarshalling json string")
	}

	element, err := jsonpath.JsonPathLookup(jsonMap, jsonPath)
	if err != nil {
		return "", errors.Wrap(err, "problem with finding element in json string")
	}

	return element.(string), err
}

func get(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", errors.Wrap(err, "problem with finding element in json string")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "problem with parsing body")
	}

	if is200Response(resp.StatusCode) {
		return "", fmt.Errorf("status code not in the 200s. body: %s", string(body))
	}

	return string(body), err
}

func put(url string, json string) (string, error) {
	client := new(http.Client)

	req, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer([]byte(json)))
	if err != nil {
		return "", errors.Wrap(err, "problem with building http req")
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "problem client http client")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "problem with parsing body")
	}

	if is200Response(resp.StatusCode) {
		return "", fmt.Errorf("status code not in the 200s. body: %s", string(body))
	}

	return string(body), err
}

func getJSONFromFile(fileName string) string {
	b, _ := testVectors.ReadFile("testdata/" + fileName)
	return string(b)
}

func is200Response(statusCode int) bool {
	return statusCode/100 != 2
}
