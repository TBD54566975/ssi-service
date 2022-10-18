package end2end

import (
	"bytes"
	"embed"
	"fmt"
	"github.com/goccy/go-json"
	"github.com/oliveagle/jsonpath"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
	"strings"
)

const endpoint = "http://localhost:8080/"
const version = "v1/"

var (
	//go:embed testdata
	testVectors embed.FS
)

func RunTest() error {
	fmt.Println("Start end to end test")

	// Make sure service is up and running
	output, err := get(endpoint + "readiness")
	fmt.Println(output)

	// Create a did for the issuer
	fmt.Println("\n\nCreate a did for the issuer:")
	output, err = put(endpoint+version+"dids/key", getJsonFromFile("did.json"))
	fmt.Println(output)
	issuerDID, err := getJsonElement(output, "$.did.id")

	// Create a schema to be used in CM
	fmt.Println("\n\nCreate a schema to be used in CM:")
	output, err = put(endpoint+version+"schemas", getJsonFromFile("schema.json"))
	fmt.Println(output)
	schemaID, err := getJsonElement(output, "$.id")

	// Create a credential
	fmt.Println("\n\nCreate a credential to be used in CA:")
	credentialJson := getJsonFromFile("credential.json")
	credentialJson = strings.Replace(credentialJson, "<CREDISSUERID>", issuerDID, -1)
	credentialJson = strings.Replace(credentialJson, "<CREDSUBJECTID>", issuerDID, -1)
	credentialJson = strings.Replace(credentialJson, "<SCHEMAID>", schemaID, -1)
	output, err = put(endpoint+version+"credentials", credentialJson)
	fmt.Println(output)
	credentialJWT, err := getJsonElement(output, "$.credentialJwt")

	// Create our Credential Manifest
	fmt.Println("\n\nCreate our Credential Manifest:")
	manifestJson := getJsonFromFile("manifest.json")
	manifestJson = strings.Replace(manifestJson, "<SCHEMAID>", schemaID, -1)
	manifestJson = strings.Replace(manifestJson, "<ISSUERID>", issuerDID, -1)
	output, err = put(endpoint+version+"manifests", manifestJson)
	fmt.Println(output)
	presentationDefinitionID, err := getJsonElement(output, "$.credential_manifest.presentation_definition.id")

	// Submit an application
	fmt.Println("\n\nSubmit an Application:")
	applicationJson := getJsonFromFile("application.json")
	applicationJson = strings.Replace(applicationJson, "<DEFINITIONID>", presentationDefinitionID, -1)
	applicationJson = strings.Replace(applicationJson, "<VCJWT>", credentialJWT, -1)
	output, err = put(endpoint+version+"manifests/applications", applicationJson)
	fmt.Println(output)

	return err
}

func getJsonElement(jsonString string, jsonPath string) (string, error) {
	var jsonMap map[string]interface{}
	err := json.Unmarshal([]byte(jsonString), &jsonMap)

	element, err := jsonpath.JsonPathLookup(jsonMap, jsonPath)

	return element.(string), err
}

func get(url string) (string, error) {
	resp, err := http.Get(url)
	body, err := ioutil.ReadAll(resp.Body)

	if resp.StatusCode > 299 {
		return "", errors.New("status code > than 299 with message: " + string(body))
	}

	return string(body), err
}

func put(url string, json string) (string, error) {
	client := &http.Client{}

	req, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer([]byte(json)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	body, err := ioutil.ReadAll(resp.Body)

	if resp.StatusCode > 299 {
		return "", errors.New("status code > than 299 with message " + string(body))
	}
	return string(body), err
}

func getJsonFromFile(fileName string) string {
	b, _ := testVectors.ReadFile("testdata/" + fileName)
	return string(b)
}
