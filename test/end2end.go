package end2end

import (
	"bytes"
	"embed"
	"fmt"
	"github.com/goccy/go-json"
	"github.com/oliveagle/jsonpath"
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
	output, err = put(endpoint+version+"dids/key", getJsonFromFile("did.json"))
	fmt.Println(output)

	issuerDID, err := getJsonElement(output, "$.did.id")
	fmt.Println(issuerDID)

	// Create a schema to be used in CM
	output, err = put(endpoint+version+"schemas", getJsonFromFile("schema.json"))
	fmt.Println(output)

	schemaID, err := getJsonElement(output, "$.id")
	fmt.Println(schemaID)

	manifestJson := getJsonFromFile("manifest.json")
	manifestJson = strings.Replace(manifestJson, "<SCHEMAID>", schemaID, -1)
	manifestJson = strings.Replace(manifestJson, "<ISSUERID>", issuerDID, -1)

	// Create our Credential Manifest
	output, err = put(endpoint+version+"manifests", manifestJson)
	fmt.Println(output)

	presentationDefinitionID, err := getJsonElement(output, "$.credential_manifest.presentation_definition.id")
	fmt.Println(presentationDefinitionID)

	applicationJson := getJsonFromFile("application.json")
	applicationJson = strings.Replace(applicationJson, "<DEFINITIONID>", presentationDefinitionID, -1)

	// Submit an application
	output, err = put(endpoint+version+"manifests/applications", applicationJson)
	fmt.Println(output)

	vcJWT, err := getJsonElement(output, "$.verifiableCredential[0]")
	fmt.Println(vcJWT)

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

	return string(body), err
}

func put(url string, json string) (string, error) {
	client := &http.Client{}

	req, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer([]byte(json)))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	body, err := ioutil.ReadAll(resp.Body)

	return string(body), err
}

func getJsonFromFile(fileName string) string {
	b, _ := testVectors.ReadFile("testdata/" + fileName)
	return string(b)
}
