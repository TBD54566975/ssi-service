package steelthread

import (
	"bytes"
	"embed"
	"fmt"
	manifestsdk "github.com/TBD54566975/ssi-sdk/credential/manifest"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/mr-tron/base58"
	credmodel "github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"io"
	"net/http"
	"strings"

	cmpact "encoding/json"
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

	// Create a did for the issuer
	fmt.Println("\n\nCreate a did for the issuer:")
	output, err = put(endpoint+version+"dids/key", getJSONFromFile("did-input.json"))
	if err != nil {
		return errors.Wrapf(err, "problem with dids/key endpoint with output: %s", output)
	}

	issuerDID, err := getJSONElement(output, "$.did.id")
	if err != nil {
		return errors.Wrap(err, "problem with getting json element")
	}

	// Create a did for alice
	fmt.Println("\n\nCreate a did for alice:")
	output, err = put(endpoint+version+"dids/key", getJSONFromFile("did-input.json"))
	if err != nil {
		return errors.Wrapf(err, "problem with dids/key endpoint with output: %s", output)
	}

	aliceDID, err := getJSONElement(output, "$.did.id")
	if err != nil {
		return errors.Wrap(err, "problem with getting json element")
	}

	aliceDIDPrivateKey, err := getJSONElement(output, "$.privateKeyBase58")
	if err != nil {
		return errors.Wrap(err, "getting json")
	}

	// Create a schema to be used in CM
	fmt.Println("\n\nCreate a schema to be used in CM:")
	output, err = put(endpoint+version+"schemas", getJSONFromFile("schema-input.json"))
	if err != nil {
		return errors.Wrapf(err, "problem with schema endpoint with output: %s", output)
	}

	schemaID, err := getJSONElement(output, "$.id")
	if err != nil {
		return errors.Wrap(err, "problem getting json element")
	}

	// Create a credential to be used in CA:
	fmt.Println("\n\nCreate a credential to be used in CA:")
	credentialJSON := getJSONFromFile("credential-input.json")
	credentialJSON = strings.ReplaceAll(credentialJSON, "<CREDISSUERID>", issuerDID)
	credentialJSON = strings.ReplaceAll(credentialJSON, "<CREDSUBJECTID>", issuerDID)
	credentialJSON = strings.ReplaceAll(credentialJSON, "<SCHEMAID>", schemaID)
	output, err = put(endpoint+version+"credentials", credentialJSON)
	if err != nil {
		return errors.Wrapf(err, "problem with credentials endpoint with output: %s", output)
	}

	credentialJWT, err := getJSONElement(output, "$.credentialJwt")
	if err != nil {
		return errors.Wrap(err, "problem getting json element")
	}

	// Create our Credential Manifest
	fmt.Println("\n\nCreate our Credential Manifest:")
	manifestJSON := getJSONFromFile("manifest-input.json")
	manifestJSON = strings.ReplaceAll(manifestJSON, "<SCHEMAID>", schemaID)
	manifestJSON = strings.ReplaceAll(manifestJSON, "<ISSUERID>", issuerDID)
	output, err = put(endpoint+version+"manifests", manifestJSON)
	if err != nil {
		return errors.Wrapf(err, "problem with manifest endpoint with output: %s", output)
	}

	presentationDefinitionID, err := getJSONElement(output, "$.credential_manifest.presentation_definition.id")
	if err != nil {
		return errors.Wrap(err, "problem getting json element")
	}
	manifestID, err := getJSONElement(output, "$.credential_manifest.id")
	if err != nil {
		return errors.Wrap(err, "problem getting json element")
	}

	// Submit an application
	fmt.Println("\n\nSubmit an Application:")
	applicationJSON := getJSONFromFile("application-input.json")
	applicationJSON = strings.ReplaceAll(applicationJSON, "<DEFINITIONID>", presentationDefinitionID)
	applicationJSON = strings.ReplaceAll(applicationJSON, "<VCJWT>", credentialJWT)
	applicationJSON = strings.ReplaceAll(applicationJSON, "<MANIFESTID>", manifestID)

	// Start signing credential application
	alicPrivKeyBytes, err := base58.Decode(aliceDIDPrivateKey)
	if err != nil {
		return errors.Wrap(err, "problem base58 decoding")
	}

	alicePrivKey, err := crypto.BytesToPrivKey(alicPrivKeyBytes, crypto.Ed25519)
	if err != nil {
		return errors.Wrap(err, "problem with bytes to priv key")
	}

	signer, err := keyaccess.NewJWKKeyAccess(aliceDID, alicePrivKey)
	if err != nil {
		return errors.Wrap(err, "problem with creating signer")
	}

	credAppWrapper := getValidApplicationRequest(applicationJSON, credentialJWT)

	signed, err := signer.SignJSON(credAppWrapper)
	if err != nil {
		return errors.Wrap(err, "problem signing json")
	}

	fmt.Println("\nApplication JSON:")
	fmt.Println(compactJSONOutput(applicationJSON))

	fmt.Println("\nSIGNED APPLICATION JWT:")
	fmt.Println(signed)
	// End signing credential application

	trueApplicationJSON := getJSONFromFile("application-input-jwt.json")
	trueApplicationJSON = strings.Replace(trueApplicationJSON, "<APPLICATIONJWT>", signed.String(), -1)

	output, err = put(endpoint+version+"manifests/applications", trueApplicationJSON)
	if err != nil {
		return errors.Wrapf(err, "problem with application endpoint with output: %s", output)
	}

	return err
}

func compactJSONOutput(json string) string {
	jsonBytes := []byte(json)
	buffer := new(bytes.Buffer)
	if err := cmpact.Compact(buffer, jsonBytes); err != nil {
		fmt.Println(err)
	}

	return buffer.String()
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
	fmt.Printf("\nPerforming GET request to:  %s\n", url)

	resp, err := http.Get(url) // #nosec: testing only.
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

	fmt.Printf("\nOutput:\n")
	fmt.Println(string(body))

	return string(body), err
}

func put(url string, json string) (string, error) {
	fmt.Printf("\nPerforming PUT request to:  %s \n\nwith data: \n%s\n", url, compactJSONOutput(json))

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

	fmt.Printf("\nOutput:\n")
	fmt.Println(string(body))

	return string(body), err
}

func getJSONFromFile(fileName string) string {
	b, _ := testVectors.ReadFile("testdata/" + fileName)
	return string(b)
}

func is200Response(statusCode int) bool {
	return statusCode/100 != 2
}

func getValidApplicationRequest(credAppJSON string, credentialJWT string) manifestsdk.CredentialApplicationWrapper {
	var createApplication manifestsdk.CredentialApplication
	if err := json.Unmarshal([]byte(credAppJSON), &createApplication); err != nil {
		fmt.Println("unmarshal error")
	}

	contain, err := credmodel.NewCredentialContainerFromJWT(credentialJWT)
	if err != nil {
		fmt.Println("Problem making NewCredentialContainerFromJWT")
	}
	contains := []credmodel.Container{*contain}

	creds := credmodel.ContainersToInterface(contains)
	return manifestsdk.CredentialApplicationWrapper{
		CredentialApplication: createApplication,
		Credentials:           creds,
	}
}
