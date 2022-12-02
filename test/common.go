package test

import (
	"bytes"
	"embed"
	cmpact "encoding/json"
	"github.com/goccy/go-json"
	"fmt"
	manifestsdk "github.com/TBD54566975/ssi-sdk/credential/manifest"
	"github.com/oliveagle/jsonpath"
	"github.com/pkg/errors"
	credmodel "github.com/tbd54566975/ssi-service/internal/credential"
	"io"
	"net/http"
)

const (
	endpoint = "http://localhost:8080/"
	version  = "v1/"
)

var (
	//go:embed testdata
	testVectors embed.FS
)

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
