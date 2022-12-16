package integration

import (
	"bytes"
	"embed"
	"fmt"
	"io"
	"net/http"
	"text/template"

	manifestsdk "github.com/TBD54566975/ssi-sdk/credential/manifest"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/goccy/go-json"
	"github.com/mr-tron/base58"
	"github.com/oliveagle/jsonpath"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	credmodel "github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
)

const (
	endpoint = "http://localhost:8080/"
	version  = "v1/"
)

var (
	//go:embed testdata
	testVectors embed.FS
	client      = new(http.Client)
)

func CreateDIDKey() (string, error) {
	logrus.Println("\n\nCreate a did for the issuer:")
	output, err := put(endpoint+version+"dids/key", getJSONFromFile("did-input.json"))
	if err != nil {
		return "", errors.Wrapf(err, "did endpoint with output: %s", output)
	}

	return output, nil
}

func CreateDIDWeb() (string, error) {
	logrus.Println("\n\nCreate a did:web")
	output, err := put(endpoint+version+"dids/web", getJSONFromFile("did-web-input.json"))
	if err != nil {
		return "", errors.Wrapf(err, "did endpoint with output: %s", output)
	}

	return output, nil
}

func ResolveDID(did string) (string, error) {
	logrus.Println("\n\nResolve a did")
	output, err := get(endpoint + version + "dids/resolver/" + did)
	if err != nil {
		return "", errors.Wrapf(err, "did resolver with output: %s", output)
	}

	return output, nil
}

func CreateKYCSchema() (string, error) {
	logrus.Println("\n\nCreate a schema")
	output, err := put(endpoint+version+"schemas", getJSONFromFile("schema-input.json"))
	if err != nil {
		return "", errors.Wrapf(err, "schema endpoint with output: %s", output)
	}

	return output, nil
}

type credInputParams struct {
	IssuerID  string
	SchemaID  string
	SubjectID string
}

func CreateVerifiableCredential(credentialInput credInputParams, revocable bool) (string, error) {
	logrus.Println("\n\nCreate a verifiable credential")

	if credentialInput.SubjectID == "" {
		credentialInput.SubjectID = credentialInput.IssuerID
	}

	fileName := "credential-input.json"
	if revocable {
		fileName = "credential-revocable-input.json"
	}
	credentialJSON, err := resolveTemplate(credentialInput, fileName)
	if err != nil {
		return "", err
	}

	output, err := put(endpoint+version+"credentials", credentialJSON)
	if err != nil {
		return "", errors.Wrapf(err, "credentials endpoint with output: %s", output)
	}

	return output, nil
}

func resolveTemplate(input any, fileName string) (string, error) {
	t, err := template.ParseFiles("testdata/" + fileName)
	if err != nil {
		return "", errors.Wrap(err, "parsing input file")
	}

	var b bytes.Buffer
	if err = t.Execute(&b, input); err != nil {
		return "", err
	}
	credentialJSON := b.String()
	return credentialJSON, nil
}

type credManifestParams struct {
	IssuerID string
	SchemaID string
}

func CreateCredentialManifest(credManifest credManifestParams) (string, error) {
	logrus.Println("\n\nCreate our Credential Manifest:")
	manifestJSON, err := resolveTemplate(credManifest, "manifest-input.json")
	if err != nil {
		return "", err
	}
	output, err := put(endpoint+version+"manifests", manifestJSON)
	if err != nil {
		return "", errors.Wrapf(err, "manifest endpoint with output: %s", output)
	}

	return output, nil
}

type credApplicationParams struct {
	DefinitionID string
	ManifestID   string
}

func CreateCredentialApplicationJWT(credApplication credApplicationParams, credentialJWT, aliceDID, aliceDIDPrivateKey string) (string, error) {
	logrus.Println("\n\nCreate an Application JWT:")
	applicationJSON, err := resolveTemplate(credApplication, "application-input.json")
	if err != nil {
		return "", err
	}

	alicePrivKeyBytes, err := base58.Decode(aliceDIDPrivateKey)
	if err != nil {
		return "", errors.Wrap(err, "base58 decoding")
	}

	alicePrivKey, err := crypto.BytesToPrivKey(alicePrivKeyBytes, crypto.Ed25519)
	if err != nil {
		return "", errors.Wrap(err, "bytes to priv key")
	}

	signer, err := keyaccess.NewJWKKeyAccess(aliceDID, alicePrivKey)
	if err != nil {
		return "", errors.Wrap(err, "creating signer")
	}

	credAppWrapper := getValidApplicationRequest(applicationJSON, credentialJWT)

	signed, err := signer.SignJSON(credAppWrapper)
	if err != nil {
		return "", errors.Wrap(err, "signing json")
	}

	return signed.String(), nil
}

type applicationParams struct {
	ApplicationJWT string
}

func SubmitApplication(app applicationParams) (string, error) {
	trueApplicationJSON, err := resolveTemplate(app, "application-input-jwt.json")
	if err != nil {
		return "", err
	}

	output, err := put(endpoint+version+"manifests/applications", trueApplicationJSON)
	if err != nil {
		return "", errors.Wrapf(err, "application endpoint with output: %s", output)
	}

	return output, nil
}

func compactJSONOutput(jsonString string) string {
	jsonBytes := []byte(jsonString)
	buffer := new(bytes.Buffer)
	if err := json.Compact(buffer, jsonBytes); err != nil {
		logrus.Println(err)
		panic(err)
	}

	return buffer.String()
}

func getJSONElement(jsonString string, jsonPath string) (string, error) {
	jsonMap := make(map[string]any)
	if err := json.Unmarshal([]byte(jsonString), &jsonMap); err != nil {
		return "", errors.Wrap(err, "unmarshalling json string")
	}

	element, err := jsonpath.JsonPathLookup(jsonMap, jsonPath)
	if err != nil {
		return "", errors.Wrap(err, "finding element in json string")
	}

	elementStr := fmt.Sprintf("%v", element)
	return elementStr, nil
}

func get(url string) (string, error) {
	logrus.Println(fmt.Sprintf("\nPerforming GET request to:  %s\n", url))

	resp, err := http.Get(url) // #nosec: testing only.
	if err != nil {
		return "", errors.Wrapf(err, "getting url: %s", url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "parsing body")
	}

	if is2xxResponse(resp.StatusCode) {
		return "", fmt.Errorf("status code not in the 200s. body: %s", string(body))
	}

	return string(body), err
}

func put(url string, json string) (string, error) {
	logrus.Println(fmt.Sprintf("\nPerforming PUT request to:  %s \n\nwith data: \n%s\n", url, compactJSONOutput(json)))

	req, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer([]byte(json)))
	if err != nil {
		return "", errors.Wrap(err, "building http req")
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "client http client")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "parsing body")
	}

	if is2xxResponse(resp.StatusCode) {
		return "", fmt.Errorf("status code %v not in the 200s. body: %s", resp.StatusCode, string(body))
	}

	logrus.Println("\nOutput:")
	logrus.Println(string(body))

	return string(body), err
}

func getJSONFromFile(fileName string) string {
	b, _ := testVectors.ReadFile("testdata/" + fileName)
	return string(b)
}

func is2xxResponse(statusCode int) bool {
	return statusCode/100 != 2
}

func getValidApplicationRequest(credAppJSON string, credentialJWT string) manifestsdk.CredentialApplicationWrapper {
	var createApplication manifestsdk.CredentialApplication
	if err := json.Unmarshal([]byte(credAppJSON), &createApplication); err != nil {
		logrus.Println("unmarshal error")
		panic(err)
	}

	contain, err := credmodel.NewCredentialContainerFromJWT(credentialJWT)
	if err != nil {
		logrus.Println("making NewCredentialContainerFromJWT")
		panic(err)
	}
	contains := []credmodel.Container{*contain}

	creds := credmodel.ContainersToInterface(contains)
	return manifestsdk.CredentialApplicationWrapper{
		CredentialApplication: createApplication,
		Credentials:           creds,
	}
}
