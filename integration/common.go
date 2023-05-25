package integration

import (
	"bytes"
	gocrypto "crypto"
	"embed"
	"fmt"
	"io"
	"net/http"
	"text/template"
	"time"

	manifestsdk "github.com/TBD54566975/ssi-sdk/credential/manifest"
	"github.com/cenkalti/backoff/v4"
	"github.com/goccy/go-json"
	"github.com/oliveagle/jsonpath"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	credmodel "github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/server/router"
)

const (
	// Note: for local testing change this to port 3000
	endpoint       = "http://localhost:8080/"
	version        = "v1/"
	MaxElapsedTime = 120 * time.Second
)

var (
	//go:embed testdata
	testVectors embed.FS
	client      = new(http.Client)
)

func init() {
	// Treats "\n" as new lines, see https://github.com/sirupsen/logrus/issues/608
	logrus.SetFormatter(&logrus.TextFormatter{
		DisableQuote: true,
		ForceColors:  true,
	})
}

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

	var createDIDWebRequest router.CreateDIDByMethodRequest
	inputJSON := getJSONFromFile("did-web-input.json")
	if err := json.Unmarshal([]byte(inputJSON), &createDIDWebRequest); err != nil {
		return "", errors.Wrap(err, "unmarshalling did:web request")
	}

	createdRequestJSONBytes, err := json.Marshal(createDIDWebRequest)
	if err != nil {
		return "", errors.Wrap(err, "creating did:web request")
	}

	output, err := put(endpoint+version+"dids/web", string(createdRequestJSONBytes))
	if err != nil {
		return "", errors.Wrapf(err, "did endpoint with output: %s", output)
	}

	return output, nil
}

func CreateDIDION() (string, error) {
	logrus.Println("\n\nCreate a did:ion")
	output, err := put(endpoint+version+"dids/ion", getJSONFromFile("did-ion-input.json"))
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
	IssuerKID string
	SchemaID  string
	SubjectID string
}

func CreateVerifiableCredential(credentialInput credInputParams) (string, error) {
	return CreateVerifiableCredentialWithStatus(credentialInput, false, false)
}
func CreateVerifiableCredentialWithStatus(credentialInput credInputParams, revocable bool, suspendable bool) (string, error) {
	logrus.Println("\n\nCreate a verifiable credential")

	if credentialInput.SubjectID == "" {
		credentialInput.SubjectID = credentialInput.IssuerID
	}

	fileName := "credential-input.json"
	if revocable {
		fileName = "credential-revocable-input.json"
	}
	if suspendable {
		fileName = "credential-suspendable-input.json"
	}

	credentialJSON, err := resolveTemplate(credentialInput, fileName)
	if err != nil {
		return "", err
	}

	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.MaxElapsedTime = MaxElapsedTime

	var output string

	err = backoff.Retry(func() error {
		output, err = put(endpoint+version+"credentials", credentialJSON)
		if err != nil {
			logrus.WithError(err).Debug("retryable error caught, retrying..")
			return err
		}
		return nil
	}, expBackoff)

	if err != nil {
		return "", errors.Wrap(err, "error after retrying")
	}

	return output, nil
}

func CreateSubmissionCredential(params credInputParams) (string, error) {
	logrus.Println("\n\nCreate a submission credential")

	credentialJSON, err := resolveTemplate(params, "submission-credential-input.json")
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
	templateJSON := b.String()
	return templateJSON, nil
}

type credManifestParams struct {
	IssuerID  string
	IssuerKID string
	SchemaID  string
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

func CreateCredentialApplicationJWT(credApplication credApplicationParams, credentialJWT, aliceDID, aliceKID string, aliceDIDPrivateKey gocrypto.PrivateKey) (string, error) {
	logrus.Println("\n\nCreate an Application JWT:")
	applicationJSON, err := resolveTemplate(credApplication, "application-input.json")
	if err != nil {
		return "", err
	}

	signer, err := keyaccess.NewJWKKeyAccess(aliceDID, aliceKID, aliceDIDPrivateKey)
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

type definitionParams struct {
	Author    string
	AuthorKID string
}

func CreatePresentationDefinition(params definitionParams) (string, error) {
	logrus.Println("\n\nCreate our Presentation Definition:")
	definitionJSON, err := resolveTemplate(params, "presentation-definition-input.json")
	if err != nil {
		return "", err
	}
	output, err := put(endpoint+version+"presentations/definitions", definitionJSON)
	if err != nil {
		return "", errors.Wrapf(err, "presentation definition endpoint with output: %s", output)
	}

	return output, nil
}

func ReviewSubmission(id string) (string, error) {
	logrus.Println("\n\nCreate our review submission request:")
	reviewJSON := getJSONFromFile("review-submission-input.json")
	output, err := put(endpoint+version+"presentations/submissions/"+id+"/review", reviewJSON)
	if err != nil {
		return "", errors.Wrapf(err, "review submission endpoint with output: %s", output)
	}

	return output, nil
}

type submissionParams struct {
	HolderID      string
	HolderKID     string
	DefinitionID  string
	CredentialJWT string
	SubmissionID  string
}

type submissionJWTParams struct {
	SubmissionJWT string
}

func CreateSubmission(params submissionParams, holderPrivateKey gocrypto.PrivateKey) (string, error) {
	logrus.Println("\n\nCreate our Submission:")
	submissionJSON, err := resolveTemplate(params, "presentation-submission-input.json")
	if err != nil {
		return "", err
	}

	signer, err := keyaccess.NewJWKKeyAccess(params.HolderID, params.HolderKID, holderPrivateKey)
	if err != nil {
		return "", errors.Wrap(err, "creating signer")
	}

	var submission any
	if err = json.Unmarshal([]byte(submissionJSON), &submission); err != nil {
		return "", err
	}

	signed, err := signer.SignJSON(submission)
	if err != nil {
		logrus.Println("Failed signing: " + submissionJSON)
		return "", errors.Wrap(err, "signing json")
	}

	submissionJSONWrapper, err := resolveTemplate(submissionJWTParams{SubmissionJWT: signed.String()},
		"presentation-submission-input-jwt.json")
	if err != nil {
		return "", err
	}

	output, err := put(endpoint+version+"presentations/submissions", submissionJSONWrapper)
	if err != nil {
		return "", errors.Wrapf(err, "presentation submission endpoint with output: %s", output)
	}

	return output, nil
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

	if element == nil {
		return "<nil>", nil
	}
	var elementStr string
	switch element.(type) {
	case bool:
		elementStr = fmt.Sprintf("%v", element)
	case string:
		elementStr = fmt.Sprintf("%v", element)
	case map[string]any:
		data, err := json.Marshal(element)
		if err != nil {
			return "", err
		}
		elementStr = compactJSONOutput(string(data))
	}

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

	if !util.Is2xxResponse(resp.StatusCode) {
		return "", fmt.Errorf("status code not in the 200s. body: %s", string(body))
	}

	logrus.Infof("Received:  %s", string(body))
	return string(body), err
}

func put(url string, json string) (string, error) {
	logrus.Printf("\nPerforming PUT request to:  %s \n\nwith data: \n%s\n", url, json)

	req, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer([]byte(json)))
	if err != nil {
		return "", errors.Wrap(err, "building http req")
	}

	req.Header.Set("Content-Type", "application/json")
	client.Timeout = 90 * time.Second
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "client http client")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.Wrap(err, "parsing body")
	}

	bodyStr := string(body)
	if !util.Is2xxResponse(resp.StatusCode) {
		return "", fmt.Errorf("status code %v not in the 200s. body: %s", resp.StatusCode, bodyStr)
	}

	logrus.Println("\nOutput:")
	logrus.Println(bodyStr)

	return bodyStr, err
}

func getJSONFromFile(fileName string) string {
	b, _ := testVectors.ReadFile("testdata/" + fileName)
	return string(b)
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

type reviewApplicationParams struct {
	ID       string
	Approved bool
	Reason   string
}

func ReviewApplication(params reviewApplicationParams) (string, error) {
	trueApplicationJSON, err := resolveTemplate(params, "review-application-input.json")
	if err != nil {
		return "", err
	}

	output, err := put(endpoint+version+"manifests/applications/"+params.ID+"/review", trueApplicationJSON)
	if err != nil {
		return "", errors.Wrapf(err, "application endpoint with output: %s", output)
	}

	return output, nil
}

type issuanceTemplateParams struct {
	SchemaID   string
	ManifestID string
	IssuerID   string
	IssuerKID  string
}

func CreateIssuanceTemplate(params issuanceTemplateParams) (string, error) {
	logrus.Println("\n\nCreating Issuance Template:")
	issuanceTemplateJSON, err := resolveTemplate(params, "issuance-template-input.json")
	if err != nil {
		return "", err
	}
	output, err := put(endpoint+version+"issuancetemplates", issuanceTemplateJSON)
	if err != nil {
		return "", errors.Wrapf(err, "creating issuance template yielded output: %s", output)
	}

	return output, nil
}
