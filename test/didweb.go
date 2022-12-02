package test

import (
	"fmt"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/mr-tron/base58"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"strings"

	"github.com/pkg/errors"
)

func RunDidWebTest() error {
	fmt.Println("Start end to end test with did:web")

	// Make sure service is up and running
	output, err := get(endpoint + "readiness")
	if err != nil {
		return errors.Wrapf(err, "problem with readiness endpoint with output: %s", output)
	}

	// Create a did for the issuer
	fmt.Println("\n\nCreate a did:web for the issuer:")
	output, err = put(endpoint+version+"dids/web", getJSONFromFile("did-web-input.json"))
	if err != nil {
		return errors.Wrapf(err, "problem with dids/web endpoint with output: %s", output)
	}

	issuerDID, err := getJSONElement(output, "$.did.id")
	if err != nil {
		return errors.Wrap(err, "problem with getting json element")
	}

	// Create a did for alice
	fmt.Println("\n\nCreate a did for alice:")
	output, err = put(endpoint+version+"dids/web", getJSONFromFile("did-web-input.json"))
	if err != nil {
		return errors.Wrapf(err, "problem with dids/web endpoint with output: %s", output)
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
	trueApplicationJSON = strings.ReplaceAll(trueApplicationJSON, "<APPLICATIONJWT>", signed.String())

	output, err = put(endpoint+version+"manifests/applications", trueApplicationJSON)
	if err != nil {
		return errors.Wrapf(err, "problem with application endpoint with output: %s", output)
	}

	return err
}
