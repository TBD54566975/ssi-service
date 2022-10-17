#!/bin/bash

#TODO: Install jq

HEALTH=$(curl -s localhost:8080/health)
echo "$HEALTH"

DID=$(curl -s -X PUT -d '{"keyType":"Ed25519"}' localhost:8080/v1/dids/key)
#echo "$DID"

ID=$(echo $DID | jq -r '.did.id')
echo "ID:"
echo "$ID"


# shellcheck disable=SC2016
SCHEMA=$(curl -s -X PUT -d '
{
     "author": "$ID",
     "name": "KYC",
     "schema": {
         "$id": "kyc-schema-1.0",
         "$schema": "https://json-schema.org/draft/2020-12/schema",
         "description": "KYC Schema",
         "type": "object",
         "properties": {
             "id": {
                 "type": "string",
                 "format": "email"
             }
         },
         "required": [],
         "additionalProperties": false
     }
 }' localhost:8080/v1/schemas)


echo "$SCHEMA"
SCHEMAID=$(echo $SCHEMA | jq -r '.schema.id')

echo "$SCHEMAID"


MANIFEST=$(curl -s -X PUT -d '
{
   "manifest":{
      "id":"WA-DL-CLASS-A",
      "issuer":{
         "id":"'"$ID"'"
      },
      "spec_version":"https://identity.foundation/credential-manifest/spec/v1.0.0/",
      "output_descriptors":[
         {
            "id":"kyc_credential",
            "schema":"'"$SCHEMAID"'"
         }
      ],
      "presentation_definition":{
         "id":"32f54163-7166-48f1-93d8-ff217bdb0653",
         "name":"KYC Requirements",
         "purpose":"TBD. i donno rn",
         "format":{
            "jwt":{
               "alg":[
                  "EdDSA"
               ]
            }
         },
         "input_descriptors":[
            {
               "id":"kyc1",
               "name":"Personal Info",
               "constraints":{
                  "subject_is_issuer":"required",
                  "fields":[
                     {
                        "id":"kycSchema",
                        "path":[
                           "$.vc.credentialSchema.id"
                        ],
                        "filter":{
                           "type":"string",
                           "const":"https://compliance-is-kewl.com/json-schemas/kyc.json"
                        }
                     },
                     {
                        "id":"givenName",
                        "path":[
                           "$.vc.credentialSubject.givenName"
                        ],
                        "filter":{
                           "type":"string",
                           "pattern":"[a-zA-Z \\-\\.].+"
                        }
                     },
                     {
                        "id":"additionalName",
                        "path":[
                           "$.vc.credentialSubject.additionalName"
                        ],
                        "filter":{
                           "type":"string",
                           "pattern":"[a-zA-Z \\-\\.].+"
                        }
                     },
                     {
                        "id":"familyName",
                        "path":[
                           "$.vc.credentialSubject.familyName"
                        ],
                        "filter":{
                           "type":"string",
                           "pattern":"[a-zA-Z \\-\\.].+"
                        }
                     },
                     {
                        "id":"birthDate",
                        "path":[
                           "$.vc.credentialSubject.birthDate"
                        ],
                        "filter":{
                           "type":"string",
                           "format":"date"
                        }
                     },
                     {
                        "id":"postalAddress",
                        "path":[
                           "$.vc.credentialSubject.postalAddress"
                        ],
                        "filter":{
                           "type":"string"
                        }
                     },
                     {
                        "id":"taxID",
                        "path":[
                           "$.vc.credentialSubject.taxID"
                        ],
                        "filter":{
                           "type":"string"
                        }
                     }
                  ]
               }
            }
         ]
      }
   }
}' localhost:8080/v1/manifests)

echo "$MANIFEST"

MANIFESTID=$(echo "$MANIFEST" | jq -r '.manifest.id')
echo "$MANIFESTID"


APPLICATIONRESPONSE=$(curl -X PUT -d '
{
     "applicantDid": "did:user:123",
     "application" :{
         "id": "00239c16-3e64-4438-8dda-641e963fa853",
         "spec_version": "https://identity.foundation/credential-manifest/spec/v1.0.0/",
         "manifest_id":"WA-DL-CLASS-A",
         "format": {
             "jwt_vc": {
             "alg": [
                 "EdDSA"
             ]
             }
         },
         "presentation_submission": {
             "id": "00239c16-3e64-4438-8dda-641e963fa853",
             "definition_id": "32f54163-7166-48f1-93d8-ff217bdb0653",
             "descriptor_map": [
             {
                 "id": "kyc1",
                 "format": "jwt_vc",
                 "path": "$.verifiableCredential[0]"
             }
             ]
         }
         }
 }' localhost:8080/v1/manifests/applications)


echo "hi"
echo "$APPLICATIONRESPONSE"