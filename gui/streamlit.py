from pickletools import read_bytes1
import streamlit as st
import requests
import json

st.title('DID and Verifiable Credentials')

#
# Show health and readiness in the sidebar
#

health = requests.get('http://web:3000/health').json()
readiness = requests.get('http://web:3000/readiness').json()
ready = readiness['status']['status']

with st.sidebar:
    with st.expander("Service detail"):
        st.write(health)
        st.write(readiness)

    if health['status'] == "OK" and ready == "ready":
        st.success("service: " + health['status'])
    else:
        st.error("service: " + str(health.json()['status']))
        st.write(readiness)

    for state in readiness['serviceStatuses']:
        if readiness['serviceStatuses'][state]['status'] == "ready":
            st.success(state + ": " + readiness['serviceStatuses'][state]['status'])
        else:
            st.error(readiness['serviceStatuses'][state]['status'])

if 'did' not in st.session_state:
    st.subheader("Create a DID:")

    if st.radio("Make or load a DID", ["Create new DID", "Use existing DID"]) == "Create new DID":
        if st.button("Create new DID"):
            did = requests.put('http://web:3000/v1/dids/key', data=json.dumps({"keyType": "Ed25519"})).json()
            st.session_state.did = did
            st.experimental_rerun()
        else:
            st.stop()

    else:
        key = st.text_input("", "did:example:1234")
        if st.button("Lookup DID"):
            did = requests.get('http://web:3000/v1/dids/key/' + key).json()
            st.session_state.did = did
            st.experimental_rerun()
        else:
            st.stop()

did = st.session_state.did

st.text("DID chosen: " + did['did']['id'])

with st.expander("(optional) Show DID detail"):
    st.write(did)

st.subheader("Choose a schema to issue a  Verifiable Credential against:")

@st.cache
def load_schemas():
    schemas = requests.get('https://schema.org/version/latest/schemaorg-current-https.jsonld').json()

    listing = []
    for schema in schemas["@graph"]:
        listing.append(schema["@id"])

    return listing


schemas = load_schemas()
default_schema = "schema:PostalAddress"
schema = st.selectbox(options=schemas, label='Select a schema', index=schemas.index(default_schema))

st.subheader("Issue a Verifiable Credential:")

expiry = st.date_input("Expiry date:", value=None, min_value=None, max_value=None, key=None, help=None)
# convert to ISO 8601
expiry = expiry.isoformat()

data = {
    "addressLocality": "Paris, France",
    "postalCode": "75002",
    "streetAddress": "38 avenue de l'\''Opera"
}
data = st.text_area("Data for credential (depends on schema):", value=json.dumps(data), height=None, max_chars=None,
                    key=None, help=None)

# TODO: Add dynamic schema payload from dropdown
if st.button("Create Schema"):
    sch = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "description": "postal address",
        "type": "object",
        "properties": {
            "addressLocality": {
                "type": "string"
            },
            "postalCode": {
                "type": "string"
            },
            "streetAddress": {
                "type": "string"
            }
        },
        "additionalProperties": False
    }

    payload = {
        "author": did['did']['id'],
        "name": "name",
        "schema": sch
    }

    schema_output = requests.put('http://web:3000/v1/schemas', data=json.dumps(payload)).json()
    st.write(schema_output)
    st.session_state.schema_id = schema_output['id']

if st.button("Issue Verifiable Credential"):
    payload = {
        "issuer": did['did']['id'],
        "issuerKid": did['did']['verificationMethod'][0]['id'],
        "subject": did['did']['id'],
        "schemaId": st.session_state.schema_id,
        "data": json.loads(data),
        "expiry": str(expiry) + "T00:00:00+00:00"
    }
    vc = requests.put('http://web:3000/v1/credentials', data=json.dumps(payload)).json()
    st.write(vc)
