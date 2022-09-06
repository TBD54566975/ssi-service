from pickletools import read_bytes1
import streamlit as st
import requests
import json

st.title('DID and Verifiable Credentials')




#
# Show health and readitness in the sidebar
#

health = requests.get('http://localhost:8080/health')
status = health.json()['status']
readiness = requests.get('http://localhost:8080/readiness')
ready = readiness.json()['status']['status']

with st.sidebar:
    if status == "OK" and ready == "ready":
        st.success("service: " + str(health.json()['status']))
        with st.expander("show service details", expanded=False):
            st.write(readiness.json())
    else:
        st.error("service: " + str(health.json()['status']))
        st.write(readiness.json())
        st.stop()    



if 'did' not in st.session_state:
    st.subheader("Create a DID:")

    if st.radio("Make or load a DID", ["Create new DID", "Use existing DID"]) == "Create new DID":
        if st.button("Create new DID"):
            did = requests.put('http://localhost:8080/v1/dids/key', data=json.dumps({"keyType":"Ed25519"})).json()            
            st.session_state.did = did
            st.experimental_rerun()
        else: 
            st.stop()        

    else:    
        key = st.text_input("", "did:example:1234")
        if st.button("Lookup DID"):
            did = requests.get('http://localhost:8080/v1/dids/key/' + key).json()
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


data =  {
       "addressLocality": "Paris, France",
        "postalCode": "75002",
        "streetAddress": "38 avenue de l'\''Opera"
}
data = st.text_area("Data for credential (depends on schema):", value=json.dumps(data), height=None, max_chars=None, key=None, help=None)

if st.button("Issue Verifiable Credential"):
    payload = {
        "Issuer": did['did']['id'],
        "Subject": did['did']['id'],
        "Schema": "https://schema.org/" + schema.split(":")[1],
        "Data": json.loads(data),
        "Expiry": str(expiry) + "T00:00:00+00:00"
    }
    vc  = requests.put('http://localhost:8080/v1/credentials', data=json.dumps(payload)).json()
    st.write(vc)