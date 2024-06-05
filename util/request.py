import base64  # Importing base64 module for encoding and decoding data
from datetime import datetime, timezone  # Importing datetime module for handling date and time
from xml.etree import ElementTree as ET  # Importing ElementTree module for XML processing

# Read variables from URL.txt
def read_variables_from_file(file_path):
    variables = {}
    with open(file_path, 'r') as file:
        for line in file:
            parts = line.strip().split('=')
            if len(parts) == 2:
                variable_name, value = parts
                variables[variable_name.strip()] = value.strip()
    return variables

# Read variables from URL.txt
variables = read_variables_from_file('URL.txt')
okta_sso_url = variables.get('okta_sso_url', '')

def generate_authn_request(entity_id, acs_url):

    # Generate a SAML authentication request XML element using the provided entity ID and ACS URL
    authn_request = ET.Element('{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest', {
    'AssertionConsumerServiceURL': acs_url,  # Set the AssertionConsumerServiceURL attribute to the provided ACS URL
    'Destination': okta_sso_url,  # Set the Destination attribute to the Okta SSO URL
    'ID': '_{}'.format(base64.b64encode(entity_id.encode()).decode()),  # Set the ID attribute with a base64 encoded version of the entity ID
    'IssueInstant': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),  # Set the IssueInstant attribute to the current UTC time in ISO 8601 format
    'ProtocolBinding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',  # Set the ProtocolBinding attribute to the SAML HTTP-POST binding
    'Version': '2.0'  # Set the Version attribute to SAML version 2.0
    })

    # Serialize the authn_request element to an XML string with UTF-8 encoding
    return ET.tostring(authn_request, encoding='utf-8', method='xml')


