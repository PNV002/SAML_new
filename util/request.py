import base64
from datetime import datetime, timezone
from xml.etree import ElementTree as ET

def generate_authn_request(entity_id, acs_url):
    """
    Generate a SAML authentication request XML.

    :param entity_id: The entity ID.
    :type entity_id: str
    :param acs_url: The Assertion Consumer Service URL.
    :type acs_url: str
    :return: The SAML authentication request XML.
    :rtype: bytes
    """
    authn_request = ET.Element('{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest', {
        'AssertionConsumerServiceURL': acs_url,
        'Destination': 'https://dev-18615030.okta.com/app/dev-18615030_samldemo_3/exkf8znpymURITvYu5d7/sso/saml',
        'ID': '_{}'.format(base64.b64encode(entity_id.encode()).decode()),
        'IssueInstant': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'ProtocolBinding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        'Version': '2.0'
    })
    return ET.tostring(authn_request, encoding='utf-8', method='xml')
