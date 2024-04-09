from flask import Flask, request, redirect, session
from app import app
import xml.etree.ElementTree as ET
from user.models import User
from util import request as myrequest
import base64
import requests
from urllib.parse import urlparse, parse_qs
from sign2 import verify_signature

@app.route('/user/signup', methods=['POST'])
def signup():
    """
    Sign up route handler.

    :return: The result of the sign-up operation
    :rtype: str
    """
    return User().signup()

@app.route('/user/signout')
def signout():
    """
    Sign out route handler.

    :return: The result of the sign-out operation
    :rtype: str
    """
    return User().signout()

@app.route('/user/login', methods=['POST'])
def login():
    """
    Login route handler.

    :return: Redirects to the SAML login route
    :rtype: flask.Response
    """
    return redirect('/user/saml/login')

@app.route('/user/saml/login', methods=['GET', 'POST'])
def saml_login():
    """
    SAML login route handler.

    :return: Redirects to the Okta Single Sign-On (SSO) URL or handles SAML response
    :rtype: flask.Response
    """
    if request.method == 'GET':
        # Generate the SAML authentication request
        entity_id = "http://localhost:5000/user/saml/login"
        acs_url = "http://localhost:5000/user/saml/login"
        authn_request_xml = myrequest.generate_authn_request(entity_id, acs_url)
        print(authn_request_xml)
        
        # Base64 encode the XML
        if authn_request_xml is not None:
            encoded_authn_request = base64.b64encode(authn_request_xml).decode()
            print("SAML Request:")
            print(encoded_authn_request)  # Print the encoded XML
        else:
            print("Error: Authentication request XML is None")

        # Okta SSO endpoint URL
        okta_sso_url = "https://dev-18615030.okta.com/app/dev-18615030_samldemo_3/exkf8znpymURITvYu5d7/sso/saml"

        # Construct the payload for the POST request
        payload = {'SAMLRequest': encoded_authn_request}

        # Send the POST request to Okta
        response = requests.post(okta_sso_url, data=payload)

        # Check the response
        if response.status_code == 200:
            print("SAML authentication request sent successfully.")
        else:
            print(f"Failed to send SAML authentication request. Status code: {response.status_code}")

        return redirect(okta_sso_url)
    
    elif request.method == 'POST':
        # Extract the SAMLResponse from the form data
        saml_response = request.form.get('SAMLResponse')
        print("SAML Response")
        print(saml_response)
        print('\n')

        # Decode the base64-encoded SAML response to bytes and then decode the bytes to UTF-8 encoded XML
        decoded_saml_response = base64.b64decode(saml_response).decode("utf-8")
        # Remove the XML declaration (if present)
        decoded_saml_response = decoded_saml_response.replace('<?xml version="1.0" encoding="UTF-8"?>', '')

        # Print the decoded SAML response
        print("Decoded SAML Response:\n")
        print(decoded_saml_response)
        print('\n')

        # Verify the signature and obtain certificate, signed info, and signature
        is_valid, certificate, signed_info, signature = verify_signature(decoded_saml_response)

        # Print certificate, signed info, and signature
        print("Certificate:", certificate)
        print('\n')
        print("Signed Info:", signed_info)
        print('\n')
        print("Signature:", signature)
        print('\n')

        # Print the verification result
        print("Signature verification result:", is_valid)
        print('\n')

        # If the signature is valid, set up the user session, parse XML and get assertion attributes and redirect
        if is_valid:
            # Set up the user session
            session['logged_in'] = True

            # Parse the decoded SAML response XML
            xml_tree = ET.fromstring(decoded_saml_response)

            # Find the Assertion element namespace
            ns = {'saml2': 'urn:oasis:names:tc:SAML:2.0:assertion'}

            # Find the Assertion element
            assertion = xml_tree.find('.//saml2:Assertion', namespaces=ns)

            # Extract assertion attributes using a python dictionary
            assertion_attributes = {}
            for attribute in assertion.findall('.//saml2:Attribute', namespaces=ns):
                attribute_name = attribute.get('Name')
                attribute_value = attribute.find('.//saml2:AttributeValue', namespaces=ns).text
                assertion_attributes[attribute_name] = attribute_value

            # Print assertion attributes
            print("Assertion Attributes:")
            for key, value in assertion_attributes.items():
                print(f"{key}: {value}")
                print('\n')
                
            # Redirect to the dashboard or any other desired page
            return redirect('/dashboard')
        else:
            # Handle invalid signature
            return "Invalid SAML response. Signature verification failed."
