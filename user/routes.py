from flask import Flask, request, redirect, session  # Importing Flask framework components for web application functionality
from app import app  # Assuming 'app' is the Flask application instance
import xml.etree.ElementTree as ET  # Importing ElementTree module for XML processing
from user.models import User  # Importing User model for user-related operations
from util import request as myrequest  # Importing custom request module for SAML authentication request generation
import base64  # Importing base64 module for encoding and decoding data
import requests  # Importing requests module for making HTTP requests
from urllib.parse import urlparse, parse_qs  # Importing urlparse and parse_qs functions for URL parsing

@app.route('/user/signup', methods=['POST'])
def signup():

    return User().signup()

@app.route('/user/signout')
def signout():
   
    return User().signout()

@app.route('/user/login', methods=['POST'])
def login():
    
    return redirect('/user/saml/login')

@app.route('/user/saml/login', methods=['GET', 'POST'])
def saml_login():
    
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
        # Extract the SAML Response from the form data
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

        # Set up the user session
        session['logged_in'] = True

        # Redirect to the dashboard or any other desired page
        return redirect('/dashboard')

      