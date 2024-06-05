from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import base64
from lxml import etree

def verify_signature(decoded_saml_response):
    
    def extract_signed_info(xml_str):
        
        root = etree.fromstring(xml_str)
        signature_element = root.find(".//{http://www.w3.org/2000/09/xmldsig#}Signature")
        signed_info_element = signature_element.find(".//{http://www.w3.org/2000/09/xmldsig#}SignedInfo")
        signed_info = etree.tostring(signed_info_element, encoding=str)
        return signed_info.strip()

    def extract_certificate(xml_str):
       
        root = etree.fromstring(xml_str)
        signature_element = root.find(".//{http://www.w3.org/2000/09/xmldsig#}Signature")
        x509_certificate_element = signature_element.find(".//{http://www.w3.org/2000/09/xmldsig#}X509Certificate")
        certificate = x509_certificate_element.text.strip()
        return certificate

    def extract_signature(xml_str):
        
        root = etree.fromstring(xml_str)
        signature_element = root.find(".//{http://www.w3.org/2000/09/xmldsig#}Signature")
        signature_value_element = signature_element.find(".//{http://www.w3.org/2000/09/xmldsig#}SignatureValue")
        signature = signature_value_element.text.strip()
        return signature

    # Extract the SignedInfo, Certificate, and Signature from the SAML response
    signed_info = extract_signed_info(decoded_saml_response)
    certificate = extract_certificate(decoded_saml_response)
    signature = extract_signature(decoded_saml_response)

    # Decode the certificate from base64 
    cert_bytes = base64.b64decode(certificate)

    # Parses certificate bytes and creates an RSA public key - 80ms
    public_key = RSA.importKey(cert_bytes)

    # Creates a new PKCS#1 v1.5 signature verifier object 
    signer = PKCS1_v1_5.new(public_key)

    # Normalize the XML content based on the canonicalization method specified in the SignedInfo
    canonicalized_signed_info = etree.tostring(etree.fromstring(signed_info), method="c14n", exclusive=True)

    # Hash the normalized SignedInfo using SHA-256 hashing algorithm to produce a digest
    digest = SHA256.new(canonicalized_signed_info)

    # Decode the signature from base64 to bytes
    signature_bytes = base64.b64decode(signature)

    # Invoke the verify() method on the verifier, with the hash object and the incoming signature as parameters. If the message is not authentic, an ValueError is raised.
    is_valid = signer.verify(digest, signature_bytes)

    # Return the verification result along with the certificate, signed info, and signature
    return is_valid, certificate, signed_info, signature
