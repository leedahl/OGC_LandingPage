# Copyright (c) 2025
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os
from typing import Optional

import boto3
import uuid
from datetime import datetime
from urllib.parse import parse_qs
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

# Get DynamoDB table names from environment variables
CERTIFICATE_STORE_TABLE = os.environ.get('CERTIFICATE_STORE_TABLE', 'certificate_store')
CERTIFICATE_METADATA_TABLE = os.environ.get('CERTIFICATE_METADATA_TABLE', 'certificate_metadata')
KEY_ALIAS = os.environ.get('KEY_ALIAS', 'security_user_store_key')


def encrypt_pem(pem, username: str, password: str, salt: Optional[str] = None):
    """
    Generates a salt and encrypts the CSR PEM using KMS.

    Args:
        pem (str): The PEM to encrypt
        username (str): The username to use
        password (str): Password from authorization header to use for key creation/retrieval
        salt (str, optional): The salt to use for encryption

    Returns:
        tuple: (encrypted_csr_pem, salt) where encrypted_pem is the encrypted PEM,
               and salt is the salt used for encryption
    """
    # Generate a UUID to use as salt
    salt = str(uuid.uuid4()) if salt is None else salt

    # Combine salt and PEM
    salted_pem = f"{salt}:{pem}"

    # Initialize KMS client
    kms_client = boto3.client('kms')

    # Encrypt the salted PEM using KMS
    response = kms_client.encrypt(
        Plaintext=salted_pem.encode('utf_8'),
        KeyId=f'alias/{KEY_ALIAS}',
        EncryptionContext={username: password}
    )

    encrypted_pem = response['CiphertextBlob']

    return encrypted_pem, salt


def decrypt_csr_private_key_pem(
        encrypted_pem: bytes, salt: str, encrypted_private_key_pem: bytes, username: str, password: str
):
    """
    Decrypts the CSR PEM using KMS and the provided salt.

    Args:
        encrypted_pem (bytes): The encrypted CSR PEM
        salt (str): The salt used for encryption
        encrypted_private_key_pem (bytes): The encrypted private key PEM
        username (str): The username to use
        password (str): Password from authorization header to use for key retrieval

    Returns:
        str: The decrypted CSR PEM
    """
    # Initialize KMS client
    kms_client = boto3.client('kms')

    # Determine which key to use for decryption
    key_id = f'alias/{KEY_ALIAS}'

    # Decrypt the hash using KMS
    response = kms_client.decrypt(
        CiphertextBlob=encrypted_pem,
        KeyId=key_id,
        EncryptionContext={username: password}
    )

    # Get the decrypted hash
    decoded_csr = response['Plaintext'].decode('utf_8')
    decrypted_csr = decoded_csr.replace(f'{salt}:', '', 1)

    response = kms_client.decrypt(
        CiphertextBlob=encrypted_private_key_pem,
        KeyId=key_id,
        EncryptionContext={username: password}
    )

    decoded_private_key = response['Plaintext'].decode('utf_8')
    decrypted_private_key = decoded_private_key.replace(f'{salt}:', '', 1)

    return decrypted_csr, decrypted_private_key


# noinspection PyUnusedLocal
def lambda_handler(event, context):
    """
    Lambda function handler for CSR generation, retrieval, and deletion.

    This function handles:
    - GET requests to /csr (to display the CSR form)
    - POST requests to /csr (to process the form submission and generate a CSR)
    - GET requests to /csr/{csr_id} (to retrieve a CSR as a PEM file)
    - DELETE requests to /csr/{csr_id} (to delete a CSR)

    :param event: The event dict that contains the request parameters
    :param context: The context object provided by AWS Lambda
    :return: The response with HTML content or PEM file
    """
    # Initialize DynamoDB client
    dynamodb = boto3.resource('dynamodb')
    certificate_store_table = dynamodb.Table(CERTIFICATE_STORE_TABLE)
    certificate_metadata_table = dynamodb.Table(CERTIFICATE_METADATA_TABLE)

    # Get the current year for copyright notice
    current_year = datetime.now().year

    # Get the HTTP method
    http_method = event.get('httpMethod', '')

    # Get the username from the Authorization header
    headers = event.get('headers', {})
    auth_header = headers.get('Authorization', '')

    # Extract username from Authorization header if present
    if auth_header:
        # Basic auth format: "Basic base64(username:password)"
        if auth_header.startswith('Basic '):
            import base64
            try:
                # Extract the base64 encoded part
                encoded_credentials = auth_header[6:]  # Remove 'Basic ' prefix

                # Decode the credentials
                decoded_credentials = base64.b64decode(encoded_credentials).decode('utf_8')

                # Split into username and password
                username, password = decoded_credentials.split(':', 1)

            except Exception as e:
                # If any error occurs during parsing, fall back to default username
                return {
                    'statusCode': 400,
                    'headers': {'Content-Type': 'text/html; charset=utf-8'},
                    'body': generate_error_html(current_year, f'Failed to get username: {str(e)}'),
                    'isBase64Encoded': False
                }

        else:
            # This is an error condition.  Other Authorization methods, besides Basic, are wrong.
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'text/html; charset=utf-8'},
                'body': generate_error_html(current_year, f'Wrong Authorization Method, requires Basic'),
                'isBase64Encoded': False
            }

    else:
        # This is an error condition.  The login uses basic authentication; so, the Authorization header is required.
        return {
            'statusCode': 400,
            'headers': {'Content-Type': 'text/html; charset=utf-8'},
            'body': generate_error_html(current_year, f'Wrong Authorization Method, requires Basic'),
            'isBase64Encoded': False
        }

    # Check if this is a request for a specific CSR by ID
    path_parameters = event.get('pathParameters', {})
    if path_parameters and path_parameters.get('csr_id'):
        csr_id = path_parameters.get('csr_id')

        # Check if this is a request for the private key
        resource_path = event.get('path', '')
        is_private_key_request = '/private_key' in resource_path

        if http_method == 'GET':
            try:
                # Retrieve the CSR from DynamoDB
                response = certificate_store_table.get_item(
                    Key={'certificate_id': csr_id}
                )

                if 'Item' not in response:
                    return generate_problem_json(
                        404,
                        'Not Found',
                        f'CSR with ID {csr_id} not found.'
                    )

                csr_data = response['Item']

                # Check if the user has access to this CSR
                metadata_response = certificate_metadata_table.get_item(
                    Key={'username': username, 'certificate_id': csr_id}
                )

                if 'Item' not in metadata_response:
                    return generate_problem_json(
                        403,
                        'Forbidden',
                        'You do not have permission to access this CSR.'
                    )

                # Decrypt the CSR and private key
                encrypted_csr_pem = bytes(csr_data.get('csr'))
                encrypted_private_key_pem = bytes(csr_data.get('private_key'))
                salt = csr_data.get('salt')

                try:
                    csr_pem, private_key_pem = decrypt_csr_private_key_pem(
                        encrypted_csr_pem, salt, encrypted_private_key_pem, username, password
                    )

                    # Return either the CSR or the private key based on the request
                    if is_private_key_request:
                        return generate_private_key_response(private_key_pem, csr_id)

                    else:
                        return generate_pem_response(csr_pem, csr_id)

                except Exception as e:
                    return generate_problem_json(
                        500,
                        'Internal Server Error',
                        f'Error decrypting CSR: {str(e)}'
                    )

            except Exception as e:
                return generate_problem_json(
                    500,
                    'Internal Server Error',
                    f'Error retrieving CSR: {str(e)}'
                )

        elif http_method == 'DELETE':
            try:
                # Check if the CSR exists and the user has access to it
                metadata_response = certificate_metadata_table.get_item(
                    Key={'username': username, 'certificate_id': csr_id}
                )

                if 'Item' not in metadata_response:
                    return generate_problem_json(
                        404,
                        'Not Found',
                        f'CSR with ID {csr_id} not found or you do not have permission to delete it.'
                    )

                # Delete the CSR from the certificate store
                certificate_store_table.delete_item(
                    Key={'certificate_id': csr_id}
                )

                # Delete the CSR metadata
                certificate_metadata_table.delete_item(
                    Key={'username': username, 'certificate_id': csr_id}
                )

                # Return success response
                return {
                    'statusCode': 200,
                    'headers': {'Content-Type': 'application/json'},
                    'body': f'{{"message": "CSR {csr_id} deleted successfully."}}',
                    'isBase64Encoded': False
                }

            except Exception as e:
                return generate_problem_json(
                    500,
                    'Internal Server Error',
                    f'Error deleting CSR: {str(e)}'
                )
        else:
            return generate_problem_json(
                400,
                'Bad Request',
                'Invalid HTTP method.'
            )


    elif http_method == 'POST':
        # Process form submission
        body = event.get('body', '')
        if body:
            # Parse form data
            form_data = parse_qs(body)

            # Extract CSR information
            common_name = form_data.get('common_name', [''])[0]
            organization = form_data.get('organization', [''])[0]
            organizational_unit = form_data.get('organizational_unit', [''])[0]
            locality = form_data.get('locality', [''])[0]
            state = form_data.get('state', [''])[0]
            country = form_data.get('country', [''])[0]
            email = form_data.get('email', [''])[0]

            # Validate inputs
            if not common_name:
                return {
                    'statusCode': 400,
                    'headers': {'Content-Type': 'text/html; charset=utf-8'},
                    'body': generate_error_html(current_year, 'Common Name is required.'),
                    'isBase64Encoded': False
                }

            # Generate a new key pair
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )

            # Create a CSR
            csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                (
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization) 
                    if organization else x509.NameAttribute(NameOID.ORGANIZATION_NAME, "")
                ),
                (
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit) 
                    if organizational_unit else x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "")
                ),
                (
                    x509.NameAttribute(NameOID.LOCALITY_NAME, locality)
                    if locality else x509.NameAttribute(NameOID.LOCALITY_NAME, "")
                ),
                (
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state) 
                    if state else x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "")
                ),
                (
                    x509.NameAttribute(NameOID.COUNTRY_NAME, country) 
                    if country else x509.NameAttribute(NameOID.COUNTRY_NAME, "")
                ),
                (
                    x509.NameAttribute(NameOID.EMAIL_ADDRESS, email) 
                    if email else x509.NameAttribute(NameOID.EMAIL_ADDRESS, "")
                )
            ])).sign(private_key, hashes.SHA256())

            # Serialize the CSR to PEM format
            csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf_8')

            # Serialize the private key to PEM format
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf_8')

            # Generate a unique ID for the certificate
            certificate_id = str(uuid.uuid4())

            # Encrypt the CSR PEM with salt using the password from authorization
            encrypted_csr_pem, salt = encrypt_pem(csr_pem, username, password)
            encrypted_private_key_pem, _ = encrypt_pem(private_key_pem, username, password, salt)

            # Store the CSR and private key in DynamoDB
            certificate_store_table.put_item(
                Item={
                    'certificate_id': certificate_id,
                    'csr': encrypted_csr_pem,
                    'salt': salt,
                    'private_key': encrypted_private_key_pem,
                    'common_name': common_name,
                    'organization': organization,
                    'organizational_unit': organizational_unit,
                    'locality': locality,
                    'state': state,
                    'country': country,
                    'email': email,
                    'created_at': datetime.now().isoformat(),
                    'status': 'pending'
                }
            )

            # Store metadata in the user's record
            certificate_metadata_table.put_item(
                Item={
                    'username': username,
                    'certificate_id': certificate_id,
                    'common_name': common_name,
                    'created_at': datetime.now().isoformat(),
                    'status': 'pending'
                }
            )

            # Check Accept header to determine a response format
            accept_header = headers.get('Accept', '')

            # If Accept header explicitly includes application/json, return JSON
            if 'application/json' in accept_header:
                return generate_success_json(certificate_id)
            # If Accept header doesn't include application/json but includes plain/html, return HTML
            elif 'plain/html' in accept_header:
                return {
                    'statusCode': 200,
                    'headers': {'Content-Type': 'text/html; charset=utf-8'},
                    'body': generate_success_html(current_year, certificate_id),
                    'isBase64Encoded': False
                }
            # Default to HTML if neither is specified
            else:
                return {
                    'statusCode': 200,
                    'headers': {'Content-Type': 'text/html; charset=utf-8'},
                    'body': generate_success_html(current_year, certificate_id),
                    'isBase64Encoded': False
                }

        else:
            # Empty form submission
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'text/html; charset=utf-8'},
                'body': generate_error_html(current_year, 'Form submission was empty.'),
                'isBase64Encoded': False
            }

    else:
        # Display the CSR form
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'text/html; charset=utf-8'},
            'body': generate_form_html(current_year),
            'isBase64Encoded': False
        }


def generate_form_html(current_year):
    """
    Generate the HTML form for CSR generation.

    :param current_year: The current year for copyright notice
    :return: HTML content
    """
    return '\r'.join([
        '<!DOCTYPE HTML>',
        '<html lang="en">',
        '  <head>',
        '    <title>Certificate Signing Request</title>',
        '    <style>',
        '      body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }',
        '      header, nav, section, footer { margin-bottom: 20px; }',
        '      header { background-color: #f5f5f5; padding: 10px; }',
        '      nav { background-color: #eee; padding: 10px; }',
        '      .content { padding: 20px; border: 1px solid #ddd; }',
        '      footer { text-align: center; font-size: 0.8em; color: #666; }',
        '      label { display: block; margin-top: 10px; }',
        '      input[type="text"] { width: 100%; padding: 8px; margin-top: 5px; }',
        '      input[type="submit"] { margin-top: 20px; padding: 10px 20px; background-color: #4CAF50; '
        'color: white; border: none; cursor: pointer; }',
        '      input[type="submit"]:hover { background-color: #45a049; }',
        '    </style>',
        '  </head>',
        '  <body>',
        '    <header><h1>Certificate Signing Request</h1></header>',
        '    <nav><a href="/">Home</a> &gt; Certificate Signing Request</nav>',
        '    <section class="content">',
        '      <h2>Generate a Certificate Signing Request</h2>',
        '      <p>Please fill out the form below to generate a Certificate Signing Request (CSR).</p>',
        '      <form action="/csr" method="POST">',
        '        <label for="common_name">Common Name (CN) *:</label>',
        '        <input type="text" id="common_name" name="common_name" placeholder="e.g., example.com" required />',
        '        <label for="organization">Organization (O):</label>',
        '        <input type="text" id="organization" name="organization" placeholder="e.g., Example Inc." />',
        '        <label for="organizational_unit">Organizational Unit (OU):</label>',
        '        <input type="text" id="organizational_unit" name="organizational_unit" '
        'placeholder="e.g., IT Department" />',
        '        <label for="locality">Locality (L):</label>',
        '        <input type="text" id="locality" name="locality" placeholder="e.g., San Francisco" />',
        '        <label for="state">State/Province (ST):</label>',
        '        <input type="text" id="state" name="state" placeholder="e.g., California" />',
        '        <label for="country">Country (C):</label>',
        '        <input type="text" id="country" name="country" placeholder="e.g., US" maxlength="2" />',
        '        <label for="email">Email Address:</label>',
        '        <input type="text" id="email" name="email" placeholder="e.g., admin@example.com" />',
        '        <input type="submit" value="Generate CSR" />',
        '      </form>',
        '    </section>',
        f'    <footer>&copy; {current_year} Michael Leedahl</footer>',
        '  </body>',
        '</html>'
    ])


def generate_success_html(current_year, certificate_id):
    """
    Generate the HTML success page with the generated CSR.

    :param current_year: The current year for copyright notice
    :param certificate_id: The unique ID for the certificate
    :return: HTML content
    """
    return '\r'.join([
        '<!DOCTYPE HTML>',
        '<html lang="en">',
        '  <head>',
        '    <title>Certificate Signing Request - Success</title>',
        '    <style>',
        '      body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }',
        '      header, nav, section, footer { margin-bottom: 20px; }',
        '      header { background-color: #f5f5f5; padding: 10px; }',
        '      nav { background-color: #eee; padding: 10px; }',
        '      .content { padding: 20px; border: 1px solid #ddd; }',
        '      footer { text-align: center; font-size: 0.8em; color: #666; }',
        '      pre { background-color: #f9f9f9; padding: 10px; border: 1px solid #ddd; overflow-x: auto; }',
        '    </style>',
        '  </head>',
        '  <body>',
        '    <header><h1>Certificate Signing Request - Success</h1></header>',
        '    <nav><a href="/">Home</a> &gt; <a href="/csr">Certificate Signing Request</a> &gt; Success</nav>',
        '    <section class="content">',
        '      <h2>CSR Generated Successfully</h2>',
        f'      <p>Your Certificate Signing Request has been generated with ID: <strong>{certificate_id}</strong></p>',
        '      <p><a href="/csr">Generate Another CSR</a></p>',
        '    </section>',
        f'    <footer>&copy; {current_year} Michael Leedahl</footer>',
        '  </body>',
        '</html>'
    ])


def generate_error_html(current_year, error_message):
    """
    Generate the HTML error page.

    :param current_year: The current year for copyright notice
    :param error_message: The error message to display
    :return: HTML content
    """
    return '\r'.join([
        '<!DOCTYPE HTML>',
        '<html lang="en">',
        '  <head>',
        '    <title>Certificate Signing Request - Error</title>',
        '    <style>',
        '      body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }',
        '      header, nav, section, footer { margin-bottom: 20px; }',
        '      header { background-color: #f5f5f5; padding: 10px; }',
        '      nav { background-color: #eee; padding: 10px; }',
        '      .content { padding: 20px; border: 1px solid #ddd; }',
        '      .error { color: #d9534f; }',
        '      footer { text-align: center; font-size: 0.8em; color: #666; }',
        '    </style>',
        '  </head>',
        '  <body>',
        '    <header><h1>Certificate Signing Request - Error</h1></header>',
        '    <nav><a href="/">Home</a> &gt; <a href="/csr">Certificate Signing Request</a> &gt; Error</nav>',
        '    <section class="content">',
        '      <h2 class="error">Error</h2>',
        f'      <p class="error">{error_message}</p>',
        '      <p><a href="/csr">Try Again</a></p>',
        '    </section>',
        f'    <footer>&copy; {current_year} Michael Leedahl</footer>',
        '  </body>',
        '</html>'
    ])


def generate_problem_json(status_code, title, detail, type_uri=None, instance=None):
    """
    Generate a response with application/problem+json format according to RFC 7807.

    :param status_code: The HTTP status code.
    :param title: A short, human-readable summary of the problem type.
    :param detail: A human-readable explanation specific to this occurrence of the problem.
    :param type_uri: A URI reference that identifies the problem type (optional).
    :param instance: A URI reference that identifies the specific occurrence of the problem (optional).
    :return: API Gateway response with the problem+json.
    """
    problem = {
        'title': title,
        'status': status_code,
        'detail': detail
    }

    if type_uri:
        problem['type'] = type_uri

    if instance:
        problem['instance'] = instance

    import json
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/problem+json'
        },
        'body': json.dumps(problem),
        'isBase64Encoded': False
    }


def generate_pem_response(csr_pem, certificate_id):
    """
    Generate a response with the CSR PEM file.

    :param csr_pem: The CSR PEM content
    :param certificate_id: The certificate ID
    :return: API Gateway response with the PEM file
    """
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/x-pem-file',
            'Content-Disposition': f'attachment; filename="{certificate_id}.pem"'
        },
        'body':csr_pem,
        'isBase64Encoded': False
    }


def generate_private_key_response(private_key_pem, certificate_id):
    """
    Generate a response with the private key PEM file.

    :param private_key_pem: The private key PEM content
    :param certificate_id: The certificate ID
    :return: API Gateway response with the private key PEM file
    """
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/x-pem-file',
            'Content-Disposition': f'attachment; filename="{certificate_id}_private_key.pem"'
        },
        'body': private_key_pem,
        'isBase64Encoded': False
    }


def generate_success_json(certificate_id):
    """
    Generate a JSON response for successful CSR creation.

    :param certificate_id: The unique ID for the certificate
    :return: JSON content
    """
    import json
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json'
        },
        'body': json.dumps({
            'message': 'CSR Generated Successfully',
            'csrId': certificate_id
        }),
        'isBase64Encoded': False
    }
