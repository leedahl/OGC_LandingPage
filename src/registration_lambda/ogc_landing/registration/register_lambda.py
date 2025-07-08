# Copyright (c) 2025
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import unicodedata
import os
import base64
from urllib.parse import unquote

import boto3
import uuid
from datetime import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_der_public_key
from ogc_landing.security import user_exists, create_user


def format_error_response(status_code, title, detail, accept_header, html_params: dict):
    """
    Formats an error response based on the Accept header.

    Parameters:
        status_code (int): HTTP status code
        title (str): Error title
        detail (str): Detailed error message
        accept_header (str): Accept header from the request
        html_params (dict): Additional parameters for HTML formatting
            - current_year: Current year for copyright
            - page_title: Title of the page
            - header_title: Title in the header section
            - nav_links: Navigation links HTML
            - error_title: Title of the error section
            - try_again_link: Link for trying again

    Returns:
        dict: API Gateway response formatted according to Accept header
    """
    current_year = html_params.get('current_year', datetime.now().year)
    page_title = html_params.get('page_title', 'Registration')
    header_title = html_params.get('header_title', 'Registration')
    nav_links = html_params.get('nav_links', f'<a href="/">Home</a> &gt; <a href="/register">Registration</a>')
    error_title = html_params.get('error_title', 'Registration Failed')
    try_again_link = html_params.get('try_again_link', '<a href="/register">Try Again</a>')

    if 'application/json' in accept_header or 'application/problem+json' in accept_header:
        return {
            'statusCode': status_code,
            'headers': {'Content-Type': 'application/problem+json'},
            'body': f'{{"type": "about:blank", "title": "{title}", "status": {status_code}, '
                    f'"detail": "{detail}"}}',
            'isBase64Encoded': False
        }

    else:
        body = '\r'.join([
            '<!DOCTYPE HTML>',
            '<html lang="en">',
            '    <head>',
            f'        <title>{page_title}</title>',
            '        <style>',
            '            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }',
            '            header, nav, section, footer { margin-bottom: 20px; }',
            '            header { background-color: #f5f5f5; padding: 10px; }',
            '            nav { background-color: #eee; padding: 10px; }',
            '            .content { padding: 20px; border: 1px solid #ddd; }',
            '            .hidden { display: none; }',
            '            footer { text-align: center; font-size: 0.8em; color: #666; }',
            '        </style>',
            '    </head>',
            '    <body>',
            '        <header>',
            f'            <h1>{header_title}</h1>',
            '        </header>',
            '        <nav>',
            f'            {nav_links}',
            '        </nav>',
            '        <section class="content">',
            f'            <h1>{error_title}</h1>',
            f'            <p>{detail}</p>',
            f'            <p>{try_again_link}</p>',
            '        </section>',
            '        <footer>',
            f'            &copy; {current_year} Michael Leedahl',
            '        </footer>',
            '    </body>',
            '</html>'
        ])

        return {
            'statusCode': status_code,
            'headers': {'Content-Type': 'text/html; charset=utf-8'},
            'body': body,
            'isBase64Encoded': False
        }


def get_public_key_from_kms():
    """
    Retrieves the public key in PEM format from KMS using the key ARN from environment variables.

    Returns:
        Tuple[str, bytes]: (The PEM-encoded public key, The DER-encoded public key)
    """
    encryption_key_arn = os.environ.get('encryption_key_arn')
    if not encryption_key_arn:
        raise ValueError("Encryption Key ARN not found in environment variables")

    kms_client = boto3.client('kms')
    response = kms_client.get_public_key(KeyId=encryption_key_arn)

    # Convert a DER format to PEM format
    der_data = response['PublicKey']
    key = load_der_public_key(der_data)
    pem_data = key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf_8')

    return pem_data, der_data


def handle_registration_id_request(event: dict):
    """
    Handles a request to the /registration-id endpoint.
    Creates and returns a new registration ID.

    Parameters:
        event (dict): the request body.

    Returns:
        dict: API Gateway response containing the new registration ID
    """
    try:
        # Generate a UUID for this registration
        registration_id = str(uuid.uuid4())

        # Store the registration_id in the DynamoDB table with a "pending" status
        try:
            dynamodb = boto3.resource('dynamodb')
            registration_table = dynamodb.Table(os.environ.get('registration_id_table'))
            registration_table.put_item(
                Item={
                    'registration_id': registration_id,
                    'status': 'pending',
                    'timestamp': datetime.now().isoformat()
                }
            )

        except Exception as e:
            print(f"Error storing registration ID: {str(e)}")
            raise e

        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': f'{{"registration_id": "{registration_id}"}}',
            'isBase64Encoded': False
        }

    except Exception as e:
        # Get the Accept header from the event
        accept_header = event.get('headers', {}).get('Accept', '')
        current_year = datetime.now().year
        html_params = {
            'current_year': current_year,
            'page_title': 'Registration ID',
            'header_title': 'Registration ID',
            'nav_links': f'<a href="/">Home</a> &gt; <a href="/registration-id">Registration ID</a>',
            'error_title': 'Error',
            'try_again_link': '<a href="/">Return to Home</a>'
        }

        return format_error_response(
            500, 
            "Internal Server Error", 
            f"Failed to create registration ID: {str(e)}", 
            accept_header,
            html_params
        )


def handle_public_key_request(event: dict):
    """
    Handles a request to the /public-key endpoint.
    Parameters:
        event (dict): the request body.

    Returns:
        dict: API Gateway response containing the public key
    """
    try:
        pem_data, _ = get_public_key_from_kms()
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/x-pem-file'},
            'body': pem_data,
            'isBase64Encoded': False
        }

    except Exception as e:
        # Get the Accept header from the event
        accept_header = event.get('headers', {}).get('Accept', '')
        current_year = datetime.now().year
        html_params = {
            'current_year': current_year,
            'page_title': 'Public Key',
            'header_title': 'Public Key',
            'nav_links': f'<a href="/">Home</a> &gt; <a href="/public-key">Public Key</a>',
            'error_title': 'Error',
            'try_again_link': '<a href="/">Return to Home</a>'
        }

        return format_error_response(
            500, 
            "Internal Server Error", 
            f"Failed to retrieve public key: {str(e)}", 
            accept_header,
            html_params
        )


# noinspection PyUnusedLocal
def lambda_handler(event, context):
    # Check if this is a request to the public key endpoint
    path = event.get('path', '')
    if path == '/public-key':
        return handle_public_key_request(event)

    # Check if this is a request to the registration ID endpoint
    elif path == '/registration-id':
        return handle_registration_id_request(event)

    # Extract host and protocol information
    headers = event.get('headers', {})
    current_year = datetime.now().year  # Dynamically get the current year

    event_body = event.get('body', '')
    event_body = event_body if event_body is not None else ''
    if event_body != '':
        values = {}
        for param in event_body.split('&'):
            if '=' in param:
                key, value = param.split('=', 1)
                values[key] = value

        # Check if we have encrypted values
        if 'encrypted_username' in values and 'encrypted_password' in values:

            # Decrypt the username and password
            try:
                # Get the encryption key ARN
                encryption_key_arn = os.environ.get('encryption_key_arn')
                if not encryption_key_arn:
                    # Determine a response format based on Accept header
                    accept_header = headers.get('Accept', '')
                    return format_error_response(
                        500,
                        "Internal Server Error",
                        "Encryption Key ARN not found in environment variables",
                        accept_header,
                        {'current_year': current_year}
                    )

                kms_client = boto3.client('kms')

                # Decrypt username
                bin_string_username = base64.b64decode(unquote(values['encrypted_username'])).decode('utf_8')
                int_username = int(bin_string_username, 2)
                encrypted_username = int_username.to_bytes(len(bin_string_username) // 8, byteorder='big')
                print(f'Encrypted username: {encrypted_username}')

                username_response = kms_client.decrypt(
                    KeyId=encryption_key_arn,
                    CiphertextBlob=encrypted_username,
                    EncryptionAlgorithm='RSAES_OAEP_SHA_256'
                )
                username = username_response['Plaintext'].decode('utf_8')

                # Decrypt password
                bin_string_password = base64.b64decode(unquote(values['encrypted_password'])).decode('utf_8')
                int_password = int(bin_string_password, 2)
                encrypted_password = int_password.to_bytes(len(bin_string_password) // 8, byteorder='big')
                password_response = kms_client.decrypt(
                    KeyId=encryption_key_arn,
                    CiphertextBlob=encrypted_password,
                    EncryptionAlgorithm='RSAES_OAEP_SHA_256'
                )
                password = password_response['Plaintext'].decode('utf_8')

            except Exception as e:
                # Determine a response format based on Accept header
                accept_header = headers.get('Accept', '')
                return format_error_response(
                    400,
                    "Bad Request",
                    f"Error decrypting data: {str(e)}",
                    accept_header,
                    {'current_year': current_year}
                )
        else:
            # Return an error response if encrypted credentials are not provided
            # Determine a response format based on Accept header
            accept_header = headers.get('Accept', '')
            return format_error_response(
                400,
                "Bad Request",
                "Encrypted username and password are required",
                accept_header,
                {'current_year': current_year}
            )

        # Validate registration_id
        if 'registration_id' not in values:
            # Determine a response format based on Accept header
            accept_header = headers.get('Accept', '')
            return format_error_response(
                400,
                "Bad Request",
                "Registration ID is required. Please try again.",
                accept_header,
                {'current_year': current_year}
            )

        # Check if registration_id exists and is in pending state
        dynamodb = boto3.resource('dynamodb')
        registration_table = dynamodb.Table(os.environ.get('registration_id_table'))
        try:
            response = registration_table.get_item(
                Key={
                    'registration_id': values['registration_id']
                }
            )

            if 'Item' not in response:
                # Determine a response format based on Accept header
                accept_header = headers.get('Accept', '')
                return format_error_response(
                    400,
                    "Bad Request",
                    "Invalid registration ID. Please try again.",
                    accept_header,
                    {'current_year': current_year}
                )

            registration_item = response['Item']
            if registration_item['status'] != 'pending':
                # Determine a response format based on Accept header
                accept_header = headers.get('Accept', '')
                return format_error_response(
                    400,
                    "Bad Request",
                    "Replay attack detected. Please try again.",
                    accept_header,
                    {'current_year': current_year}
                )

            # Check if the registration ID has expired (after 1 minute)
            registration_timestamp = datetime.fromisoformat(registration_item['timestamp'])
            current_time = datetime.now()
            time_difference = current_time - registration_timestamp
            if time_difference.total_seconds() > 60:  # 60 seconds = 1 minute
                # Determine a response format based on Accept header
                accept_header = headers.get('Accept', '')
                return format_error_response(
                    400,
                    "Bad Request",
                    "Registration ID has expired. Please try again with a new registration.",
                    accept_header,
                    {'current_year': current_year}
                )

        except Exception as e:
            print(f"Error validating registration ID: {str(e)}")
            # Return an error response if there's an internal error validating the registration ID
            accept_header = headers.get('Accept', '')
            return format_error_response(
                500,
                "Internal Server Error",
                "An error occurred while validating your registration. Please try again later.",
                accept_header,
                {'current_year': current_year}
            )

        # Validate username
        if not _validate_username(username):
            error_message = ("Invalid username. Username must contain only alphabetical and numerical characters, "
                             "periods (.), underscores (_), and dashes (-).")

            # Determine a response format based on Accept header
            accept_header = headers.get('Accept', '')
            return format_error_response(
                400,
                "Bad Request",
                error_message,
                accept_header,
                {'current_year': current_year}
            )

        # Check if user already exists
        if user_exists(username):
            error_message = "A user with this username already exists. Please choose a different username."

            # Determine a response format based on Accept header
            accept_header = headers.get('Accept', '')
            return format_error_response(
                409,  # Conflict
                "Conflict",
                error_message,
                accept_header,
                {'current_year': current_year}
            )

        # Create the user with the given username and password
        create_user(username, password)

        # Update the registration_id status to "used"
        try:
            registration_table.update_item(
                Key={
                    'registration_id': values['registration_id']
                },
                UpdateExpression="set #status = :s, updated_at = :t",
                ExpressionAttributeNames={
                    '#status': 'status'
                },
                ExpressionAttributeValues={
                    ':s': 'used',
                    ':t': datetime.now().isoformat()
                }
            )

        except Exception as e:
            print(f"Error updating registration ID status: {str(e)}")
            # Continue even if there's an error, as the user has been created successfully

        # Determine a response format based on Accept header
        accept_header = headers.get('Accept', '')

        if 'application/json' in accept_header:
            # JSON response
            body = f'{{"message": "Registration successful", "username": "{username}"}}'
            content_type = 'application/json'

        else:
            # HTML response (default)
            body = '\r'.join([
                '<!DOCTYPE HTML>',
                '<html lang="en">',
                '    <head>',
                '        <title>Registration</title>',
                '        <style>',
                '            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }',
                '            header, nav, section, footer { margin-bottom: 20px; }',
                '            header { background-color: #f5f5f5; padding: 10px; }',
                '            nav { background-color: #eee; padding: 10px; }',
                '            .content { padding: 20px; border: 1px solid #ddd; }',
                '            .hidden { display: none; }',
                '            footer { text-align: center; font-size: 0.8em; color: #666; }',
                '        </style>',
                '    </head>',
                '    <body>',
                '        <header>',
                '            <h1>Registration</h1>',
                '        </header>',
                '        <nav>',
                f'            <a href="/">Home</a> &gt; <a href="/register">Registration</a>',
                '        </nav>',
                '        <section class="content">',
                '            <h1>Thank you for registering for Michael\'s Wonderful APIs!</h1>',
                '            <p>You may now use the the APIs as described in the API documentation on the homepage.<br>',
                '            <a href="/user-management">User Management</a></p>',
                '        </section>',
                '        <footer>',
                f'            &copy; {current_year} Michael Leedahl',
                '        </footer>',
                '        <script>showSection();</script>',
                '    </body>',
                '</html>'
            ])
            content_type = 'text/html; charset=utf-8'

    else:
        # Generate a UUID for this registration session
        registration_id = str(uuid.uuid4())

        # Store the registration_id in the DynamoDB table with a "pending" status
        try:
            dynamodb = boto3.resource('dynamodb')
            registration_table = dynamodb.Table(os.environ.get('registration_id_table'))
            registration_table.put_item(
                Item={
                    'registration_id': registration_id,
                    'status': 'pending',
                    'timestamp': datetime.now().isoformat()
                }
            )
        except Exception as e:
            print(f"Error storing registration ID: {str(e)}")
            # Continue even if there's an error, as we'll validate in the POST request

        # Get the certificate for client-side encryption
        try:
            _, der = get_public_key_from_kms()
            encoded_pem = base64.b64encode(der).decode('ascii')

        except Exception as e:
            encoded_pem = ""
            print(f"Error retrieving certificate: {str(e)}")

        body = '\r'.join([
            '<!DOCTYPE HTML>',
            '<html lang="en">',
            '    <head>',
            '        <title>Registration</title>',
            '        <style>',
            '            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }',
            '            header, nav, section, footer { margin-bottom: 20px; }',
            '            header { background-color: #f5f5f5; padding: 10px; }',
            '            nav { background-color: #eee; padding: 10px; }',
            '            .content { padding: 20px; border: 1px solid #ddd; }',
            '            footer { text-align: center; font-size: 0.8em; color: #666; }',
            '        </style>',
            '    </head>',
            '    <body>',
            '        <header><h1>Registration</h1></header>',
            '        <nav><a href="/">Home</a> &gt; <a href="/register">Registration</a></nav>',
            '        <section class="content">',
            "            <h1>Welcome to Michael's Wonderful API Registration</h1>",
            '            <p>You can register to use the Greeting API by creating a username and password:</p>',
            '            <form id="user_data" action="/register" method="POST">',
            '                <p><label for="username">Username: </label><input type="text" id="username" /></p>',
            '                <p><label for="password">Password: </label><input type="password" id="password" /></p>',
            '                <input type="hidden" id="encrypted_username" name="encrypted_username" />',
            '                <input type="hidden" id="encrypted_password" name="encrypted_password" />',
            '                <input type="hidden" id="registration_id" name="registration_id" '
            f'value="{registration_id}" />',
            '                <p><input type="submit" value="Register" /></p>',
            '            </form>',
            '            <script>',
            '                async function rsaOAEPEncrypt(publicKey, data) {',
            '                    const encodedData = new TextEncoder().encode(data);',
            '                    const encryptedData = await window.crypto.subtle.encrypt(',
            '                        {',
            '                          name: "RSA-OAEP"',
            '                        },',
            '                        publicKey,',
            '                        encodedData',
            '                    );',
            '                    ',
            '                    return new Uint8Array(encryptedData);',
            '                }',
            '                ',
            '                // Converts an array buffer to a binary string.',
            '                function arrayBufferToBinaryString(buffer) {',
            '                    const uint8Array = new Uint8Array(buffer);',
            '                    let binaryString = "";',
            '                    ',
            '                    for (let i = 0; i < uint8Array.length; i++) {',
            '                        // Convert the byte to its binary representation',
            '                        const binaryByte = uint8Array[i].toString(2);',
            '                        ',
            '                        // Pad with leading zeros to ensure 8 bits',
            "                        const paddedBinaryByte = '00000000'.substring(binaryByte.length) + binaryByte;",
            '                        binaryString += paddedBinaryByte;',
            '                    }',
            '                    ',
            '                    return binaryString;',
            '                }',
            '                ',
            '                function stringToArrayBuffer(stringValue) {',
            '                    const buf = new ArrayBuffer(stringValue.length);',
            '                    const bufView = new Uint8Array(buf);',
            '                    for (let i = 0, strLen = stringValue.length; i < strLen; i++) {',
            '                        bufView[i] = stringValue.charCodeAt(i);',
            '                    }',
            '                    ',
            '                    return buf',
            '                }',
            '                ',
            '                // Function to encrypt data with the public key',
            '                async function encryptData() {',
            '                    try {'
            '                        // Store the certificate',
            f'                        const decoded_der = stringToArrayBuffer(atob("{encoded_pem}"));',
            '                        const der_key = await crypto.subtle.importKey("spki", decoded_der, {',
            '                            name: "RSA-OAEP",',
            '                            hash: "SHA-256"',
            '                        }, true, ["encrypt"],);',
            '                        ',
            '                        const username = document.getElementById("username").value;',
            '                        const password = document.getElementById("password").value;',
            '                        ',
            '                        // Encrypt the username and password',
            '                        const encryptedUsername = await rsaOAEPEncrypt(der_key, username);',
            '                        const encryptedPassword = await rsaOAEPEncrypt(der_key, password);'
            '                        ',
            '                        // Base64 encode the encrypted values',
            '                        const base64Username = btoa(arrayBufferToBinaryString(encryptedUsername));',
            '                        const base64Password = btoa(arrayBufferToBinaryString(encryptedPassword));',
            '                        ',
            '                        // Set the base64 encoded encrypted values in hidden fields',
            '                        document.getElementById("encrypted_username").value = base64Username;',
            '                        document.getElementById("encrypted_password").value = base64Password;',
            '                        ',
            '                        // Return true to allow the form submission to proceed',
            '                    } catch(e) {',
            '                        console.log(e.message);'
            '                        return false'
            '                    }'
            '                    '
            '                    return true;',
            '                }',
            '                ',
            '                const form = document.getElementById("user_data");',
            '                form.addEventListener("submit", async function(event) {',
            '                    event.preventDefault(); // Prevent default form submission',
            '                    ',
            '                    try {',
            '                        const success = await encryptData();',
            '                        if (success) {',
            '                            console.log("Form processing complete and successful.");',
            '                            event.target.submit(); ',
            '                        } else {',
            '                            console.log("Form processing failed.");',
            '                        }',
            '                    } catch (error) {',
            '                        console.error("An error occurred during form submission:", error);',
            '                    }',
            '                });',
            '            </script>',
            '        </section>',
            '        <footer>',
            f'            &copy; {current_year} Michael Leedahl',
            '        </footer>',
            '    </body>',
            '</html>',
        ])
        content_type = 'text/html; charset=utf-8'

    return {
        'statusCode': 200,
        'headers': {'Content-Type': content_type},
        'body': body,
        'isBase64Encoded': False
    }


def _validate_username(username):
    """
    Validates that the username only uses UTF-8 character set and limits characters
    to alphabetical and numerical with consideration for other languages besides English.

    Args:
        username (str): The username to validate

    Returns:
        bool: True if the username is valid, False otherwise
    """
    # Check if the username is empty
    if not username:
        return False

    try:
        # Ensure the username is valid UTF-8
        username.encode('utf-8').decode('utf-8')

        # Check if the username contains only letters, numbers, periods, underscores, and dashes
        for char in username:
            category = unicodedata.category(char)
            # L* categories are letters, N* categories are numbers
            # Also allow periods, underscores, and dashes
            if not (category.startswith('L') or category.startswith('N') or char in ['.', '_', '-']):
                return False

        return True

    except UnicodeError:
        # If there's an encoding/decoding error, the username is not valid UTF-8
        return False
