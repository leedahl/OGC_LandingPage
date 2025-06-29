# Copyright (c) 2025
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import base64
import binascii
import re
import boto3
import os
import hashlib
import json
from enum import Enum
from typing import Optional


class _AuthenticationStatus(Enum):
    UNAUTHORIZED = 'Unauthorized'
    FORBIDDEN = 'Forbidden'


# noinspection PyUnusedLocal
def lambda_handler(event, context):
    # Check if this is a request from the decision endpoint
    is_decision_path = False
    if 'path' in event:
        is_decision_path = event['path'] == '/decision'

    if (
            is_decision_path and 
            'body' in event and 
            event['body'] is not None
    ):
        print('Processing Decision Endpoint Request')
        try:
            # Use the body of the request as the event to process
            body_event = json.loads(event['body'])
            body_event['isDecisionPath'] = True

            # Process the body event
            return lambda_handler(body_event, context)

        except json.JSONDecodeError:
            print('Invalid JSON in request body')
            return deny_access(
                _AuthenticationStatus.UNAUTHORIZED, event.get('methodArn', 'unknown'), 
                is_decision_path=is_decision_path
            )

    is_decision_path = event.get('isDecisionPath', False)
    if (
            ('requestContext' in event) and ('identity' in event['requestContext'])
            and ('clientCert' in event['requestContext']['identity'])
    ):
        print('Processing Certificate Authorization Request')
        result = process_cert_authorization(event, is_decision_path)

    elif all([
        event.get('headers', dict()) is not None,
        (
                (
                        ('Authorization' in event.get('headers', dict())) and
                        event.get('headers', dict())['Authorization'].startswith('Basic ')
                ) or
                (
                    ('authorization' in event.get('headers', dict())) and
                    event.get('headers', dict())['authorization'].startswith('Basic ')
                )
        )
    ]):
        result = process_header_authorization(event, is_decision_path)

    else:
        result = deny_access(
            _AuthenticationStatus.UNAUTHORIZED, event.get('methodArn', 'unknown'),
            is_decision_path=is_decision_path
        )

    return result


def process_cert_authorization(event: dict, is_decision_path: bool = False) -> dict:
    cert = event['requestContext']['identity']['clientCert']
    subject_dn = cert['subjectDN'].split(',')
    subject_map = dict(
        {item.split('=')[0]: item.split('=')[1] for item in subject_dn}
    )
    username = subject_map['CN']
    password = cert['clientCertPem']
    http_method = event['requestContext']['httpMethod']
    method_arn = event['methodArn']

    return process_authorization(username, password, http_method, method_arn, is_decision_path)


def process_header_authorization(event: dict, is_decision_path: bool = False) -> dict:
    try:
        authorization_header = 'Authorization' if 'Authorization' in event['headers'] else 'authorization'
        b64_value = event['headers'][authorization_header].replace('Basic ', '')
        value = base64.b64decode(b64_value, validate=True).decode('utf_8')
        matches = re.match(
            '^([A-Za-z0-9_.@-]*):'
            '([A-Za-z0-9!@#$%^&*()\\[\\]\\\\{};<>,.?/~`+=_-]*$)', value
        )
        if (matches is None) or (matches == ''):
            raise ValueError('Username/password incorrectly mapped within Authentication header.')

        username = matches.group(1)
        password = matches.group(2)
        http_method = event['requestContext']['httpMethod']
        method_arn = event['methodArn']

        print(f'Processing Authorization Request for {username}.')
        result = process_authorization(username, password, http_method, method_arn, is_decision_path)

    except binascii.Error:
        print({'error': 'Invalid encoding in Authentication header.'})
        result = deny_access(_AuthenticationStatus.UNAUTHORIZED, event['methodArn'], is_decision_path=is_decision_path)

    except ValueError:
        print({'error': 'Username/password incorrectly mapped within Authentication header.'})

        result = deny_access(_AuthenticationStatus.UNAUTHORIZED, event['methodArn'], is_decision_path=is_decision_path)

    return result


def process_authorization(
        username: str, password: str, http_method: str, method_arn: str, 
        is_decision_path: bool = False
) -> dict:
    db_client = boto3.client('dynamodb')
    item_result = db_client.get_item(
        TableName='user_store', Key={'username': {'S': username}},
        ConsistentRead=True, ProjectionExpression='password,salt'
    )

    if 'Item' in item_result:
        print(f'A record for {username} was found.')
        cipher_text = item_result['Item']['password']['B']

        # Get the salt from the item result
        salt = item_result['Item']['salt']['S'] if 'salt' in item_result['Item'] else None

        key_alias = os.environ.get('key_alias', 'hello_world')

        kms_client = boto3.client('kms')
        response = kms_client.decrypt(
            CiphertextBlob=cipher_text,
            KeyId=f'alias/{key_alias}'
        )

        db_password = response['Plaintext'].decode('utf_8')

        kms_client.close()
        print(f'The password for {username} was decoded.')

    else:
        db_password = None
        salt = None

    # With our new approach, the decrypted value from the database is the SHA-256 hash of the salted password
    if salt:
        print(f'The salt for {username} was found.')
        # Combine salt with the provided password
        salted_password = f"{salt}:{password}"

        # Hash the salted password with SHA-256
        hashed_salted_password = hashlib.sha256(salted_password.encode('utf_8')).hexdigest()

        # Compare the hash with the decrypted value from the database
        password_matches = db_password == hashed_salted_password
        print(f'The password match result: {password_matches}.')

    else:
        password_matches = False

    # Check if this is an openapi request with an api_id
    method_arn_parts = method_arn.split(':')
    api_parts = method_arn_parts[5].split('/')

    # Check if this is an openapi request with an api_id
    is_openapi_request = len(api_parts) >= 6 and api_parts[4] == 'openapi' and len(api_parts) > 4
    print(f'is_openapi_request: {is_openapi_request}')

    # If this is an openapi request with an api_id, check if the user owns the API
    if (is_openapi_request and
        ('Item' in item_result) and 
        ('password' in item_result['Item']) and 
        password_matches and 
        (db_password is not None)):

        api_id = api_parts[5]

        # Check if the user owns this API ID
        api_security_result = db_client.get_item(
            TableName='api_security',
            Key={
                'username': {'S': username},
                'api_id': {'S': api_id}
            },
            ConsistentRead=True
        )

        if 'Item' not in api_security_result:
            # User doesn't own this API ID
            return deny_access(_AuthenticationStatus.FORBIDDEN, method_arn, username, is_decision_path=is_decision_path)

    if 'Item' in item_result and 'password' in item_result['Item'] and password_matches and db_password is not None:
        match http_method:
            case 'GET':
                # noinspection PyUnusedLocal
                request_valid = True

            case 'PUT':
                # noinspection PyUnusedLocal
                request_valid = (
                    'data_management/backup' in method_arn or
                    'data_management/restore' in method_arn
                )

            case 'POST':
                # noinspection PyUnusedLocal
                request_valid = (
                        'user-management' in method_arn or
                        'openapi' in method_arn or
                        'csr' in method_arn
                )

            case 'DELETE':
                # noinspection PyUnusedLocal
                request_valid = (
                        'user-management' in method_arn or
                        'csr' in method_arn or
                        'data_management/delete' in method_arn
                )

            case _:
                # noinspection PyUnusedLocal
                request_valid = False
    else:
        request_valid = False

    if request_valid:
        print(f'The password for {username} matches and an Allow Result is being produced.')
        result = allow_access(method_arn, username, is_decision_path=is_decision_path)

    else:
        print(f'The password for {username} does not match an a Deny Result is being produced.')
        result = deny_access(_AuthenticationStatus.FORBIDDEN, method_arn, username, is_decision_path=is_decision_path)

    return result


def deny_access(status: _AuthenticationStatus, method_arn: str, user: Optional[str] = None, is_decision_path: bool = False) -> dict:
    if method_arn == 'unknown':
        # Handle a case where methodArn is not provided
        response = {
            "statusCode": 401,
            "body": status.value
        }

    elif status == _AuthenticationStatus.FORBIDDEN:
        response = (
            response_dictionary('Deny', method_arn, is_decision_path=is_decision_path) if user is None
            else response_dictionary('Deny', method_arn, user, is_decision_path=is_decision_path)
        )

    else:
        response = {
            "statusCode": 401,
            "body": status.value
        }

    print_message = {
        **({'user': user} if user is not None else {}),
        'status': status.value, 'resource': method_arn
    }
    print(print_message)

    # If this is a decision path request, format the response for API Gateway
    if is_decision_path:
        if isinstance(response, dict) and "policyDocument" in response:
            # This is already a policy document, wrap it in API Gateway format
            return {
                "statusCode": 200,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps(response)
            }

        # Otherwise, it's already formatted for API Gateway
        return response

    else:
        # Return the standard response
        return response


def allow_access(method_arn: str, user: str, is_decision_path: bool = False) -> dict:
    print({'user': user, 'action': 'Allow', 'resource': method_arn})

    response = response_dictionary('Allow', method_arn, user, is_decision_path=is_decision_path)

    # If this is a decision path request, format the response for API Gateway
    if is_decision_path:
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(response),
            'isBase64Encoded': False
        }

    else:
        return response


def response_dictionary(action: str, method_arn: str, user: str = 'user', is_decision_path: bool = False) -> dict:
    """
    Generates the policy document to return to the API Gateway.  The
    Gateway uses the document to decide if it can invoke lambdas in the API.

    :param action: The action in the policy (Allow or Deny).
    :param method_arn: The ARN for the method to execute.
    :param user: The username to use as the identifier for the principal.
    :param is_decision_path: Whether this is a request from the decision endpoint.
    """
    method_arn_parts = method_arn.split(':')
    api_parts = method_arn_parts[5].split('/')
    new_method_arn = ':'.join(method_arn_parts[:-1])
    new_method_arn += f":{'/'.join(api_parts[0:3])}"
    new_method_arn += '/*'

    return {
        "principalId": user,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": action,
                    "Resource": new_method_arn
                }
            ]
        }
    }
