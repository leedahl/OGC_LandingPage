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
from enum import Enum
from typing import Optional


class _AuthenticationStatus(Enum):
    UNAUTHORIZED = 'Unauthorized'
    FORBIDDEN = 'Forbidden'


# noinspection PyUnusedLocal
def lambda_handler(event, context):
    print(event)

    if (
            ('requestContext' in event) and ('identity' in event['requestContext'])
            and ('clientCert' in event['requestContext']['identity'])
    ):
        result = process_cert_authorization(event)

    elif all([
        event.get('headers', dict()) is not None,
        (
                ('Authorization' in event.get('headers', dict())) and
                event.get('headers', dict())['Authorization'].startswith('Basic ')
        )
    ]):
        result = process_header_authorization(event)

    else:
        result = deny_access(
            _AuthenticationStatus.UNAUTHORIZED, event['methodArn']
        )

    return result


def process_cert_authorization(event: dict) -> dict:
    cert = event['requestContext']['identity']['clientCert']
    subject_dn = cert['subjectDN'].split(',')
    subject_map = dict(
        {item.split('=')[0]: item.split('=')[1] for item in subject_dn}
    )
    username = subject_map['CN']
    password = cert['clientCertPem']
    http_method = event['requestContext']['httpMethod']
    method_arn = event['methodArn']

    return process_authorization(username, password, http_method, method_arn)


def process_header_authorization(event: dict) -> dict:
    try:
        b64_value = event['headers']['Authorization'].replace('Basic ', '')
        value = base64.b64decode(b64_value, validate=True).decode('ascii')
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

        result = process_authorization(username, password, http_method, method_arn)

    except binascii.Error:
        print({'error': 'Invalid encoding in Authentication header.'})
        result = deny_access(_AuthenticationStatus.UNAUTHORIZED, event['methodArn'])

    except ValueError:
        print({'error': 'Username/password incorrectly mapped within Authentication header.'})

        result = deny_access(_AuthenticationStatus.UNAUTHORIZED, event['methodArn'])

    return result


def process_authorization(
        username: str, password: str, http_method: str, method_arn: str
) -> dict:
    db_client = boto3.client('dynamodb')
    item_result = db_client.get_item(
        TableName='user_store', Key={'username': {'S': username}},
        ConsistentRead=True, ProjectionExpression='password,salt'
    )

    if 'Item' in item_result:
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

    else:
        db_password = None
        salt = None

    # Check if the stored password contains the salt format
    if db_password and ':' in db_password and salt:
        # The stored password already includes the salt in format "salt:password"
        # Compare with the provided password
        stored_salt, stored_password = db_password.split(':', 1)
        password_matches = stored_password == password

    elif salt:
        # Need to combine salt with provided password for comparison
        salted_password = f"{salt}:{password}"
        password_matches = db_password == salted_password

    else:
        # Fallback for old entries without salt
        password_matches = db_password == password

    if (
            ('Item' in item_result) and
            ('password' in item_result['Item']) and
            password_matches and
            (http_method == 'GET' or 
             (http_method == 'POST' and 'user-management' in method_arn)) and
            (db_password is not None)
    ):
        result = allow_access(method_arn, username)

    else:
        result = deny_access(_AuthenticationStatus.FORBIDDEN, method_arn, username)

    return result


def deny_access(status: _AuthenticationStatus, method_arn: str, user: Optional[str] = None) -> dict:
    if status == _AuthenticationStatus.FORBIDDEN:
        response = (
            response_dictionary('Deny', method_arn) if user is None
            else response_dictionary('Deny', method_arn, user)
        )

    else:
        response = {
            "statusCode": 401,
            "body": status.value
        }

    print_message = {'user': user} if user is not None else {}
    print_message.update({'status': status.value, 'resource': method_arn})
    print(print_message)

    return response


def allow_access(method_arn: str, user: str) -> dict:
    print({'user': user, 'action': 'Allow', 'resource': method_arn})

    return response_dictionary('Allow', method_arn, user)


def response_dictionary(action: str, method_arn: str, user: str = 'user') -> dict:
    """
    Generates the policy document to return to the API Gateway.  The
    Gateway uses the document to decide if it can invoke lambdas in the API.

    :param action: The action in the policy (Allow or Deny).
    :param method_arn: The ARN for the method to execute.
    :param user: The username to use as the identifier for the principal.
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
