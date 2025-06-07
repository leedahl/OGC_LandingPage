# Copyright (c) 2025
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import unittest
from unittest.mock import patch, MagicMock
import base64

# noinspection PyProtectedMember
from ogc_landing.authorizer.authorizer_lambda import (
    _AuthenticationStatus,
    lambda_handler,
    process_cert_authorization,
    process_header_authorization,
    process_authorization,
    deny_access,
    allow_access,
    response_dictionary
)


class TestAuthenticationStatus(unittest.TestCase):
    """Test cases for the _AuthenticationStatus enum class."""

    def test_authentication_status_values(self):
        """Test that the enum has the expected values."""
        self.assertEqual(_AuthenticationStatus.UNAUTHORIZED.value, 'Unauthorized')
        self.assertEqual(_AuthenticationStatus.FORBIDDEN.value, 'Forbidden')


class TestLambdaHandler(unittest.TestCase):
    """Test cases for the lambda_handler function."""

    @patch('ogc_landing.authorizer.authorizer_lambda.process_cert_authorization')
    def test_lambda_handler_with_cert(self, mock_process_cert):
        """Test lambda_handler with client certificate."""
        # Setup
        mock_process_cert.return_value = {"result": "success"}
        event = {
            'requestContext': {
                'identity': {
                    'clientCert': {}
                }
            },
            'methodArn': 'arn:aws:execute-api:region:account:api/stage/method/resource'
        }

        # Execute
        result = lambda_handler(event, {})

        # Verify
        mock_process_cert.assert_called_once_with(event)
        self.assertEqual(result, {"result": "success"})

    @patch('ogc_landing.authorizer.authorizer_lambda.process_header_authorization')
    def test_lambda_handler_with_basic_auth(self, mock_process_header):
        """Test lambda_handler with Basic Authentication header."""
        # Setup
        mock_process_header.return_value = {"result": "success"}
        event = {
            'headers': {
                'Authorization': 'Basic dXNlcjpwYXNzd29yZA=='  # user:password in base64
            },
            'methodArn': 'arn:aws:execute-api:region:account:api/stage/method/resource',
            'requestContext': {}
        }

        # Execute
        result = lambda_handler(event, {})

        # Verify
        mock_process_header.assert_called_once_with(event)
        self.assertEqual(result, {"result": "success"})

    @patch('ogc_landing.authorizer.authorizer_lambda.deny_access')
    def test_lambda_handler_with_no_auth(self, mock_deny_access):
        """Test lambda_handler with no authentication."""
        # Setup
        mock_deny_access.return_value = {"result": "unauthorized"}
        event = {
            'headers': {},
            'methodArn': 'arn:aws:execute-api:region:account:api/stage/method/resource',
            'requestContext': {}
        }

        # Execute
        result = lambda_handler(event, {})

        # Verify
        mock_deny_access.assert_called_once_with(
            _AuthenticationStatus.UNAUTHORIZED, event['methodArn']
        )
        self.assertEqual(result, {"result": "unauthorized"})


class TestProcessCertAuthorization(unittest.TestCase):
    """Test cases for the process_cert_authorization function."""

    @patch('ogc_landing.authorizer.authorizer_lambda.process_authorization')
    def test_process_cert_authorization(self, mock_process_auth):
        """Test process_cert_authorization with valid certificate."""
        # Setup
        mock_process_auth.return_value = {"result": "success"}
        event = {
            'requestContext': {
                'identity': {
                    'clientCert': {
                        'subjectDN': 'CN=username,O=organization',
                        'clientCertPem': 'certificate-content'
                    }
                },
                'httpMethod': 'GET'
            },
            'methodArn': 'arn:aws:execute-api:region:account:api/stage/method/resource'
        }

        # Execute
        result = process_cert_authorization(event)

        # Verify
        mock_process_auth.assert_called_once_with(
            'username', 'certificate-content', 'GET', event['methodArn']
        )
        self.assertEqual(result, {"result": "success"})


class TestProcessHeaderAuthorization(unittest.TestCase):
    """Test cases for the process_header_authorization function."""

    @patch('ogc_landing.authorizer.authorizer_lambda.process_authorization')
    def test_process_header_authorization_valid(self, mock_process_auth):
        """Test process_header_authorization with valid Basic Auth header."""
        # Setup
        mock_process_auth.return_value = {"result": "success"}
        # Base64 encoded "user:password"
        auth_header = 'Basic ' + base64.b64encode(b'user:password').decode('ascii')
        event = {
            'headers': {
                'Authorization': auth_header
            },
            'requestContext': {
                'httpMethod': 'GET'
            },
            'methodArn': 'arn:aws:execute-api:region:account:api/stage/method/resource'
        }

        # Execute
        result = process_header_authorization(event)

        # Verify
        mock_process_auth.assert_called_once_with(
            'user', 'password', 'GET', event['methodArn']
        )
        self.assertEqual(result, {"result": "success"})

    @patch('ogc_landing.authorizer.authorizer_lambda.deny_access')
    def test_process_header_authorization_invalid_encoding(self, mock_deny_access):
        """Test process_header_authorization with invalid Base64 encoding."""
        # Setup
        mock_deny_access.return_value = {"result": "unauthorized"}
        event = {
            'headers': {
                'Authorization': 'Basic invalid-base64!'
            },
            'methodArn': 'arn:aws:execute-api:region:account:api/stage/method/resource'
        }

        # Execute
        result = process_header_authorization(event)

        # Verify
        mock_deny_access.assert_called_once_with(
            _AuthenticationStatus.UNAUTHORIZED, event['methodArn']
        )
        self.assertEqual(result, {"result": "unauthorized"})

    @patch('ogc_landing.authorizer.authorizer_lambda.deny_access')
    def test_process_header_authorization_invalid_format(self, mock_deny_access):
        """Test process_header_authorization with invalid username:password format."""
        # Setup
        mock_deny_access.return_value = {"result": "unauthorized"}
        # Base64 encoded "invalid-format" (no colon)
        auth_header = 'Basic ' + base64.b64encode(b'invalid-format').decode('ascii')
        event = {
            'headers': {
                'Authorization': auth_header
            },
            'methodArn': 'arn:aws:execute-api:region:account:api/stage/method/resource'
        }

        # Execute
        result = process_header_authorization(event)

        # Verify
        mock_deny_access.assert_called_once_with(
            _AuthenticationStatus.UNAUTHORIZED, event['methodArn']
        )
        self.assertEqual(result, {"result": "unauthorized"})


class TestProcessAuthorization(unittest.TestCase):
    """Test cases for the process_authorization function."""

    @patch('boto3.client')
    def test_process_authorization_success(self, mock_boto3_client):
        """Test process_authorization with valid credentials."""
        # Setup
        # Mock DynamoDB client
        mock_dynamodb = MagicMock()
        mock_dynamodb.get_item.return_value = {
            'Item': {
                'password': {
                    'B': b'encrypted-password'
                }
            }
        }

        # Mock KMS client
        mock_kms = MagicMock()
        mock_kms.decrypt.return_value = {
            'Plaintext': b'password'
        }

        # Configure boto3.client to return our mocks
        mock_boto3_client.side_effect = lambda service, **kwargs: {
            'dynamodb': mock_dynamodb,
            'kms': mock_kms
        }[service]

        # Execute
        result = process_authorization(
            'user', 'password', 'GET', 'arn:aws:execute-api:region:account:api/stage/method/resource'
        )

        # Verify
        mock_dynamodb.get_item.assert_called_once()
        mock_kms.decrypt.assert_called_once()
        self.assertEqual(result['principalId'], 'user')
        self.assertEqual(result['policyDocument']['Statement'][0]['Effect'], 'Allow')

    @patch('boto3.client')
    def test_process_authorization_wrong_password(self, mock_boto3_client):
        """Test process_authorization with the wrong password."""
        # Setup
        # Mock DynamoDB client
        mock_dynamodb = MagicMock()
        mock_dynamodb.get_item.return_value = {
            'Item': {
                'password': {
                    'B': b'encrypted-password'
                }
            }
        }

        # Mock KMS client
        mock_kms = MagicMock()
        mock_kms.decrypt.return_value = {
            'Plaintext': b'correct-password'
        }

        # Configure boto3.client to return our mocks
        mock_boto3_client.side_effect = lambda service, **kwargs: {
            'dynamodb': mock_dynamodb,
            'kms': mock_kms
        }[service]

        # Execute
        result = process_authorization(
            'user', 'wrong-password', 'GET', 'arn:aws:execute-api:region:account:api/stage/method/resource'
        )

        # Verify
        self.assertEqual(result['policyDocument']['Statement'][0]['Effect'], 'Deny')

    @patch('boto3.client')
    def test_process_authorization_user_not_found(self, mock_boto3_client):
        """Test process_authorization with non-existent user."""
        # Setup
        # Mock DynamoDB client
        mock_dynamodb = MagicMock()
        mock_dynamodb.get_item.return_value = {}  # No Item in response

        # Configure boto3.client to return our mock
        mock_boto3_client.return_value = mock_dynamodb

        # Execute
        result = process_authorization(
            'non-existent-user', 'password', 'GET', 'arn:aws:execute-api:region:account:api/stage/method/resource'
        )

        # Verify
        self.assertEqual(result['policyDocument']['Statement'][0]['Effect'], 'Deny')


class TestDenyAccess(unittest.TestCase):
    """Test cases for the deny_access function."""

    def test_deny_access_forbidden_with_user(self):
        """Test deny_access with FORBIDDEN status and user."""
        # Execute
        result = deny_access(
            _AuthenticationStatus.FORBIDDEN, 
            'arn:aws:execute-api:region:account:api/stage/method/resource',
            'user'
        )

        # Verify
        self.assertEqual(result['principalId'], 'user')
        self.assertEqual(result['policyDocument']['Statement'][0]['Effect'], 'Deny')

    def test_deny_access_forbidden_without_user(self):
        """Test deny_access with FORBIDDEN status and no user."""
        # Execute
        result = deny_access(
            _AuthenticationStatus.FORBIDDEN, 
            'arn:aws:execute-api:region:account:api/stage/method/resource'
        )

        # Verify
        self.assertEqual(result['principalId'], 'user')  # Default value
        self.assertEqual(result['policyDocument']['Statement'][0]['Effect'], 'Deny')

    def test_deny_access_unauthorized(self):
        """Test deny_access with UNAUTHORIZED status."""
        # Execute
        result = deny_access(
            _AuthenticationStatus.UNAUTHORIZED, 
            'arn:aws:execute-api:region:account:api/stage/method/resource'
        )

        # Verify
        self.assertEqual(result["statusCode"], 401)
        self.assertEqual(result["headers"]["WWW-Authenticate"], 'Basic scope="Greeting Service API"')
        self.assertEqual(result["body"], 'Unauthorized')


class TestAllowAccess(unittest.TestCase):
    """Test cases for the allow_access function."""

    def test_allow_access(self):
        """Test allow_access function."""
        # Execute
        result = allow_access(
            'arn:aws:execute-api:region:account:api/stage/method/resource',
            'user'
        )

        # Verify
        self.assertEqual(result['principalId'], 'user')
        self.assertEqual(result['policyDocument']['Statement'][0]['Effect'], 'Allow')


class TestResponseDictionary(unittest.TestCase):
    """Test cases for the response_dictionary function."""

    def test_response_dictionary_allow(self):
        """Test response_dictionary with Allow action."""
        # Execute
        result = response_dictionary(
            'Allow',
            'arn:aws:execute-api:region:account:api/stage/method/resource',
            'user'
        )

        # Verify
        self.assertEqual(result['principalId'], 'user')
        self.assertEqual(result['policyDocument']['Statement'][0]['Effect'], 'Allow')
        self.assertEqual(
            result['policyDocument']['Statement'][0]['Resource'],
            'arn:aws:execute-api:region:account:api/stage/method/*'
        )

    def test_response_dictionary_deny(self):
        """Test response_dictionary with Deny action."""
        # Execute
        result = response_dictionary(
            'Deny',
            'arn:aws:execute-api:region:account:api/stage/method/resource',
            'user'
        )

        # Verify
        self.assertEqual(result['principalId'], 'user')
        self.assertEqual(result['policyDocument']['Statement'][0]['Effect'], 'Deny')

    def test_response_dictionary_default_user(self):
        """Test response_dictionary with default user."""
        # Execute
        result = response_dictionary(
            'Allow',
            'arn:aws:execute-api:region:account:api/stage/method/resource'
        )

        # Verify
        self.assertEqual(result['principalId'], 'user')  # Default value


if __name__ == '__main__':
    unittest.main()
