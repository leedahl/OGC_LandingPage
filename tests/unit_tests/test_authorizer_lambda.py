import unittest
from unittest.mock import patch, MagicMock
import hashlib

from ogc_landing.authorizer.authorizer_lambda import process_authorization


class TestProcessAuthorization(unittest.TestCase):
    """Unit tests for the process_authorization function in authorizer_lambda.py"""

    def setUp(self):
        """Set up test fixtures, if any."""
        # Common test variables
        self.username = "TestUser"
        self.password = "TestPassword"
        self.http_method = "GET"
        self.method_arn = "arn:aws:execute-api:us-east-1:123456789012:abcdef123/test/GET/resource"
        self.salt = "TestSalt"
        self.hashed_password = hashlib.sha256(f"{self.salt}:{self.password}".encode('utf_8')).hexdigest()

    @patch('ogc_landing.authorizer.authorizer_lambda.boto3')
    @patch('ogc_landing.authorizer.authorizer_lambda.os')
    def test_successful_authorization(self, mock_os, mock_boto3):
        """Test successful authorization with valid credentials."""
        # Mock DynamoDB client
        mock_dynamodb = MagicMock()
        mock_boto3.client.side_effect = lambda service, **kwargs: {
            'dynamodb': mock_dynamodb,
            'kms': self._mock_kms_client()
        }[service]

        # Mock environment variable
        mock_os.environ.get.return_value = 'hello_world'

        # Mock DynamoDB response
        mock_dynamodb.get_item.return_value = {
            'Item': {
                'password': {'B': b'encrypted_password'},
                'salt': {'S': self.salt}
            }
        }

        # Call the function
        result = process_authorization(self.username, self.password, self.http_method, self.method_arn)

        # Assertions
        self.assertEqual(result['principalId'], self.username)
        self.assertEqual(result['policyDocument']['Statement'][0]['Effect'], 'Allow')

        # Verify DynamoDB was called with correct parameters
        mock_dynamodb.get_item.assert_called_with(
            TableName='user_store',
            Key={'username': {'S': self.username}},
            ConsistentRead=True,
            ProjectionExpression='password,salt'
        )

    @patch('ogc_landing.authorizer.authorizer_lambda.boto3')
    @patch('ogc_landing.authorizer.authorizer_lambda.os')
    def test_failed_authorization_wrong_password(self, mock_os, mock_boto3):
        """Test failed authorization with the wrong password."""
        # Mock DynamoDB client
        mock_dynamodb = MagicMock()
        mock_boto3.client.side_effect = lambda service, **kwargs: {
            'dynamodb': mock_dynamodb,
            'kms': self._mock_kms_client(wrong_password=True)
        }[service]

        # Mock environment variable
        mock_os.environ.get.return_value = 'hello_world'

        # Mock DynamoDB response
        mock_dynamodb.get_item.return_value = {
            'Item': {
                'password': {'B': b'encrypted_password'},
                'salt': {'S': self.salt}
            }
        }

        # Call the function
        result = process_authorization(self.username, "WrongPassword", self.http_method, self.method_arn)

        # Assertions
        self.assertEqual(result['principalId'], self.username)
        self.assertEqual(result['policyDocument']['Statement'][0]['Effect'], 'Deny')

    @patch('ogc_landing.authorizer.authorizer_lambda.boto3')
    def test_user_not_found(self, mock_boto3):
        """Test authorization when a user is not found."""
        # Mock DynamoDB client
        mock_dynamodb = MagicMock()
        mock_boto3.client.return_value = mock_dynamodb

        # Mock DynamoDB response for when the user isn't found
        mock_dynamodb.get_item.return_value = {}

        # Call the function
        result = process_authorization(self.username, self.password, self.http_method, self.method_arn)

        # Assertions
        self.assertEqual(result['policyDocument']['Statement'][0]['Effect'], 'Deny')

    @patch('ogc_landing.authorizer.authorizer_lambda.boto3')
    @patch('ogc_landing.authorizer.authorizer_lambda.os')
    def test_openapi_request_authorized(self, mock_os, mock_boto3):
        """Test successful authorization for OpenAPI request."""
        # Mock clients
        mock_dynamodb = MagicMock()
        mock_boto3.client.side_effect = lambda service, **kwargs: {
            'dynamodb': mock_dynamodb,
            'kms': self._mock_kms_client()
        }[service]

        # Mock environment variable
        mock_os.environ.get.return_value = 'hello_world'

        # Set up method_arn for OpenAPI request
        openapi_method_arn = "arn:aws:execute-api:us-east-1:123456789012:abcdef123/test/GET/api/openapi/api123"

        # Mock DynamoDB responses
        mock_dynamodb.get_item.side_effect = [
            # First call for user lookup
            {
                'Item': {
                    'password': {'B': b'encrypted_password'},
                    'salt': {'S': self.salt}
                }
            },
            # Second call for API ownership check
            {
                'Item': {
                    'username': {'S': self.username},
                    'api_id': {'S': 'api123'}
                }
            }
        ]

        # Call the function
        result = process_authorization(self.username, self.password, self.http_method, openapi_method_arn)

        # Assertions
        self.assertEqual(result['principalId'], self.username)
        self.assertEqual(result['policyDocument']['Statement'][0]['Effect'], 'Allow')

        # Verify API ownership was checked
        self.assertEqual(mock_dynamodb.get_item.call_count, 2)

    @patch('ogc_landing.authorizer.authorizer_lambda.boto3')
    @patch('ogc_landing.authorizer.authorizer_lambda.os')
    def test_openapi_request_unauthorized(self, mock_os, mock_boto3):
        """Test failed authorization for OpenAPI request when a user doesn't own the API."""
        # Mock clients
        mock_dynamodb = MagicMock()
        mock_boto3.client.side_effect = lambda service, **kwargs: {
            'dynamodb': mock_dynamodb,
            'kms': self._mock_kms_client()
        }[service]

        # Mock environment variable
        mock_os.environ.get.return_value = 'hello_world'

        # Set up method_arn for OpenAPI request
        openapi_method_arn = "arn:aws:execute-api:us-east-1:123456789012:abcdef123/test/GET/api/openapi/api123"

        # Mock DynamoDB responses
        mock_dynamodb.get_item.side_effect = [
            # First call for user lookup
            {
                'Item': {
                    'password': {'B': b'encrypted_password'},
                    'salt': {'S': self.salt}
                }
            },
            # Second call for API ownership check (user doesn't own the API)
            {}
        ]

        # Call the function
        result = process_authorization(self.username, self.password, self.http_method, openapi_method_arn)

        # Assertions
        self.assertEqual(result['principalId'], self.username)
        self.assertEqual(result['policyDocument']['Statement'][0]['Effect'], 'Deny')

        # Verify API ownership was checked
        self.assertEqual(mock_dynamodb.get_item.call_count, 2)

    @patch('ogc_landing.authorizer.authorizer_lambda.boto3')
    @patch('ogc_landing.authorizer.authorizer_lambda.os')
    def test_post_method_user_management(self, mock_os, mock_boto3):
        """Test POST method authorization for user-management endpoint."""
        # Mock clients
        mock_dynamodb = MagicMock()
        mock_boto3.client.side_effect = lambda service, **kwargs: {
            'dynamodb': mock_dynamodb,
            'kms': self._mock_kms_client()
        }[service]

        # Mock environment variable
        mock_os.environ.get.return_value = 'hello_world'

        # Set up method_arn for user-management POST request
        user_mgmt_method_arn = "arn:aws:execute-api:us-east-1:123456789012:abcdef123/test/POST/api/user-management"

        # Mock DynamoDB response
        mock_dynamodb.get_item.return_value = {
            'Item': {
                'password': {'B': b'encrypted_password'},
                'salt': {'S': self.salt}
            }
        }

        # Call the function
        result = process_authorization(self.username, self.password, "POST", user_mgmt_method_arn)

        # Assertions
        self.assertEqual(result['principalId'], self.username)
        self.assertEqual(result['policyDocument']['Statement'][0]['Effect'], 'Allow')

    def _mock_kms_client(self, wrong_password=False):
        """Helper method to create a mock KMS client."""
        mock_kms = MagicMock()

        # If testing a wrong password scenario, return a completely different hash
        if wrong_password:
            mock_kms.decrypt.return_value = {
                'Plaintext': "completely_different_hash_that_will_never_match".encode('utf_8')
            }
        else:
            mock_kms.decrypt.return_value = {
                'Plaintext': self.hashed_password.encode('utf_8')
            }

        return mock_kms


if __name__ == '__main__':
    unittest.main()
