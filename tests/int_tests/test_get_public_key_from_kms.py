import unittest
import os
import base64
import boto3
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from ogc_landing.registration.register_lambda import get_public_key_from_kms


class TestGetPublicKeyFromKMS(unittest.TestCase):
    """Integration tests for the get_public_key_from_kms function in register_lambda.py

    This test automatically finds the KMS key with alias "security_encryption" and uses it
    for testing the get_public_key_from_kms function. It requires AWS credentials with
    permissions to list KMS aliases and describe KMS keys.
    """

    def setUp(self):
        """Set up test fixtures, if any."""
        try:
            # Find the KMS key ARN by looking up the key with alias "security_encryption"
            kms_client = boto3.client('kms')
            response = kms_client.list_aliases()

            # Find the alias with name "security_encryption"
            key_id = None
            for alias in response['Aliases']:
                if alias['AliasName'] == 'alias/security_encryption':
                    key_id = alias['TargetKeyId']
                    break

            if not key_id:
                self.skipTest("KMS key with alias 'security_encryption' not found")

            # Get the full ARN for the key
            key_response = kms_client.describe_key(KeyId=key_id)
            key_arn = key_response['KeyMetadata']['Arn']

            # Set the environment variable for the test
            os.environ['encryption_key_arn'] = key_arn

        except Exception as e:
            self.skipTest(f"Failed to find KMS key: {str(e)}")

    def tearDown(self):
        """Tear down test fixtures, if any."""
        # Restore the original environment variable if it was changed
        if 'encryption_key_arn' in os.environ:
            del os.environ['encryption_key_arn']

    def test_get_public_key_from_kms(self):
        """Test that get_public_key_from_kms returns a valid PEM-encoded public key."""
        # Call the function
        pem_data = get_public_key_from_kms()

        # Verify the result is a string
        self.assertIsInstance(pem_data, str)

        # Verify the result starts with the PEM header for a public key
        self.assertTrue(pem_data.startswith('-----BEGIN PUBLIC KEY-----'))
        self.assertTrue(pem_data.endswith('-----END PUBLIC KEY-----\n'))

        # Verify the result can be loaded as a public key
        try:
            load_pem_public_key(pem_data.encode('utf-8'))
            is_valid_key = True

        except Exception as e:
            is_valid_key = False
            self.fail(f"Failed to load PEM data as a public key: {str(e)}")

        self.assertTrue(is_valid_key, "The returned PEM data is not a valid public key")


if __name__ == '__main__':
    unittest.main()
