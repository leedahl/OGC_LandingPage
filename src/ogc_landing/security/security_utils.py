# Copyright (c) 2025
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import boto3
import uuid
import os


def user_exists(username):
    """
    Checks if a user with the given username already exists in the database.

    Args:
        username (str): The username to check

    Returns:
        bool: True if the user exists, False otherwise
    """
    db_client = boto3.client('dynamodb')
    response = db_client.get_item(
        TableName='user_store',
        Key={'username': {'S': username}},
        ConsistentRead=True
    )

    return 'Item' in response


def encrypt_password(password):
    """
    Generates a salt and encrypts the password using KMS.

    Args:
        password (str): The password to encrypt

    Returns:
        tuple: (encrypted_password, salt) where encrypted_password is the encrypted password
               and salt is the salt used for encryption
    """
    # Generate a UUID to use as salt
    salt = str(uuid.uuid4())

    # Combine salt and password for encryption
    salted_password = f"{salt}:{password}"

    key_alias = os.environ.get('key_alias', 'hello_world')

    kms_client = boto3.client('kms')
    response = kms_client.encrypt(
        Plaintext=salted_password.encode('utf_8'),
        KeyId=f'alias/{key_alias}'
    )

    db_password = response['CiphertextBlob']

    return db_password, salt


def update_user_password(username, password):
    """
    Updates the password for an existing user.

    Args:
        username (str): The username of the user to update
        password (str): The new password

    Returns:
        bool: True if the update was successful, False otherwise
    """
    # Check if user exists
    if not user_exists(username):
        return False

    # Encrypt the password
    db_password, salt = encrypt_password(password)

    # Update the user in DynamoDB
    dynamodb_client = boto3.resource('dynamodb')
    table = dynamodb_client.Table('user_store')
    table.update_item(
        Key={'username': username},
        UpdateExpression='SET password = :p, salt = :s',
        ExpressionAttributeValues={
            ':p': db_password,
            ':s': salt
        }
    )

    return True


def create_user(username, password):
    """
    Creates a new user with the given username and password.

    Args:
        username (str): The username for the new user
        password (str): The password for the new user

    Returns:
        bool: True if the user was created successfully, False if the user already exists
    """
    # Check if user already exists
    if user_exists(username):
        return False

    # Encrypt the password
    db_password, salt = encrypt_password(password)

    # Create the user in DynamoDB
    dynamodb_client = boto3.resource('dynamodb')
    table = dynamodb_client.Table('user_store')
    table.put_item(Item={'username': username, 'password': db_password, 'salt': salt})

    return True
