# Copyright (c) 2025
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import json
import os
import boto3
from typing import Dict, Any

# Get the target account ID and function name from environment variables
TARGET_ACCOUNT_ID = os.environ.get('TARGET_ACCOUNT_ID')
TARGET_FUNCTION_NAME = os.environ.get('TARGET_FUNCTION_NAME', 'well_known_lambda')
TARGET_REGION = os.environ.get('TARGET_REGION', 'us-east-1')


# noinspection PyUnusedLocal
def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Proxy lambda function that invokes the well_known_lambda in another AWS account.
    
    This function forwards the incoming request to the well_known_lambda in the target account
    and returns the response back to the caller.
    
    :param event: The event dict that contains the request parameters
    :param context: The context object provided by AWS Lambda
    :return: The response from the well_known_lambda
    """
    print(f"Received event: {json.dumps(event)}")
    
    if not TARGET_ACCOUNT_ID:
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/problem+json; charset=utf-8'
            },
            'body': json.dumps({
                'type': 'about:blank',
                'title': 'Internal Server Error',
                'detail': 'TARGET_ACCOUNT_ID environment variable is not set'
            }),
            'isBase64Encoded': False
        }
    
    # Create a Lambda client
    lambda_client = boto3.client('lambda', region_name=TARGET_REGION)
    
    # Construct the ARN of the target function
    target_function_arn = f'arn:aws:lambda:{TARGET_REGION}:{TARGET_ACCOUNT_ID}:function:{TARGET_FUNCTION_NAME}'
    
    try:
        # Invoke the target function
        print(f"Invoking function: {target_function_arn}")
        response = lambda_client.invoke(
            FunctionName=target_function_arn,
            InvocationType='RequestResponse',
            Payload=json.dumps(event)
        )
        
        # Parse the response payload
        payload = json.loads(response['Payload'].read().decode('utf-8'))
        print(f"Received response: {json.dumps(payload)}")
        
        # Check if the invocation was successful
        if response.get('FunctionError'):
            print(f"Function error: {response.get('FunctionError')}")
            return {
                'statusCode': 500,
                'headers': {
                    'Content-Type': 'application/problem+json; charset=utf-8'
                },
                'body': json.dumps({
                    'type': 'about:blank',
                    'title': 'Internal Server Error',
                    'detail': f"Error invoking target function: {response.get('FunctionError')}"
                }),
                'isBase64Encoded': False
            }
        
        # Return the response from the target function
        return payload
        
    except Exception as e:
        print(f"Error invoking target function: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/problem+json; charset=utf-8'
            },
            'body': json.dumps({
                'type': 'about:blank',
                'title': 'Internal Server Error',
                'detail': f"Error invoking target function: {str(e)}"
            }),
            'isBase64Encoded': False
        }