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
import requests
import logging
from typing import Dict, Any

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)


# noinspection PyUnusedLocal
def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Authorizer Proxy Lambda function that forwards authorization requests to the security service.
    
    This function extracts the host from the event, replaces the first part with 'security',
    and makes an HTTPS request to the modified host with the event as the JSON body.
    
    :param event: The event dict that contains the request parameters
    :param context: The context object provided by AWS Lambda
    :return: The response from the security service
    """
    # Extract host from the event
    host = None
    if 'headers' in event and event['headers'] is not None:
        if 'Host' in event['headers']:
            host = event['headers']['Host']
        elif 'host' in event['headers']:
            host = event['headers']['host']
    
    if not host:
        logger.error("Host not found in event headers")
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/problem+json; charset=utf-8'
            },
            'body': json.dumps({
                'type': 'about:blank',
                'title': 'Internal Server Error',
                'detail': 'Host not found in event headers'
            }),
            'isBase64Encoded': False
        }
    
    # Replace the first part of the host with 'security'
    parts = host.split('.')
    if len(parts) >= 2:
        security_host = 'security.' + '.'.join(parts[1:])
        logger.info(f"Modified host: {security_host}")

    else:
        logger.error(f"Invalid host format: {host}")
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/problem+json; charset=utf-8'
            },
            'body': json.dumps({
                'type': 'about:blank',
                'title': 'Internal Server Error',
                'detail': f'Invalid host format: {host}'
            }),
            'isBase64Encoded': False
        }
    
    # Construct the URL for the security service
    url = f"https://{security_host}/decision"
    logger.info(f"Forwarding request to: {url}")
    
    try:
        # Make HTTPS request to the security service with the event as the JSON body
        response = requests.post(
            url,
            json=event,
            headers={'Content-Type': 'application/json'},
            timeout=10  # Set a reasonable timeout
        )
        
        # Check if the request was successful
        response.raise_for_status()
        
        # Parse the response
        result = response.json()
        logger.info(f"Received response: {json.dumps(result)}")
        
        return result
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error making request to security service: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/problem+json; charset=utf-8'
            },
            'body': json.dumps({
                'type': 'about:blank',
                'title': 'Internal Server Error',
                'detail': f'Error making request to security service: {str(e)}'
            }),
            'isBase64Encoded': False
        }