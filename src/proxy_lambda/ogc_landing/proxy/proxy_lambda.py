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
    Proxy Lambda function that forwards authorization requests or Well-Known requests to the appropriate service.
    
    For authorizer requests, this function extracts the host from the event, replaces the first part with 'security'
    and sends the event as the JSON body.  Then the method calls the decision endpoint of the security service.

    For well-known requests, this function extracts the host from the event, replaces the first part with 'portfolio'
    and sends the event as the JSON body.  The method extracts the subdomain from the root domain name and converts
    the subdomain name to Pascal case.  Then the method calls the well-known/api-catalog endpoint with the appropriate
    API name.
    
    :param event: The event dict that contains the request parameters
    :param context: The context object provided by AWS Lambda
    :return: The response from the security service
    """
    # Extract host from the event
    host = None
    if 'headers' in event and event['headers'] is not None:
        headers = event['headers']
        if 'Host' in event['headers']:
            host = event['headers']['Host']

        elif 'host' in event['headers']:
            host = event['headers']['host']

        host_parts = host.split('.')
        logger.info(f'Host: {host}')

    else:
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
    logger.info(f'Type: {event.get('type', '')}')
    if len(host_parts) >= 2 and 'type' in event:
        request_host = 'security.' + '.'.join(host_parts[1:])

    elif 'type' in event:
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

    else:
        request_host = 'portfolio.' + '.'.join(host_parts[1:])

    # Construct the URL for the security service
    url = f'https://{request_host}/{'decision' if 'type' in event else f'.well-known/api-catalog'}'
    logger.info(f"Forwarding request to: {url}")
    
    try:
        # Make HTTPS request to the security service with the event as the JSON body
        logger.info(f"Making a request to {request_host}.")
        response = requests.post(
            url,
            json=event,
            headers={'Content-Type': 'application/json'},
            timeout=10  # Set a reasonable timeout
        )
        
        # Check if the request was successful
        response.raise_for_status()
        
        # Parse the response
        logger.info(f"Response from {request_host}: {response.text}")
        body = response.text
        headers = {key: value for key, value in response.headers.items()}
        logger.info(f"Status: {response.status_code}")
        logger.info(f"Headers: {json.dumps(headers)}")
        logger.info(f"Body: {body}")

        return response.json() if 'type' in event else {
            'statusCode': response.status_code,
            'headers': headers,
            'body': body,
            'isBase64Encoded': False
        }
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error making request to {'security' if 'type' in event else 'portfolio'} service: {str(e)}")
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