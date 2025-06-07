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
import uuid
import base64
from datetime import datetime
from typing import Dict, Any

import boto3
from botocore.exceptions import ClientError


# noinspection PyUnusedLocal
def lambda_handler(event, context):
    """
    AWS Lambda function to receive an OpenAPI 3.0 JSON document, parse it,
    and upload it to DynamoDB tables according to the schema.

    Args:
        event (dict): Lambda event object containing the OpenAPI document
        context (object): Lambda context object

    Returns:
        dict: Response with status and details
    """
    try:
        # Check if the request body exists
        if 'body' not in event or not event['body']:
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/problem+json'},
                'body': json.dumps({
                    'type': 'https://i7es.click/errors/missing-request-body',
                    'title': 'Missing Request Body',
                    'status': 400,
                    'detail': 'Request body is required'
                })
            }

        # Parse the OpenAPI document from the request body
        try:
            body = event['body']
            # Check if the body is base64 encoded
            if event.get('isBase64Encoded', False):
                body = base64.b64decode(body).decode('utf_8')

            openapi_doc = json.loads(body)

        except json.JSONDecodeError:
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/problem+json'},
                'body': json.dumps({
                    'type': 'https://i7es.click/errors/invalid-json',
                    'title': 'Invalid JSON Format',
                    'status': 400,
                    'detail': 'Invalid JSON in request body'
                })
            }

        # Validate that it's an OpenAPI 3.0 document
        if 'openapi' not in openapi_doc or not openapi_doc['openapi'].startswith('3.'):
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/problem+json'},
                'body': json.dumps({
                    'type': 'https://i7es.click/errors/invalid-openapi',
                    'title': 'Invalid OpenAPI Document',
                    'status': 400,
                    'detail': 'Document is not a valid OpenAPI 3.0 specification'
                })
            }

        # Generate a unique API ID if not provided
        api_id = event.get('pathParameters', {}).get('api_id')
        if not api_id:
            api_id = str(uuid.uuid4())

        # Get a version from the OpenAPI document
        version = openapi_doc.get('info', {}).get('version', '1.0.0')

        # Store the OpenAPI document in DynamoDB
        result = store_openapi_document(api_id, version, openapi_doc)

        return {
            'statusCode': 201,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'message': 'OpenAPI document successfully processed',
                'api_id': api_id,
                'version': version,
                'details': result
            })
        }

    except Exception as e:
        print(f"Error processing OpenAPI document: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/problem+json'},
            'body': json.dumps({
                'type': 'https://i7es.click/errors/server-error',
                'title': 'Internal Server Error',
                'status': 500,
                'detail': f'An unexpected error occurred: {str(e)}'
            })
        }


def store_openapi_document(api_id: str, version: str, openapi_doc: Dict[str, Any]) -> Dict[str, Any]:
    """
    Store an OpenAPI document in DynamoDB tables according to the schema.

    Args:
        api_id (str): The API identifier
        version (str): The API version
        openapi_doc (dict): The OpenAPI document

    Returns:
        dict: Details about the storage operation
    """
    dynamodb = boto3.resource('dynamodb')
    current_time = datetime.now().isoformat()

    result = {
        'tables_updated': [],
        'items_created': 0
    }

    # 1. Store API information in openapi_documents table
    documents_table = dynamodb.Table('openapi_documents')
    info = openapi_doc.get('info', {})

    documents_table.put_item(
        Item={
            'api_id': api_id,
            'version': version,
            'title': info.get('title', ''),
            'description': info.get('description', ''),
            'terms_of_service': info.get('termsOfService', ''),
            'contact': info.get('contact', {}),
            'license': info.get('license', {}),
            'external_docs': openapi_doc.get('externalDocs', {}),
            'created_at': current_time,
            'updated_at': current_time
        }
    )
    result['tables_updated'].append('openapi_documents')
    result['items_created'] += 1

    # 2. Store servers in openapi_servers table
    if 'servers' in openapi_doc:
        servers_table = dynamodb.Table('openapi_servers')
        for i, server in enumerate(openapi_doc['servers']):
            servers_table.put_item(
                Item={
                    'api_id': api_id,
                    'server_id': f'server_{i+1}',
                    'version': version,
                    'url': server.get('url', ''),
                    'description': server.get('description', ''),
                    'variables': server.get('variables', {})
                }
            )
        result['tables_updated'].append('openapi_servers')
        result['items_created'] += len(openapi_doc['servers'])

    # 3. Store paths in openapi_paths table
    if 'paths' in openapi_doc:
        paths_table = dynamodb.Table('openapi_paths')
        operations_table = dynamodb.Table('openapi_operations')

        for path, path_item in openapi_doc['paths'].items():
            # Extract path-level properties
            path_properties = {k: v for k, v in path_item.items() 
                              if k not in ['get', 'post', 'put', 'delete', 'options', 'head', 'patch', 'trace']}

            # Store path information
            paths_table.put_item(
                Item={
                    'api_id': api_id,
                    'path': path,
                    'version': version,
                    'summary': path_properties.get('summary', ''),
                    'description': path_properties.get('description', ''),
                    'parameters': path_properties.get('parameters', [])
                }
            )
            result['items_created'] += 1

            # Store operations for this path
            for method, operation in path_item.items():
                if method in ['get', 'post', 'put', 'delete', 'options', 'head', 'patch', 'trace']:
                    operations_table.put_item(
                        Item={
                            'api_id#path': f"{api_id}#{path}",
                            'method': method.upper(),
                            'version': version,
                            'operation_id': operation.get('operationId', ''),
                            'summary': operation.get('summary', ''),
                            'description': operation.get('description', ''),
                            'tags': operation.get('tags', []),
                            'parameters': operation.get('parameters', []),
                            'request_body': operation.get('requestBody', {}),
                            'responses': operation.get('responses', {}),
                            'deprecated': operation.get('deprecated', False),
                            'security': operation.get('security', [])
                        }
                    )
                    result['items_created'] += 1

        result['tables_updated'].extend(['openapi_paths', 'openapi_operations'])

    # 4. Store components in openapi_components table
    if 'components' in openapi_doc:
        components_table = dynamodb.Table('openapi_components')
        components = openapi_doc['components']

        for component_type, components_dict in components.items():
            for component_name, component_data in components_dict.items():
                components_table.put_item(
                    Item={
                        'api_id': api_id,
                        'component_type#component_name': f"{component_type}#{component_name}",
                        'version': version,
                        'description': component_data.get('description', '') if isinstance(component_data, dict) else '',
                        'component_data': component_data
                    }
                )
                result['items_created'] += 1

        result['tables_updated'].append('openapi_components')

    # 5. Store tags in openapi_tags table
    if 'tags' in openapi_doc:
        tags_table = dynamodb.Table('openapi_tags')
        for tag in openapi_doc['tags']:
            tags_table.put_item(
                Item={
                    'api_id': api_id,
                    'tag_name': tag['name'],
                    'version': version,
                    'description': tag.get('description', ''),
                    'external_docs': tag.get('externalDocs', {})
                }
            )
            result['items_created'] += 1

        result['tables_updated'].append('openapi_tags')

    # 6. Store security schemes in openapi_security_schemes table
    if 'components' in openapi_doc and 'securitySchemes' in openapi_doc['components']:
        security_table = dynamodb.Table('openapi_security_schemes')
        security_schemes = openapi_doc['components']['securitySchemes']

        for scheme_name, scheme in security_schemes.items():
            # Extract scheme-specific details
            scheme_type = scheme.get('type', '')
            scheme_details = {k: v for k, v in scheme.items() if k not in ['type', 'description']}

            security_table.put_item(
                Item={
                    'api_id': api_id,
                    'scheme_name': scheme_name,
                    'version': version,
                    'type': scheme_type,
                    'description': scheme.get('description', ''),
                    'scheme_details': scheme_details
                }
            )
            result['items_created'] += 1

        result['tables_updated'].append('openapi_security_schemes')

    # Update the api_catalog table to include this API
    try:
        catalog_table = dynamodb.Table('api_catalog')

        # Check if this API already exists in the catalog
        response = catalog_table.query(
            KeyConditionExpression='api_id = :api_id',
            ExpressionAttributeValues={':api_id': api_id}
        )

        # If not, add it to the catalog
        if not response.get('Items'):
            # Get the highest catalog_order
            scan_response = catalog_table.scan(
                ProjectionExpression='catalog_order'
            )
            catalog_orders = [item.get('catalog_order', 0) for item in scan_response.get('Items', [])]
            next_order = max(catalog_orders, default=0) + 1

            # Create a new catalog entry
            catalog_table.put_item(
                Item={
                    'api_id': api_id,
                    'catalog_order': next_order,
                    'anchor': '/',
                    'description': info.get('description', 'API created from OpenAPI document'),
                    'domain': 'i7es.click',  # Default domain, can be overridden
                    'title': info.get('title', f'API {api_id}'),
                    'relations': {
                        'service-desc': {
                            'href': f'api/{api_id}/openapi',
                            'title': 'OpenAPI Document',
                            'types': ['application/json', 'application/yaml']
                        },
                        'service-doc': {
                            'href': f'api/{api_id}/docs',
                            'title': 'API Documentation',
                            'types': ['text/html']
                        },
                        'conformance': {
                            'href': f'conformance',
                            'rel': 'conformance',
                            'title': 'Conformance Declaration',
                            'types': ['application/json', 'text/html'],
                            'conformsTo': ['https://www.openapis.org/']
                        }
                    }
                }
            )
            result['tables_updated'].append('api_catalog')
            result['items_created'] += 1

    except ClientError as e:
        print(f"Error updating api_catalog: {str(e)}")
        # Continue even if catalog update fails

    return result
