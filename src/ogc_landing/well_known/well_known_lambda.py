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
from collections import namedtuple
from typing import List, Tuple, Dict, Any, Optional
from boto3.dynamodb import conditions
from boto3 import resource

from botocore.exceptions import BotoCoreError

CatalogRecord = namedtuple('CatalogRecord', [
    'api_id', 'catalog_order', 'anchor', 'description', 'domain', 'relations', 'title'
])

CatalogDomainRecord = namedtuple('CatalogDomainRecord', [
    'domain', 'catalog_order', 'title', 'description'
])


# noinspection PyUnusedLocal
def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main entry point for the Lambda function that handles API catalog requests.

    This function processes various types of requests based on the resource path
    and returns appropriate responses with content based on the Accept header.

    :param event: The event dict that contains the request parameters
    :param context: The context object provided by AWS Lambda
    :return: The response object containing status code, headers, and body
    """
    print(event)

    if event.get('resource', '') == '/index.html':
        event['resource'] = '/'
        if 'headers' not in event or event['headers'] is None:
            event['headers'] = dict()

        event.setdefault('headers', dict())['Accept'] = 'text/html'

    headers = event.get('headers', dict()) if event.get('headers', dict()) is not None else dict()
    accept = headers.get('Accept', None) if headers.get('Accept', None) is not None else 'text/html'
    host = headers.get('Host', None) if headers.get('Host', None) is not None else 'i7es.click'
    protocol = (
        headers.get('CloudFront-Forwarded-Proto', None) if headers.get('CloudFront-Forwarded-Proto', None) is not None
        else 'https'
    )

    dynamodb_client = resource('dynamodb')
    api_methods_table = dynamodb_client.Table('api_catalog')
    api_catalog = api_methods_table.scan(
        Select='ALL_ATTRIBUTES',
        ConsistentRead=True
    )

    items = [
        CatalogRecord(
            item['api_id'], item['catalog_order'], item['anchor'], item['description'], item['domain'],
            item['relations'], item['title']
        )
        for item in api_catalog['Items']
    ]
    items.sort(key=lambda item: item.catalog_order)

    match event.get('resource', ''):
        case '/.well-known/{well_known_name}':
            body, content_type, link_header, location_header, status_code = _process_well_known_request(
                accept, event, host, items, protocol
            )

        case '/conformance':
            body, content_type, link_header, location_header, status_code = _process_conformance_request(
                accept, host, items, protocol
            )

        case '/conformance/{conformance_alias}':
            body, content_type, link_header, location_header, status_code = _process_conformance_alias_request(
                accept, event, host, items
            )

        case '/api':
            body, content_type, link_header, location_header, status_code = _process_api_request(host, items)

        case 'documentation':
            body, content_type, link_header, location_header, status_code = _process_documentation_request(host, items)

        case '/':
            body, content_type, link_header, location_header, status_code = _process_landing_page_request(
                accept, host, items, protocol
            )

        case _:
            status_code = 404
            content_type = 'application/problem+json; charset=utf-8'
            body = json.dumps({'type': 'about:blank', 'title': 'Not Found'})
            link_header = None
            location_header = None

    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': content_type,
            **({'Location': location_header} if location_header is not None else {}),
            **({'Link': link_header} if link_header is not None else {}),
            'Content-Length': len(body)
        },
        'body': body,
        'isBase64Encoded': False
    }


def _generate_openapi_document(api_id: str, version: str) -> Dict[str, Any]:
    """
    Dynamically generate an OpenAPI 3.0 document from DynamoDB tables.

    Args:
        api_id (str): The API identifier
        version (str): The API version

    Returns:
        dict: The complete OpenAPI document
    """
    dynamodb_resource = resource('dynamodb')

    # Initialize the OpenAPI document
    openapi_doc:  dict[str, str | dict | dict[str, dict] | list] = {
        "openapi": "3.0.0",
        "paths": {},
        "components": {
            "schemas": {},
            "parameters": {},
            "responses": {},
            "securitySchemes": {}
        }
    }

    # 1. Get API information
    documents_table = dynamodb_resource.Table('openapi_documents')
    document_response = documents_table.get_item(
        Key={
            'api_id': api_id,
            'version': version
        }
    )

    if 'Item' not in document_response:
        # If the version is 'latest', try to find the latest version
        if version == 'latest':
            documents_response = documents_table.query(
                KeyConditionExpression=conditions.Key('api_id').eq(api_id)
            )
            if documents_response.get('Items'):
                # Sort by version and get the latest
                items = sorted(documents_response['Items'], key=lambda x: x['version'], reverse=True)
                document = items[0]
                version = document['version']
            else:
                raise ValueError(f"API with id {api_id} not found")
        else:
            raise ValueError(f"API with id {api_id} and version {version} not found")
    else:
        document = document_response['Item']

    # Add an info section
    openapi_doc["info"] = {
        "title": document.get('title', ''),
        "description": document.get('description', ''),
        "version": version,
        "termsOfService": document.get('terms_of_service', ''),
        "contact": document.get('contact', dict()),
        "license": document.get('license', dict())
    }

    # Add external docs if available
    if 'external_docs' in document:
        openapi_doc["externalDocs"] = document['external_docs']

    # 2. Get servers
    servers_table = dynamodb_resource.Table('openapi_servers')
    servers_response = servers_table.query(
        KeyConditionExpression=conditions.Key('api_id').eq(api_id)
    )

    if servers_response.get('Items'):
        openapi_doc["servers"] = list()
        for server in servers_response['Items']:
            if server.get('version') == version:
                server_obj = {
                    "url": server.get('url', ''),
                    "description": server.get('description', '')
                }
                if 'variables' in server:
                    server_obj["variables"] = server['variables']
                openapi_doc["servers"].append(server_obj)

    # 3. Get paths and operations
    paths_table = dynamodb_resource.Table('openapi_paths')
    paths_response = paths_table.query(
        KeyConditionExpression=conditions.Key('api_id').eq(api_id)
    )

    operations_table = dynamodb_resource.Table('openapi_operations')

    for path_item in paths_response.get('Items', []):
        if path_item.get('version') != version:
            continue

        path = path_item['path']
        path_obj = {
            "summary": path_item.get('summary', ''),
            "description": path_item.get('description', '')
        }

        # Add path parameters if available
        if 'parameters' in path_item:
            path_obj["parameters"] = path_item['parameters']

        # Get operations for this path
        operations_response = operations_table.query(
            KeyConditionExpression=conditions.Key('api_id#path').eq(f"{api_id}#{path}")
        )

        for operation in operations_response.get('Items', []):
            if operation.get('version') != version:
                continue

            method = operation['method'].lower()
            operation_obj = {
                "operationId": operation.get('operation_id', ''),
                "summary": operation.get('summary', ''),
                "description": operation.get('description', '')
            }

            # Add tags if available
            if 'tags' in operation:
                operation_obj["tags"] = operation['tags']

            # Add parameters if available
            if 'parameters' in operation:
                operation_obj["parameters"] = operation['parameters']

            # Add requestBody if available
            if 'request_body' in operation:
                operation_obj["requestBody"] = operation['request_body']

            # Add responses if available
            if 'responses' in operation:
                operation_obj["responses"] = operation['responses']

            # Add security if available
            if 'security' in operation:
                operation_obj["security"] = operation['security']

            # Add the deprecated flag if available
            if 'deprecated' in operation:
                operation_obj["deprecated"] = operation['deprecated']

            path_obj[method] = operation_obj

        openapi_doc["paths"][path] = path_obj

    # 4. Get components
    components_table = dynamodb_resource.Table('openapi_components')
    components_response = components_table.query(
        KeyConditionExpression=conditions.Key('api_id').eq(api_id)
    )

    for component in components_response.get('Items', []):
        if component.get('version') != version:
            continue

        component_key = component['component_type#component_name']
        component_type, component_name = component_key.split('#', 1)

        # Initialize component type if not exists
        if component_type not in openapi_doc["components"]:
            openapi_doc["components"][component_type] = {}

        openapi_doc["components"][component_type][component_name] = component['component_data']

    # 5. Get tags
    tags_table = dynamodb_resource.Table('openapi_tags')
    tags_response = tags_table.query(
        KeyConditionExpression=conditions.Key('api_id').eq(api_id)
    )

    if tags_response.get('Items'):
        openapi_doc["tags"] = []
        for tag in tags_response['Items']:
            if tag.get('version') == version:
                tag_obj = {
                    "name": tag['tag_name'],
                    "description": tag.get('description', '')
                }
                if 'external_docs' in tag:
                    tag_obj["externalDocs"] = tag['external_docs']
                openapi_doc["tags"].append(tag_obj)

    # 6. Get security schemes
    security_table = dynamodb_resource.Table('openapi_security_schemes')
    security_response = security_table.query(
        KeyConditionExpression=conditions.Key('api_id').eq(api_id)
    )

    for scheme in security_response.get('Items', []):
        if scheme.get('version') != version:
            continue

        scheme_name = scheme['scheme_name']
        scheme_obj = {
            "type": scheme.get('type', ''),
            "description": scheme.get('description', '')
        }

        # Add scheme-specific details
        if 'scheme_details' in scheme:
            for key, value in scheme['scheme_details'].items():
                scheme_obj[key] = value

        openapi_doc["components"]["securitySchemes"][scheme_name] = scheme_obj

    return openapi_doc


def _generate_openapi_html(openapi_doc: Dict[str, Any]) -> str:
    """
    Generate an HTML representation of an OpenAPI document.

    Args:
        openapi_doc (dict): The OpenAPI document

    Returns:
        str: HTML representation of the OpenAPI document
    """
    title = openapi_doc.get('info', {}).get('title', 'API Documentation')

    # Create a basic HTML template with Swagger UI
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - OpenAPI Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@3/swagger-ui.css">
    <style>
        body {{
            margin: 0;
            padding: 0;
        }}
        #swagger-ui {{
            max-width: 1200px;
            margin: 0 auto;
        }}
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@3/swagger-ui-bundle.js"></script>
    <script>
        window.onload = function() {{
            const ui = SwaggerUIBundle({{
                spec: {json.dumps(openapi_doc)},
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIBundle.SwaggerUIStandalonePreset
                ],
                layout: "BaseLayout",
                docExpansion: "list",
                defaultModelsExpandDepth: 1,
                defaultModelExpandDepth: 1,
                defaultModelRendering: "example",
                displayRequestDuration: true,
                filter: true,
                showExtensions: true
            }});
            window.ui = ui;
        }};
    </script>
</body>
</html>"""

    return html


def _prepare_conformance_alias_html_body(item: CatalogRecord, alias: str) -> Tuple[str, bool]:
    """
    Create the HTML representation of a conformance metadata that is associated with specified alias.

    :param item: The catalog record that contains information about the API that conforms to the specified alias.
    :param alias: The alias of the conformance requirement.
    :return: The HTML representation of the conformance metadata that is associated with specified alias.
    """
    try:
        dynamodb_client = resource('dynamodb')
        api_methods_table = dynamodb_client.Table('api_conformance')
        result = api_methods_table.query(
            Select='ALL_ATTRIBUTES',
            ConsistentRead=True,
            KeyConditionExpression='api_id = :api_id and alias = :alias',
            ExpressionAttributeValues={':api_id': item.api_id, ':alias': alias},
        )

        conformance_items = result['Items']
        if len(conformance_items) <= 0:
            raise BotoCoreError(error='No results found.')

        conformance_item = conformance_items[0]

    except BotoCoreError as e:
        print(e)
        body = json.dumps({'type': 'about:blank', 'title': 'Not Found'})
        found = False

    else:

        body = (
            '<DOCTYPE html>'
            '<html>'
            '<head>'
            '<style type="text/css">'
            'th, td {padding: 5px; text-align: left;}'
            '</style>'
            f'<title>{item.title} Conformance Metadata</title>'
            '</head>'
            '<body>'
            f'<h1>{item.title} Conformance Metadata</h1>'
            '<table>'
            '<tr><th>Conformance URI</th><th>Title</th></tr>'
            f'<tr><td>{conformance_item['conformance_uri']}</td><td>{conformance_item['title']}</td></tr>'
            '</table>'
            f'{bytes(conformance_item['description']).decode('utf_8')}'
            '</body>'
            '</html>'
        )

        found = True

    return body, found


def _prepare_conformance_html_body(item: CatalogRecord, protocol: str) -> str:
    """
    Creates the HTML Representation of the Conformance body.

    :param item: The catalog record to use for reporting the conformance metadata.
    :param protocol: The Internet protocol used to communicate with this server.
    :return: The HTML Representation of the Conformance body.
    """
    dynamodb_client = resource('dynamodb')
    api_methods_table = dynamodb_client.Table('api_conformance')
    conformance_items = api_methods_table.query(
        Select='ALL_ATTRIBUTES',
        ConsistentRead=True,
        KeyConditionExpression='api_id = :api_id',
        ExpressionAttributeValues={':api_id': item.api_id},
    )

    return (
        '<DOCTYPE html>'
        '<html lang="en">'
        '<head>'
        '<style type="text/css">'
        'th, td {text-align: left; padding: 5px;}'
        '</style>'
        f'<title>{item.title} Conformance Metadata</title>'
        '</head>'
        '<body>'
        f'<h1>{item.title} Conformance Metadata</h1>'
        '<p>On this page you will find links to the Conformance Metadata for the Requirements this API conforms to.</p>'
        '<table>'
        '<tr><th>Conformance Metadata Links</th>'
        f'{''.join([
            f'<tr><td><a href="{protocol}://{item.domain}{item.anchor}conformance/{conformance_item['alias']}">'
            f'{conformance_item['title']}</a></td></tr>'
            for conformance_item in conformance_items['Items']
        ])}'
        '</table>'
        '</body>'
        '</html>'
    )


def _prepare_conformance_json_body(item: CatalogRecord) -> str:
    """
    Creates the JSON Representation of the Conformance body.

    :param item: A catalog record to use for reporting the conformance metadata.
    :return: The JSON Representation of the Conformance body.
    """
    return f'{{"conformsTo": ["{'", "'.join(item.relations['conformance']['conformsTo'])}"]}}'


def _prepare_landing_html_body(host: str, items: List[CatalogRecord], protocol: str) -> str:
    """
    Creates the HTML body for the landing page.

    :param host: The host of the landing page.
    :param items: The catalog API items.
    :param protocol: The protocol used to invoke the landing page.
    :return: The body of the landing page.
    """
    body = (
        '<!DOCTYPE HTML>'
        '<html lang="en">'
        '<head>'
        "<title>Michael's Portfolio of APIs</title>"
        '</head>'
        '<body>'
        "<h1>Welcome to Michael's Portfolio of APIs</h1>"
        '<p>You can find the API documentation for all the wonderful APIs at the following links:</p>'
        '<p>'
        f'<a href="{protocol}://{host}/.well-known/api-catalog" rel="api-catalog">'
        f"Michael's portfolio of APIs.</a><br><br>"
    )
    body += ''.join([
        f'{(
            f'<a href="{protocol}://{item.domain}{item.anchor}'
            f'{item.relations['service-doc']['href']}" rel="service-doc">'
            f'{item.title}</a>: {item.description}<br/>'
            f'<a href="{protocol}://{item.domain}{item.anchor}{item.relations['conformance']['href']}" '
            f'rel="{item.relations['conformance']['rel']}">Conformance</a>: '
            f'{item.relations['conformance']['title']}<br><br>'
        )}'
        for item in items
    ])
    body += (
        '</p>'
        '</body>'
        '</html>'
    )

    return body


def _prepare_landing_json_body(item: CatalogRecord, protocol: str) -> str:
    """
    Prepare the landing JSON body for an item.

    :param item: The catalog item containing the Catalog API information.
    :param protocol: The protocol by the invocation of this lambda.
    :return: The landing JSON body.
    """
    body = json.dumps({
        'tile': "Michael's Portfolio of APIs",
        'description': "Access to Michael's Portfolio of APIs.",
        'links': [
            *[{
                'rel': 'api-catalog',
                'type': 'application/linkset+json',
                'title': "Michael's Portfolio of APIs",
                'href': f'{protocol}://{item.domain}{item.anchor}.well-known/api-catalog'
            }],
            *[
                {
                    'rel': 'service-desc',
                    'type': service_desc_type,
                    'title': item.relations['service-desc']['title'],
                    'href': f'{protocol}://{item.domain}{item.anchor}'
                            f'{item.relations['service-desc']['href']}'
                }
                for service_desc_type in item.relations['service-desc']['types']
            ],
            *[
                {
                    'rel': 'service-doc',
                    'type': service_doc_type,
                    'title': item.relations['service-doc']['title'],
                    'href': f'{protocol}://{item.domain}{item.anchor}'
                            f'{item.relations['service-doc']['href']}'
                }
                for service_doc_type in item.relations['service-doc']['types']
            ],
            *[
                {
                    'rel': f'{item.relations['conformance']['rel']}',
                    'type': service_desc_type,
                    'title': item.relations['conformance']['title'],
                    'href': f'{protocol}://{item.domain}{item.anchor}'
                            f'{item.relations['conformance']['href']}'
                }
                for service_desc_type in item.relations['conformance']['types']
            ],
            *[{
                'rel': 'self',
                'type': 'application/json',
                'title': item.title,
                'href': f'{protocol}://{item.domain}{item.anchor}'
            }],
            *[{
                'rel': 'alternate',
                'type': 'text/html',
                'title': item.title,
                'href': f'{protocol}://{item.domain}{item.anchor}index.html'
            }]
        ]
    })
    return body


def _prepare_well_known_html(items: List[CatalogRecord], protocol: str) -> str:
    """
    Creates the HTML representation of the Well-known catalog items.

    :param items: The list of portfolio API catalog items.
    :param protocol: The Internet protocol used to access this API.
    :return: The HTML representation of the Well-known catalog items.
    """
    domains: List[CatalogDomainRecord] = list({
        CatalogDomainRecord(item.domain, item.catalog_order, item.title, item.description) for item in items
    })
    domains.sort(key=lambda item: item.catalog_order)

    return (
        '<!DOCTYPE html>'
        '<html lang="en">'
        '<head>'
        '<style>'
        'th.left {text-align: left}'
        'th, td {padding: 5px}'
        'td.top {vertical-align: top}'
        '</style>'
        "<title>Michael's Portfolio Listing of API Documentation Endpoints</title>"
        '</head>'
        "<body><h1>Michael's Portfolio Listing of API Documentation Endpoints</h1><table>"
        f'{''.join([
            '<tr>'
            f'<th colspan="3" class="left">{domain.title}: {domain.description}</th>'
            '</tr>'
            f'{''.join([
                '<tr><td class="top">Service API Documentation</td>'
                f'<td class="top"><a href="{protocol}://{item.domain}{item.anchor}'
                f'{item.relations['service-doc']['href']}" rel="service-doc">'
                f'{item.relations['service-doc']['title']}</a></td>'
                f'<td class="top">{'<br>'.join(item.relations['service-doc']['types'])}</td></tr>'

                '<tr><td class="top">Service API Specification</td>'
                f'<td class="top"><a href="{protocol}://{item.domain}{item.anchor}'
                f'{item.relations['service-desc']['href']}" rel="service-desc">'
                f'{item.relations['service-desc']['title']}</a></td>'
                f'<td class="top">{'<br>'.join(item.relations['service-desc']['types'])}</td></tr>'

                '<tr><td class="top">Service Conformance Metadata</td>'
                f'<td class="top"><a href="{protocol}://{item.domain}{item.anchor}'
                f'{item.relations['conformance']['href']}" rel="{item.relations['conformance']['rel']}">'
                f'{item.relations['conformance']['title']}</a></td>'
                f'<td class="top">{'<br>'.join(item.relations['conformance']['types'])}</td></tr>'

                '<tr><td><br></td><td><br></td><td><br></td></tr>'
                for item in items if item.domain == domain.domain
            ])}'
            for domain in domains
        ])}</table></body></html>'
    )


def _prepare_well_known_json(items: List[CatalogRecord], protocol: str) -> str:
    """
    Creates the JSON representation of the Well-known catalog items.

    :param items: The list of portfolio API catalog items.
    :param protocol: The Internet protocol used to access this API.
    :return: The JSON representation of the Well-known catalog items.
    """
    body = json.dumps({
        'linkset': [
            {
                'anchor': f'{protocol}://{item.domain}{item.anchor}',
                'service-desc': [
                    {
                        'type': service_desc_type,
                        'href': f'{protocol}://{item.domain}{item.anchor}'
                                f'{item.relations['service-desc']['href']}'
                    }
                    for service_desc_type in item.relations['service-desc']['types']
                ],
                'service-doc': [
                    {
                        'type': service_doc_type,
                        'href': f'{protocol}://{item.domain}{item.anchor}'
                                f'{item.relations['service-doc']['href']}'
                    }
                    for service_doc_type in item.relations['service-doc']['types']
                ],
                'service-meta': [
                    {
                        'type': service_desc_type,
                        'href': f'{protocol}://{item.domain}{item.anchor}'
                                f'{item.relations['conformance']['href']}'
                    }
                    for service_desc_type in item.relations['conformance']['types']
                ]
            }
            for item in items
        ]
    })
    return body


def _process_api_request(
        host: str, items: List[CatalogRecord]
) -> Tuple[str, str, Optional[str], Optional[str], int]:
    """
    Construct a JSON body that conforms to the Open API 3.0 Specification.

    :param host: The host from which the request was made.
    :param items: List of catalog records to process.
    :return: A tuple containing (body, content_type, link_header, location_header, status_code)
    """
    api_id = [item.api_id for item in items if item.domain == host][0]
    body = json.dumps(_generate_openapi_document(api_id, 'latest'))

    return body, 'application/vnd.oai.openapi+json;version=3.0', None, None, 200


def _process_conformance_alias_request(
        accept: str, event: Dict[str, Any], host: str, items: List[CatalogRecord]
) -> Tuple[str, str, Optional[str], Optional[str], int]:
    """
    Process conformance alias requests and generate appropriate responses.

    This function handles requests to the '/conformance/{conformance_alias}' endpoint
    and returns the appropriate response based on the Accept header.

    :param accept: The Accept header from the request
    :param event: The event dict that contains the request parameters
    :param host: The host from which the request was made
    :param items: List of catalog records to process
    :return: A tuple containing (body, content_type, link_header, location_header, status_code)
    """
    if 'text/html' in accept:
        alias = event['pathParameters']['conformance_alias']
        item = [entity for entity in items if entity.domain == host][0]
        body, found = _prepare_conformance_alias_html_body(item, alias)

        if found:
            status_code = 200
            content_type = 'text/html; charset=utf-8'

        else:
            status_code = 404
            content_type = 'application/problem+json; charset=utf-8'

        link_header = None
        location_header = None

    else:
        status_code = 404
        content_type = 'application/problem+json; charset=utf-8'
        body = json.dumps({'type': 'about:blank', 'title': 'Not Found'})
        link_header = None
        location_header = None

    return body, content_type, link_header, location_header, status_code


def _process_conformance_request(
        accept: str, host: str, items: List[CatalogRecord], protocol: str
) -> Tuple[str, str, Optional[str], Optional[str], int]:
    """
    Process conformance requests and generate appropriate responses.

    This function handles requests to the '/conformance' endpoint and returns
    the appropriate response based on the Accept header, either in HTML or JSON format.

    :param accept: The Accept header from the request
    :param host: The host from which the request was made
    :param items: List of catalog records to process
    :param protocol: The protocol used for the request (http/https)
    :return: A tuple containing (body, content_type, link_header, location_header, status_code)
    """
    if 'text/html' in accept:
        status_code = 200
        item = [entity for entity in items if entity.domain == host][0]
        body = _prepare_conformance_html_body(item, protocol)
        content_type = 'text/html; charset=utf-8'
        link_header = None
        location_header = None

    elif 'application/json' in accept:
        status_code = 200
        item = [entity for entity in items if entity.domain == host][0]
        body = _prepare_conformance_json_body(item)
        content_type = 'application/json; charset=utf-8'
        link_header = None
        location_header = None

    else:
        status_code = 404
        content_type = 'application/problem+json; charset=utf-8'
        body = json.dumps({'type': 'about:blank', 'title': 'Not Found'})
        link_header = None
        location_header = None

    return body, content_type, link_header, location_header, status_code


def _process_documentation_request(
        host: str, items: List[CatalogRecord]
) -> Tuple[str, str, Optional[str], Optional[str], int]:
    """
    Process documentation requests and generate appropriate responses.

    This function handles requests to the 'documentation' endpoint and returns
    the appropriate response based on the Accept header.

    :param host: The host from which the request was made
    :param items: List of catalog records to process
    :return: A tuple containing (body, content_type, link_header, location_header, status_code)
    """
    api_id = [item.api_id for item in items if item.domain == host][0]
    openapi_doc = _generate_openapi_document(api_id, 'latest')
    body = _generate_openapi_html(openapi_doc)

    return body, 'text/html', None, None, 200


def _process_landing_page_request(
        accept: str, host: str, items: List[CatalogRecord], protocol: str
) -> Tuple[str, str, Optional[str], Optional[str], int]:
    """
    Process landing page requests and generate appropriate responses.

    This function handles requests to the root endpoint ('/') and returns
    the appropriate response based on the Accept header, either in HTML or JSON format.

    :param accept: The Accept header from the request
    :param host: The host from which the request was made
    :param items: List of catalog records to process
    :param protocol: The protocol used for the request (http/https)
    :return: A tuple containing (body, content_type, link_header, location_header, status_code)
    """
    if 'text/html' in accept:
        status_code = 200
        body = _prepare_landing_html_body(host, items, protocol)
        content_type = 'text/html; charset=utf-8'
        link_header = '</.well-known/api-catalog>; rel=api-catalog'
        location_header = '/index.html'

    elif 'application/json' in accept:
        status_code = 200
        item = [entity for entity in items if entity.domain == host][0]
        body = _prepare_landing_json_body(item, protocol)
        content_type = 'application/json; charset=utf-8'
        link_header = None
        location_header = '/'

    else:
        status_code = 404
        content_type = 'application/problem+json; charset=utf-8'
        body = json.dumps({'type': 'about:blank', 'title': 'Not Found'})
        link_header = None
        location_header = None

    return body, content_type, link_header, location_header, status_code


def _process_well_known_request(
        accept: str, event: Dict[str, Any], host: str, items: List[CatalogRecord], protocol: str
) -> Tuple[str, str, Optional[str], Optional[str], int]:
    """
    Process well-known requests and generate appropriate responses.

    This function handles requests to the '/.well-known/{well_known_name}' endpoint
    and returns the appropriate response based on the Accept header and the well-known name.
    Currently, it supports 'api-catalog' as a well-known name.

    :param accept: The Accept header from the request.
    :param event: The event dict that contains the request parameters.
    :param host: The host from which the request was made.
    :param items: List of catalog records to process.
    :param protocol: The protocol used for the request (http/https).
    :return: A tuple containing (body, content_type, link_header, location_header, status_code).
    """
    path_parameters = event.get('pathParameters', None)
    path_parameters = path_parameters if path_parameters is not None else dict()
    match path_parameters['well_known_name']:
        case 'api-catalog':
            if 'text/html' in accept:
                status_code = 200
                body = _prepare_well_known_html(items, protocol)
                content_type = 'text/html; charset=utf-8'
                link_header = f'</.well-known/api-catalog>; rel=api-catalog'
                location_header = f'{protocol}://{host}{event['path']}'

            elif 'application/linkset+json' in accept:
                status_code = 200
                body = _prepare_well_known_json(items, protocol)
                content_type = 'application/linkset+json; charset=utf-8'
                link_header = f'</.well-known/api-catalog>; rel=api-catalog'
                location_header = f'{protocol}://{host}{event['path']}'

            else:
                content_type = 'application/problem+json; charset=utf-8'
                status_code = 404
                body = json.dumps({'type': 'about:blank', 'title': 'Not Found'})
                link_header = None
                location_header = None

        case _:
            content_type = 'application/problem+json; charset=utf-8'
            status_code = 404
            body = json.dumps({'type': 'about:blank', 'title': 'Not Found'})
            link_header = None
            location_header = None

    return body, content_type, link_header, location_header, status_code
