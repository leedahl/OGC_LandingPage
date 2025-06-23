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
from datetime import datetime
from decimal import Decimal
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
    print(f'Received Event: {event}')

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
                accept, event, host, items, protocol
            )

        case '/api':
            body, content_type, link_header, location_header, status_code = _process_api_request(host, items)

        case '/documentation':
            body, content_type, link_header, location_header, status_code = _process_documentation_request(host, items)

        case '/':
            body, content_type, link_header, location_header, status_code = _process_landing_page_request(
                accept, host, items, protocol
            )

        case _:
            print(f'Unhandled method: {event.get("resource", '')}')
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


def _convert_decimal_to_int_or_float(obj: Any) -> Any:
    """
    Recursively convert Decimal values to int or float based on whether they have a fractional part.

    Args:
        obj: The object to convert, which may contain Decimal values

    Returns:
        The converted object with Decimal values replaced by int or float
    """
    if isinstance(obj, Decimal):
        # Convert to int if the Decimal has no fractional part, otherwise to float
        return int(obj) if obj % 1 == 0 else float(obj)

    elif isinstance(obj, dict):
        # Recursively process dictionaries
        return {key: _convert_decimal_to_int_or_float(value) for key, value in obj.items()}

    elif isinstance(obj, list):
        # Recursively process lists
        return [_convert_decimal_to_int_or_float(item) for item in obj]

    elif isinstance(obj, tuple):
        # Recursively process tuples
        return tuple(_convert_decimal_to_int_or_float(item) for item in obj)

    else:
        # Return other types unchanged
        return obj


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
                # Convert Decimal values to int or float
                items = _convert_decimal_to_int_or_float(documents_response['Items'])
                # Sort by version and get the latest
                items = sorted(items, key=lambda x: x['version'], reverse=True)
                document = items[0]
                version = document['version']
            else:
                raise ValueError(f"API with id {api_id} not found")
        else:
            raise ValueError(f"API with id {api_id} and version {version} not found")
    else:
        # Convert Decimal values to int or float
        document = _convert_decimal_to_int_or_float(document_response['Item'])

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
        # Convert Decimal values to int or float
        servers = _convert_decimal_to_int_or_float(servers_response['Items'])
        openapi_doc["servers"] = list()
        for server in servers:
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

    # Convert Decimal values to int or float
    path_items = _convert_decimal_to_int_or_float(paths_response.get('Items', []))

    operations_table = dynamodb_resource.Table('openapi_operations')

    for path_item in path_items:
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

        # Convert Decimal values to int or float
        operations = _convert_decimal_to_int_or_float(operations_response.get('Items', []))

        for operation in operations:
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

    # Convert Decimal values to int or float
    components = _convert_decimal_to_int_or_float(components_response.get('Items', []))

    for component in components:
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
        # Convert Decimal values to int or float
        tags = _convert_decimal_to_int_or_float(tags_response['Items'])
        openapi_doc["tags"] = []
        for tag in tags:
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

    # Convert Decimal values to int or float
    security_schemes = _convert_decimal_to_int_or_float(security_response.get('Items', []))

    for scheme in security_schemes:
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
    current_year = datetime.now().year  # Dynamically get the current year

    # Create a basic HTML template with Swagger UI
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - OpenAPI Documentation</title>
    <style>
        /* Basic reset and common styles */
        body {{
            margin: 0;
            padding: 0;
            font-family: Arial, sans-serif;
            color: #3b4151;
        }}

        /* Header, nav, section, footer styles */
        header, nav, section, footer {{
            margin-bottom: 20px;
        }}

        header {{
            background-color: #f5f5f5;
            padding: 10px;
        }}

        nav {{
            background-color: #eee;
            padding: 10px;
        }}

        .content {{
            padding: 20px;
            border: 1px solid #ddd;
        }}

        .hidden {{
            display: none;
        }}

        footer {{
            text-align: center;
            font-size: 0.8em;
            color: #666;
        }}

        /* Swagger UI container */
        #swagger-ui {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}

        /* Header styling */
        .swagger-ui .topbar {{
            background-color: #1b1b1b;
            padding: 10px 0;
        }}

        .swagger-ui .info {{
            margin: 20px 0;
        }}

        .swagger-ui .info .title {{
            font-size: 36px;
            margin: 0;
            font-weight: bold;
        }}

        .swagger-ui .info .description {{
            font-size: 14px;
            margin: 10px 0;
        }}

        /* Operation blocks */
        .swagger-ui .opblock {{
            margin: 0 0 15px;
            border-radius: 4px;
            box-shadow: 0 0 3px rgba(0,0,0,.19);
        }}

        .swagger-ui .opblock .opblock-summary {{
            padding: 5px;
            cursor: pointer;
        }}

        .swagger-ui .opblock .opblock-summary-method {{
            font-size: 14px;
            font-weight: 700;
            min-width: 80px;
            padding: 6px 15px;
            text-align: center;
            border-radius: 3px;
            text-shadow: 0 1px 0 rgba(0,0,0,.1);
            font-family: sans-serif;
            color: #fff;
        }}

        /* HTTP methods colors */
        .swagger-ui .opblock-get .opblock-summary-method {{
            background: #61affe;
        }}

        .swagger-ui .opblock-post .opblock-summary-method {{
            background: #49cc90;
        }}

        .swagger-ui .opblock-put .opblock-summary-method {{
            background: #fca130;
        }}

        .swagger-ui .opblock-delete .opblock-summary-method {{
            background: #f93e3e;
        }}

        .swagger-ui .opblock-patch .opblock-summary-method {{
            background: #50e3c2;
        }}

        /* Models */
        .swagger-ui .model {{
            font-size: 12px;
            font-weight: 300;
            font-family: monospace;
        }}

        .swagger-ui .model-title {{
            font-size: 16px;
            font-family: sans-serif;
            margin: 10px 0;
        }}

        /* Tables */
        .swagger-ui table {{
            width: 100%;
            border-collapse: collapse;
        }}

        .swagger-ui table thead tr th {{
            font-size: 12px;
            font-weight: 700;
            padding: 12px 0;
            text-align: left;
            border-bottom: 1px solid rgba(59,65,81,.2);
        }}

        .swagger-ui table tbody tr td {{
            padding: 10px 0;
            vertical-align: top;
        }}

        /* Buttons */
        .swagger-ui .btn {{
            font-size: 14px;
            font-weight: 700;
            padding: 5px 23px;
            transition: all .3s;
            border: 2px solid #888;
            border-radius: 4px;
            background: transparent;
            box-shadow: 0 1px 2px rgba(0,0,0,.1);
            cursor: pointer;
        }}

        .swagger-ui .btn.execute {{
            background-color: #4990e2;
            color: #fff;
            border-color: #4990e2;
        }}

        /* Schema */
        .swagger-ui .property-name {{
            font-size: 14px;
            font-family: monospace;
            font-weight: 600;
        }}

        .swagger-ui .property-type {{
            color: #6b6b6b;
        }}

        /* Responses */
        .swagger-ui .responses-inner {{
            padding: 20px;
        }}

        .swagger-ui .response-col_status {{
            font-size: 14px;
            font-family: sans-serif;
        }}

        /* Code blocks */
        .swagger-ui .microlight {{
            font-size: 12px;
            font-family: monospace;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}
    </style>
</head>
<body>
    <header>
        <h1>{title} - OpenAPI Documentation</h1>
    </header>
    <nav>
        <a href="/">Home</a> &gt; <a href="/documentation">API Documentation</a>
    </nav>
    <section class="content">
        <div id="swagger-ui"></div>
    </section>
    <footer>
        &copy; {current_year} Michael Leedahl
    </footer>
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
    <script>showSection();</script>
</body>
</html>"""

    return html


def _prepare_conformance_alias_html_body(item: CatalogRecord, alias: str, host: str, protocol: str) -> Tuple[str, bool]:
    """
    Create the HTML representation of a conformance metadata that is associated with specified alias.

    :param item: The catalog record that contains information about the API that conforms to the specified alias.
    :param alias: The alias of the conformance requirement.
    :param host: The website hostname.
    :param protocol: The Internet Protocol used to access this page.
    :return: The HTML representation of the conformance metadata that is associated with specified alias.
    """
    current_year = datetime.now().year  # Dynamically get the current year

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
            '<!DOCTYPE html>'
            '<html lang="en">'
            '<head>'
            '<style>'
            '  body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }'
            '  header, nav, section, footer { margin-bottom: 20px; }'
            '  header { background-color: #f5f5f5; padding: 10px; }'
            '  nav { background-color: #eee; padding: 10px; }'
            '  .content { padding: 20px; border: 1px solid #ddd; }'
            '  .hidden { display: none; }'
            '  footer { text-align: center; font-size: 0.8em; color: #666; }'
            '  th, td {padding: 5px; text-align: left;}'
            '</style>'
            f'<title>{item.title} Conformance Metadata</title>'
            '</head>'
            '<body>'
            '<header>'
            f'<h1>{item.title} Conformance Metadata</h1>'
            '</header>'
            '<nav>'
            f'<a href="{protocol}://{host}/">Home</a> &gt; '
            f'<a href="{protocol}://{host}/conformance">Conformance</a> &gt; {alias}'
            '</nav>'
            '<section class="content">'
            '<table>'
            '<tr><th>Conformance URI</th><th>Title</th></tr>'
            f'<tr><td>{conformance_item['conformance_uri']}</td><td>{conformance_item['title']}</td></tr>'
            '</table>'
            f'{bytes(conformance_item['description']).decode('utf_8')}'
            '</section>'
            '<footer>'
            f'&copy; {current_year} Michael Leedahl'
            '</footer>'
            '<script>showSection();</script>'
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
    current_year = datetime.now().year  # Dynamically get the current year
    dynamodb_client = resource('dynamodb')
    api_methods_table = dynamodb_client.Table('api_conformance')
    conformance_items = api_methods_table.query(
        Select='ALL_ATTRIBUTES',
        ConsistentRead=True,
        KeyConditionExpression='api_id = :api_id',
        ExpressionAttributeValues={':api_id': item.api_id},
    )

    return (
        '<!DOCTYPE html>'
        '<html lang="en">'
        '<head>'
        '<style>'
        '  body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }'
        '  header, nav, section, footer { margin-bottom: 20px; }'
        '  header { background-color: #f5f5f5; padding: 10px; }'
        '  nav { background-color: #eee; padding: 10px; }'
        '  .content { padding: 20px; border: 1px solid #ddd; }'
        '  .hidden { display: none; }'
        '  footer { text-align: center; font-size: 0.8em; color: #666; }'
        '  th, td {text-align: left; padding: 5px;}'
        '</style>'
        f'<title>{item.title} Conformance Metadata</title>'
        '</head>'
        '<body>'
        '<header>'
        f'<h1>{item.title} Conformance Metadata</h1>'
        '</header>'
        '<nav>'
        f'<a href="{protocol}://{item.domain}/">Home</a> &gt; '
        f'<a href="{protocol}://{item.domain}{item.anchor}conformance">Conformance</a>'
        '</nav>'
        '<section class="content">'
        '<p>On this page you will find links to the Conformance Metadata for the Requirements this API conforms to.</p>'
        '<table>'
        '<tr><th>Conformance Metadata Links</th>'
        f'{''.join([
            f'<tr><td><a href="{protocol}://{item.domain}{item.anchor}conformance/{conformance_item['alias']}">'
            f'{conformance_item['title']}</a></td></tr>'
            for conformance_item in conformance_items['Items']
        ])}'
        '</table>'
        '</section>'
        '<footer>'
        f'&copy; {current_year} Michael Leedahl'
        '</footer>'
        '<script>showSection();</script>'
        '</body>'
        '</html>'
    )


def _prepare_conformance_json_body(item: CatalogRecord) -> str:
    """
    Creates the JSON Representation of the Conformance body.

    :param item: A catalog record to use for reporting the conformance metadata.
    :return: The JSON Representation of the Conformance body.
    """
    return f'{{"conformsTo": ["{'", "'.join(item.relations['service-meta']['conformsTo'])}"]}}'


def _prepare_landing_html_body(host: str, items: List[CatalogRecord], protocol: str) -> str:
    """
    Creates the HTML body for the landing page.

    :param host: The host of the landing page.
    :param items: The catalog API items.
    :param protocol: The protocol used to invoke the landing page.
    :return: The body of the landing page.
    """
    current_year = datetime.now().year  # Dynamically get the current year

    body = (
        '<!DOCTYPE HTML>'
        '<html lang="en">'
        '<head>'
        "<title>Michael's Portfolio of APIs</title>"
        '<style>'
        '  body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }'
        '  header, nav, section, footer { margin-bottom: 20px; }'
        '  header { background-color: #f5f5f5; padding: 10px; }'
        '  nav { background-color: #eee; padding: 10px; }'
        '  .content { padding: 20px; border: 1px solid #ddd; }'
        '  .hidden { display: none; }'
        '  footer { text-align: center; font-size: 0.8em; color: #666; }'
        '</style>'
        '</head>'
        '<body>'
        '<header>'
        "<h1>Michael's Portfolio of APIs</h1>"
        '</header>'
        '<nav>'
        f'<a href="{protocol}://{host}/">Home</a>'
        '</nav>'
        '<section class="content">'
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
            f'<a href="{protocol}://{item.domain}{item.anchor}{item.relations['service-meta']['href']}" '
            f'rel="{item.relations['service-meta']['rel']}">Conformance</a>: '
            f'{item.relations['service-meta']['title']}<br><br>'
        )}'
        for item in items
    ])
    body += (
        '</p>'
        '</section>'
        '<footer>'
        f'&copy; {current_year} Michael Leedahl'
        '</footer>'
        '<script>showSection();</script>'
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
                    'rel': f'{item.relations['service-meta']['rel']}',
                    'type': service_desc_type,
                    'title': item.relations['service-meta']['title'],
                    'href': f'{protocol}://{item.domain}{item.anchor}'
                            f'{item.relations['service-meta']['href']}'
                }
                for service_desc_type in item.relations['service-meta']['types']
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
    current_year = datetime.now().year  # Dynamically get the current year
    domains: List[CatalogDomainRecord] = list({
        CatalogDomainRecord(item.domain, item.catalog_order, item.title, item.description) for item in items
    })
    domains.sort(key=lambda item: item.catalog_order)

    # Get the first domain to use in navigation
    first_domain = domains[0].domain if domains else ""

    return (
        '<!DOCTYPE html>'
        '<html lang="en">'
        '<head>'
        '<style>'
        '  body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }'
        '  header, nav, section, footer { margin-bottom: 20px; }'
        '  header { background-color: #f5f5f5; padding: 10px; }'
        '  nav { background-color: #eee; padding: 10px; }'
        '  .content { padding: 20px; border: 1px solid #ddd; }'
        '  .hidden { display: none; }'
        '  footer { text-align: center; font-size: 0.8em; color: #666; }'
        '  th.left {text-align: left}'
        '  th, td {padding: 5px}'
        '  td.top {vertical-align: top}'
        '</style>'
        "<title>Michael's Portfolio Listing of API Documentation Endpoints</title>"
        '</head>'
        '<body>'
        '<header>'
        "<h1>Michael's Portfolio Listing of API Documentation Endpoints</h1>"
        '</header>'
        '<nav>'
        f'<a href="{protocol}://{first_domain}/">Home</a> &gt; '
        f'<a href="{protocol}://{first_domain}/.well-known/api-catalog">API Catalog</a>'
        '</nav>'
        '<section class="content">'
        '<table>'
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
                f'{item.relations['service-meta']['href']}" rel="{item.relations['service-meta']['rel']}">'
                f'{item.relations['service-meta']['title']}</a></td>'
                f'<td class="top">{'<br>'.join(item.relations['service-meta']['types'])}</td></tr>'

                '<tr><td><br></td><td><br></td><td><br></td></tr>'
                for item in items if item.domain == domain.domain
            ])}'
            for domain in domains
        ])}'
        '</table>'
        '</section>'
        '<footer>'
        f'&copy; {current_year} Michael Leedahl'
        '</footer>'
        '<script>showSection();</script>'
        '</body>'
        '</html>'
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
                                f'{item.relations['service-meta']['href']}'
                    }
                    for service_desc_type in item.relations['service-meta']['types']
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
        accept: str, event: Dict[str, Any], host: str, items: List[CatalogRecord], protocol: str
) -> Tuple[str, str, Optional[str], Optional[str], int]:
    """
    Process conformance alias requests and generate appropriate responses.

    This function handles requests to the '/conformance/{conformance_alias}' endpoint
    and returns the appropriate response based on the Accept header.

    :param accept: The Accept header from the request
    :param event: The event dict that contains the request parameters
    :param host: The host from which the request was made
    :param items: List of catalog records to process
    :param protocol: The Internet protocol used to access this API.
    :return: A tuple containing (body, content_type, link_header, location_header, status_code)
    """
    if 'text/html' in accept:
        alias = event['pathParameters']['conformance_alias']
        item = [entity for entity in items if entity.domain == host][0]
        body, found = _prepare_conformance_alias_html_body(item, alias, host, protocol)

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
