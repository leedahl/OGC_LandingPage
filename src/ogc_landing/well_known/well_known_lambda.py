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
from json import dumps
from typing import List, Tuple

import boto3
from botocore.exceptions import BotoCoreError

Record = namedtuple('Record', [
    'api_type', 'method_name', 'domain', 'http_methods', 'inputs', 'media_types', 'security_controls', 'title'
])

WellKnownRecord = namedtuple('WellKnownRecord', [
    'api_type', 'method_name', 'domain', 'media_types', 'title'
])

CatalogRecord = namedtuple('CatalogRecord', [
    'api_id', 'catalog_order', 'anchor', 'description', 'domain', 'relations', 'title'
])

CatalogDomainRecord = namedtuple('CatalogDomainRecord', [
    'domain', 'catalog_order', 'title', 'description'
])


# noinspection PyUnusedLocal
def lambda_handler(event, context):
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

    dynamodb_client = boto3.resource('dynamodb')
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
            body, content_type, link_header, location_header, status_code = _process_api_request(
                accept, event, host, items
            )

        case 'documentation':
            body, content_type, link_header, location_header, status_code = _process_documentation_request(
                accept, event, host, items
            )

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


def _process_api_request(
        accept: str, event: dict, host: str, items: List[CatalogRecord]
) -> Tuple[str, str, str, str, int]:
    return '', '', '', '', 200


def _process_documentation_request(
        accept: str, event: dict, host: str, items: List[CatalogRecord]
) -> Tuple[str, str, str, str, int]:
    return '', '', '', '', 200


def _process_landing_page_request(accept, host, items, protocol):
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


def _process_conformance_alias_request(accept, event, host, items):
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


def _process_conformance_request(accept, host, items, protocol):
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


def _process_well_known_request(accept, event, host, items, protocol):
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


def _prepare_conformance_alias_html_body(item: CatalogRecord, alias: str) -> Tuple[str, bool]:
    """
    Create the HTML representation of a conformance metadata that is associated with specified alias.

    :param item: The catalog record that contains information about the API that conforms to the specified alias.
    :param alias: The alias of the conformance requirement.
    :return: The HTML representation of the conformance metadata that is associated with specified alias.
    """
    try:
        dynamodb_client = boto3.resource('dynamodb')
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
    dynamodb_client = boto3.resource('dynamodb')
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


def _save_for_reference(accept, event):
    dynamodb_client = boto3.resource('dynamodb')
    api_methods_table = dynamodb_client.Table('api_methods')
    api_methods = api_methods_table.query(
        Select='ALL_ATTRIBUTES',
        ConsistentRead=True,
        KeyConditionExpression='api_type = :api_type',
        ExpressionAttributeValues={':api_type': 'api'}
    )
    items = [
        Record(
            item['api_type'], item['method_name'], item['domain'], item['http_methods'], item['inputs'],
            item['media_types'], item['security_controls'], item['title']
        )
        for item in api_methods['Items'] if item['api_type'] == 'api'
    ]
    items.sort(key=lambda item: (item.domain, item.title))
    domains = set([item.domain for item in items])
    if 'text/html' in accept:
        body = (
            '<!DOCTYPE HTML>'
            '<html lang="en">'
            '<head>'
            '<style>'
            'table.solid, th, td {border: 1px solid black; border-collapse: collapse; '
            'padding: 5px; text-align: center}'
            'table.none, th.none, td.none {border: none; border-collapse: collapse; text-align: left}'
            'td.top {vertical-align: top}'
            'td.left {border: none; border-bottom: 1px solid black; text-align: left}'
            'th.bottom, td.bottom {border: none; border-bottom: 1px solid black}'
            '</style>'
            "<title>Michael's API Catalog</title>"
            '</head>'
            '<body>'
            "<h1>Welcome to Michael's API Catalog</h1>"
            '<table class="none">'
        )

        for domain in domains:
            body += (
                f'<tr class="none"><td class="none"><br>{domain.replace("https://", "")}</td></tr>'
                f'<tr class="none"><td class="none"><table class="solid">'
                f'<tr><th>API Method Title</th><th>URL</th><th>HTTP Methods</th><th>Media Types</th>'
                f'<th>Security Controls</th><th>Inputs</th></tr>'
            )

            body += ''.join([
                f'<tr><td>{item.title}</td>'
                f'<td>{(
                    f'<a href="{item.domain}/{item.method_name.rstrip()}">'
                    f'{item.domain}/{item.method_name.rstrip()}</a>'
                    if event['resource'] != f'/{item.method_name.rstrip()}'
                    else f'{item.domain}/{item.method_name.rstrip()}'
                )}</td>'
                f'<td>{dumps(list(item.http_methods))}</td>'
                f'<td>{dumps(list(item.media_types))}</td>'
                f'{(
                    f'<td class="top">'
                    f'<table class="none"><tr><th class="bottom">Name</th>'
                    f'<th class="bottom">Type</th></tr>'
                    f'{"".join([
                        f"<tr>"
                        f"<td class=\"bottom\">"
                        f"{'Authentication' if key == 'authentication' else key}</td>"
                        f"<td class=\"bottom\">"
                        f"{"Basic" if value == 'basic' else value}"
                        f"</td>"
                        f"</tr>"
                        for key, value in item.security_controls.items()
                    ])}</table>' if len(item.security_controls.keys()) > 0 else '<td>None'
                )}</td>'
                f'{(
                    f'<td class="top">'
                    f'<table class="none"><tr><th class="bottom">Name</th>'
                    f'<th class="bottom">Description</th></tr>'
                    f'{"".join([
                        f"<tr>"
                        f"<td class=\"bottom\">{key_input}</td>"
                        f"<td class=\"left\">{value_input}</td>"
                        f"</tr>"
                        for key_input, value_input in item.inputs.items()
                    ])}</table>' if len(item.inputs.keys()) > 0 else '<td>None'
                )}</td></tr>'
                for item in items if item[2] == domain
            ])

            body += '</table></td></tr>'

        body += (
            f'</table>'
            '</body>'
            '</html>'
        )

        status_code = 200
        content_type = 'text/html; charset=utf-8'
        location_header = '/.well-known/api-catalog'
        link_header = None

    else:
        # {
        #   "linkset": [
        #   {
        #     "anchor": "https://developer.example.com/apis/foo_api",
        #     "service-desc": [
        #       {
        #         "href": "https://developer.example.com/apis/foo_api/spec",
        #         "type": "application/yaml"
        #       }
        #     ],
        #     "status": [
        #       {
        #         "href": "https://developer.example.com/apis/foo_api/status",
        #         "type": "application/json"
        #       }
        #     ],
        #     "service-doc": [
        #       {
        #         "href": "https://developer.example.com/apis/foo_api/doc",
        #         "type": "text/html"
        #       }
        #     ],
        #     "service-meta": [
        #       {
        #         "href": "https://developer.example.com/apis/foo_api/policies",
        #         "type": "text/xml"
        #       }
        #     ]
        #   },
        #   {
        #     "anchor": "https://developer.example.com/apis/bar_api",
        #     "service-desc": [
        #       {
        #         "href": "https://developer.example.com/apis/bar_api/spec",
        #         "type": "application/yaml"
        #       }
        #     ],
        #     "status": [
        #       {
        #         "href": "https://developer.example.com/apis/bar_api/status",
        #        "type": "application/json"
        #       }
        #     ],
        #     "service-doc": [
        #       {
        #         "href": "https://developer.example.com/apis/bar_api/doc",
        #         "type": "text/plain"
        #       }
        #     ]
        #   },
        #   {
        #     "anchor": "https://apis.example.net/apis/cantona_api",
        #     "service-desc": [
        #       {
        #         "href": "https://apis.example.net/apis/cantona_api/spec",
        #         "type": "text/n3"
        #       }
        #     ],
        #     "service-doc": [
        #       {
        #         "href": "https://apis.example.net/apis/cantona_api/doc",
        #         "type": "text/html"
        #       }
        #     ]
        #   }
        #   ]
        # }
        status_code = 200
        body = json.dumps({
            'linkset': [
                {
                    'anchor': f'{domain}/.well-known/api-catalog',
                    'item': [
                        {
                            'well-known': ['api-catalog'],
                        }
                        for item in items if item.domain == domain
                    ],
                    'api-catalog': f'{domain}/.well-known/api-catalog'
                }
                for domain in domains
            ]
        })
        content_type = 'application/linkset+json'
        link_header = None
        location_header = None
    return body, content_type, link_header, location_header, status_code


def _prepare_landing_json_body(item, protocol):
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


def _prepare_landing_html_body(host, items, protocol):
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
