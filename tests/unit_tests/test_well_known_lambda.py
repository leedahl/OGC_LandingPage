import unittest
from unittest.mock import patch, MagicMock

from ogc_landing.well_known.well_known_lambda import lambda_handler, Record


class TestLambdaHandler(unittest.TestCase):
    """Test cases for the lambda_handler function in well_known_lambda.py."""

    @patch('boto3.resource')
    def test_api_catalog_html(self, mock_boto3_resource):
        """Test lambda_handler when requesting /.well-known/api-catalog with HTML Accept header."""
        # Setup mock DynamoDB response
        mock_table = MagicMock()
        mock_boto3_resource.return_value.Table.return_value = mock_table

        mock_scan_response = {
            'Items': [
                {
                    'api_id': 'test-api',
                    'catalog_order': 1,
                    'anchor': '#test',
                    'description': 'Test API Description',
                    'domain': 'example.com',
                    'relations': {
                        'service-doc': {
                            'href': '/docs',
                            'title': 'API Documentation',
                            'types': ['text/html']
                        },
                        'service-desc': {
                            'href': '/spec',
                            'title': 'API Specification',
                            'types': ['application/json']
                        },
                        'conformance': {
                            'href': '/conformance',
                            'rel': 'conformance',
                            'title': 'Conformance',
                            'types': ['text/html', 'application/json']
                        }
                    },
                    'title': 'Test API'
                }
            ]
        }
        mock_table.scan.return_value = mock_scan_response

        # Setup event
        event = {
            'resource': '/.well-known/{well_known_name}',
            'pathParameters': {
                'well_known_name': 'api-catalog'
            },
            'headers': {
                'Accept': 'text/html',
                'Host': 'example.com'
            },
            'path': '/.well-known/api-catalog'
        }
        context = {}

        # Execute
        result = lambda_handler(event, context)

        # Verify
        self.assertEqual(result['statusCode'], 200)
        self.assertEqual(result['headers']['Content-Type'], 'text/html; charset=utf-8')
        self.assertIn('<!DOCTYPE html>', result['body'])
        self.assertIn("Michael's Portfolio", result['body'])
        self.assertEqual(result['isBase64Encoded'], False)

        # Verify DynamoDB was scanned correctly
        mock_table.scan.assert_called_once_with(
            Select='ALL_ATTRIBUTES',
            ConsistentRead=True
        )

    @patch('boto3.resource')
    def test_api_catalog_json(self, mock_boto3_resource):
        """Test lambda_handler when requesting /.well-known/api-catalog with JSON Accept header."""
        # Setup mock DynamoDB response
        mock_table = MagicMock()
        mock_boto3_resource.return_value.Table.return_value = mock_table

        # Setup event
        event = {
            'resource': '/.well-known/{well_known_name}',
            'pathParameters': {
                'well_known_name': 'api-catalog'
            },
            'headers': {
                'Accept': 'application/linkset+json',
                'Host': 'example.com'
            },
            'path': '/.well-known/api-catalog'
        }
        context = {}

        # Execute
        result = lambda_handler(event, context)

        # Verify
        self.assertEqual(result['statusCode'], 200)
        self.assertEqual(result['headers']['Content-Type'], 'application/linkset+json; charset=utf-8')
        self.assertEqual(result['body'], '{}')
        self.assertEqual(result['isBase64Encoded'], False)

    @patch('boto3.resource')
    def test_unknown_well_known_name(self, mock_boto3_resource):
        """Test lambda_handler when requesting an unknown well-known name."""
        # Setup mock DynamoDB response
        mock_table = MagicMock()
        mock_boto3_resource.return_value.Table.return_value = mock_table

        # Setup event
        event = {
            'resource': '/.well-known/{well_known_name}',
            'pathParameters': {
                'well_known_name': 'unknown'
            },
            'headers': {
                'Accept': 'text/html',
                'Host': 'example.com'
            }
        }
        context = {}

        # Execute
        result = lambda_handler(event, context)

        # Verify
        self.assertEqual(result['statusCode'], 404)
        self.assertEqual(result['headers']['Content-Type'], 'application/problem+json; charset=utf-8')
        self.assertIn('Not Found', result['body'])
        self.assertEqual(result['isBase64Encoded'], False)

    @patch('boto3.resource')
    def test_root_path_html(self, mock_boto3_resource):
        """Test lambda_handler when requesting the root path (/) with HTML Accept header."""
        # Setup mock DynamoDB response
        mock_table = MagicMock()
        mock_boto3_resource.return_value.Table.return_value = mock_table

        mock_scan_response = {
            'Items': [
                {
                    'api_id': 'test-api',
                    'catalog_order': 1,
                    'anchor': '#test',
                    'description': 'Test API Description',
                    'domain': 'example.com',
                    'relations': {
                        'service-doc': {
                            'href': '/docs',
                            'title': 'API Documentation',
                            'types': ['text/html']
                        },
                        'service-desc': {
                            'href': '/spec',
                            'title': 'API Specification',
                            'types': ['application/json']
                        },
                        'conformance': {
                            'href': '/conformance',
                            'rel': 'conformance',
                            'title': 'Conformance',
                            'types': ['text/html']
                        }
                    },
                    'title': 'Test API'
                }
            ]
        }
        mock_table.scan.return_value = mock_scan_response

        # Setup event
        event = {
            'resource': '/',
            'headers': {
                'Accept': 'text/html',
                'Host': 'example.com'
            }
        }
        context = {}

        # Execute
        result = lambda_handler(event, context)

        # Verify
        self.assertEqual(result['statusCode'], 200)
        self.assertEqual(result['headers']['Content-Type'], 'text/html; charset=utf-8')
        self.assertEqual(result['headers']['Link'], '</.well-known/api-catalog>; rel=api-catalog')
        self.assertEqual(result['headers']['Location'], '/index.html')
        self.assertIn('<!DOCTYPE HTML>', result['body'])
        self.assertEqual(result['isBase64Encoded'], False)

    @patch('boto3.resource')
    def test_root_path_json(self, mock_boto3_resource):
        """Test lambda_handler when requesting the root path (/) with JSON Accept header."""
        # Setup mock DynamoDB response
        mock_table = MagicMock()
        mock_boto3_resource.return_value.Table.return_value = mock_table

        mock_scan_response = {
            'Items': [
                {
                    'api_id': 'test-api',
                    'catalog_order': 1,
                    'anchor': '#test',
                    'description': 'Test API Description',
                    'domain': 'example.com',
                    'relations': {
                        'service-doc': {
                            'href': '/docs',
                            'title': 'API Documentation',
                            'types': ['text/html']
                        },
                        'service-desc': {
                            'href': '/spec',
                            'title': 'API Specification',
                            'types': ['application/json']
                        },
                        'conformance': {
                            'href': '/conformance',
                            'rel': 'conformance',
                            'title': 'Conformance',
                            'types': ['text/html']
                        }
                    },
                    'title': 'Test API'
                }
            ]
        }
        mock_table.scan.return_value = mock_scan_response

        # Setup event
        event = {
            'resource': '/',
            'headers': {
                'Accept': 'application/json',
                'Host': 'example.com'
            }
        }
        context = {}

        # Execute
        result = lambda_handler(event, context)

        # Verify
        self.assertEqual(result['statusCode'], 200)
        self.assertEqual(result['headers']['Content-Type'], 'application/json; charset=utf-8')
        self.assertEqual(result['headers']['Location'], '/')
        self.assertEqual(result['isBase64Encoded'], False)

    def test_index_html_redirect(self):
        """Test lambda_handler redirects /index.html to /."""
        # Setup event
        event = {
            'resource': '/index.html'
        }
        context = {}

        # Execute with patched print to avoid output
        with patch('builtins.print'):
            lambda_handler(event, context)

        # Verify resource was changed to '/'
        self.assertEqual(event['resource'], '/')
        self.assertEqual(event['headers']['Accept'], 'text/html')

    @patch('boto3.resource')
    def test_unknown_resource(self, mock_boto3_resource):
        """Test lambda_handler when requesting an unknown resource."""
        # Setup mock DynamoDB response
        mock_table = MagicMock()
        mock_boto3_resource.return_value.Table.return_value = mock_table

        # Setup event
        event = {
            'resource': '/unknown'
        }
        context = {}

        # Execute
        result = lambda_handler(event, context)

        # Verify
        self.assertEqual(result['statusCode'], 404)
        self.assertEqual(result['headers']['Content-Type'], 'application/problem+json; charset=utf-8')
        self.assertIn('Not Found', result['body'])
        self.assertEqual(result['isBase64Encoded'], False)

    @patch('builtins.print')
    def test_print_event(self, mock_print):
        """Test that the event is printed."""
        # Setup event
        event = {
            'resource': '/unknown'
        }
        context = {}

        # Execute with mocked DynamoDB
        with patch('boto3.resource'):
            lambda_handler(event, context)

        # Verify print was called with the event
        mock_print.assert_called_once_with(event)


if __name__ == '__main__':
    unittest.main()
