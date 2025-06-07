# Copyright (c) 2025
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import unittest
from unittest.mock import patch

from ogc_landing.greeting.greeting_lambda import lambda_handler


class TestLambdaHandler(unittest.TestCase):
    """Test cases for the lambda_handler function."""

    def test_lambda_handler_with_name(self):
        """Test lambda_handler when a name is provided in pathParameters."""
        # Setup
        event = {
            'pathParameters': {
                'name': 'John'
            }
        }
        context = {}

        # Execute
        result = lambda_handler(event, context)

        # Verify
        self.assertEqual(result['statusCode'], 200)
        self.assertEqual(result['headers'], {"Content-Type": "application/json"})
        self.assertEqual(result['body'], '{"greeting": "Hello John!"}')
        self.assertEqual(result['isBase64Encoded'], False)

    def test_lambda_handler_with_none_pathParameters(self):
        """Test lambda_handler when pathParameters is None."""
        # Setup
        event = {
            'pathParameters': None
        }
        context = {}

        # Execute
        result = lambda_handler(event, context)

        # Verify
        self.assertEqual(result['statusCode'], 200)
        self.assertEqual(result['headers'], {"Content-Type": "application/json"})
        self.assertEqual(result['body'], '{"greeting": "Hello World!"}')
        self.assertEqual(result['isBase64Encoded'], False)

    def test_lambda_handler_without_name_in_pathParameters(self):
        """Test lambda_handler when pathParameters doesn't contain 'name'."""
        # Setup
        event = {
            'pathParameters': {
                'other': 'value'
            }
        }
        context = {}

        # Execute
        result = lambda_handler(event, context)

        # Verify
        self.assertEqual(result['statusCode'], 200)
        self.assertEqual(result['headers'], {"Content-Type": "application/json"})
        self.assertEqual(result['body'], '{"greeting": "Hello World!"}')
        self.assertEqual(result['isBase64Encoded'], False)

    def test_lambda_handler_without_pathParameters(self):
        """Test lambda_handler when pathParameters is not in the event."""
        # Setup
        event = {}
        context = {}

        # Execute
        result = lambda_handler(event, context)

        # Verify
        self.assertEqual(result['statusCode'], 200)
        self.assertEqual(result['headers'], {"Content-Type": "application/json"})
        self.assertEqual(result['body'], '{"greeting": "Hello World!"}')
        self.assertEqual(result['isBase64Encoded'], False)


    @patch('builtins.print')
    def test_lambda_handler_with_mocked_print(self, mock_print):
        """Test lambda_handler with mocked print function to suppress output."""
        # Setup
        event = {
            'pathParameters': {
                'name': 'John'
            }
        }
        context = {}

        # Execute
        result = lambda_handler(event, context)

        # Verify
        self.assertEqual(result['statusCode'], 200)
        self.assertEqual(result['headers'], {"Content-Type": "application/json"})
        self.assertEqual(result['body'], '{"greeting": "Hello John!"}')
        self.assertEqual(result['isBase64Encoded'], False)

        # Verify print was called with the expected arguments
        mock_print.assert_any_call(event)
        mock_print.assert_any_call({'name': 'John'})


if __name__ == '__main__':
    unittest.main()
