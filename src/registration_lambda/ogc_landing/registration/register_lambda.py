# Copyright (c) 2025
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import unicodedata
from ogc_landing.security import user_exists, create_user


# noinspection PyUnusedLocal
def lambda_handler(event, context):
    # Extract host and protocol information
    headers = event.get('headers', {})
    host = headers.get('Host', '')
    # Extract protocol from CloudFront-Forwarded-Proto header, default to https if not present
    protocol = headers.get('CloudFront-Forwarded-Proto', 'https')

    current_year = 2025  # This should be dynamically generated in a real application

    event_body = event.get('body', '')
    event_body = event_body if event_body is not None else ''
    if event_body != '':
        values = event_body.split('&')
        username = values[0].split('=')[1]
        password = values[1].split('=')[1]

        # Validate username
        if not _validate_username(username):
            body = (
                '<!DOCTYPE HTML>'
                '<html lang="en">'
                '<head>'
                "<title>Registration</title>"
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
                "<h1>Registration</h1>"
                '</header>'
                '<nav>'
                f'<a href="{protocol}://{host}/">Home</a> &gt; <a href="{protocol}://{host}/register">Registration</a>'
                '</nav>'
                '<section class="content">'
                "<h1>Registration Failed</h1>"
                '<p>Invalid username. Username must contain only alphabetical and numerical characters, periods (.), underscores (_), and dashes (-).</p>'
                '<p><a href="/register">Try Again</a></p>'
                '</section>'
                '<footer>'
                f'&copy; {current_year} Michael Leedahl'
                '</footer>'
                '<script>showSection();</script>'
                '</body>'
                '</html>'
            )
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'text/html; charset=utf-8'},
                'body': body,
                'isBase64Encoded': False
            }

        # Check if user already exists
        if user_exists(username):
            body = (
                '<!DOCTYPE HTML>'
                '<html lang="en">'
                '<head>'
                "<title>Registration</title>"
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
                "<h1>Registration</h1>"
                '</header>'
                '<nav>'
                f'<a href="{protocol}://{host}/">Home</a> &gt; <a href="{protocol}://{host}/register">Registration</a>'
                '</nav>'
                '<section class="content">'
                "<h1>Registration Failed</h1>"
                '<p>A user with this username already exists. Please choose a different username.</p>'
                '<p><a href="/register">Try Again</a></p>'
                '</section>'
                '<footer>'
                f'&copy; {current_year} Michael Leedahl'
                '</footer>'
                '<script>showSection();</script>'
                '</body>'
                '</html>'
            )
            return {
                'statusCode': 409,  # Conflict
                'headers': {'Content-Type': 'text/html; charset=utf-8'},
                'body': body,
                'isBase64Encoded': False
            }

        # Create the user with the given username and password
        create_user(username, password)

        body = (
            '<!DOCTYPE HTML>'
            '<html lang="en">'
            '<head>'
            "<title>Registration</title>"
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
            "<h1>Registration</h1>"
            '</header>'
            '<nav>'
            f'<a href="{protocol}://{host}/">Home</a> &gt; <a href="{protocol}://{host}/register">Registration</a>'
            '</nav>'
            '<section class="content">'
            "<h1>Thank you for registering for Michael's Wonderful APIs!</h1>"
            '<p>You may now use the the APIs as described in the API documentation on the homepage.<br>'
            '<a href="/user-management">User Management</a></p>'
            '</section>'
            '<footer>'
            f'&copy; {current_year} Michael Leedahl'
            '</footer>'
            '<script>showSection();</script>'
            '</body>'
            '</html>'
        )

    else:

        body = (
            '<!DOCTYPE HTML>'
            '<html lang="en">'
            '<head>'
            "<title>Registration</title>"
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
            "<h1>Registration</h1>"
            '</header>'
            '<nav>'
            f'<a href="{protocol}://{host}/">Home</a> &gt; <a href="{protocol}://{host}/register">Registration</a>'
            '</nav>'
            '<section class="content">'
            "<h1>Welcome to Michael's Wonderful API Registration</h1>"
            '<p>You can register to use the Greeting API by creating a username and password:</p>'
            '<form action="/register" method="POST">'
            '<p>Username: <input type="text" name="username" /></p>'
            '<p>Password: <input type="password" name="password" /></p>'
            '<p><input type="submit" value="Register" /></p>'
            '</form>'
            '</section>'
            '<footer>'
            f'&copy; {current_year} Michael Leedahl'
            '</footer>'
            '<script>showSection();</script>'
            '</body>'
            '</html>'
        )

    return {
        'statusCode': 200,
        'headers': {'Content-Type': 'text/html; charset=utf-8'},
        'body': body,
        'isBase64Encoded': False
    }


def _validate_username(username):
    """
    Validates that the username only uses UTF-8 character set and limits characters
    to alphabetical and numerical with consideration for other languages besides English.

    Args:
        username (str): The username to validate

    Returns:
        bool: True if the username is valid, False otherwise
    """
    # Check if the username is empty
    if not username:
        return False

    try:
        # Ensure the username is valid UTF-8
        username.encode('utf-8').decode('utf-8')

        # Check if the username contains only letters, numbers, periods, underscores, and dashes
        for char in username:
            category = unicodedata.category(char)
            # L* categories are letters, N* categories are numbers
            # Also allow periods, underscores, and dashes
            if not (category.startswith('L') or category.startswith('N') or char in ['.', '_', '-']):
                return False

        return True

    except UnicodeError:
        # If there's an encoding/decoding error, the username is not valid UTF-8
        return False
