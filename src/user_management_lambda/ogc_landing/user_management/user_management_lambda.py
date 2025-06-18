# Copyright (c) 2025
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
from ogc_landing.security import user_exists, update_user_password




# noinspection PyUnusedLocal
def lambda_handler(event, context):
    """
    Lambda handler for user management operations.
    Currently, it supports changing user passwords.

    Args:
        event: The event dict from API Gateway
        context: The Lambda context

    Returns:
        dict: The response to be sent back to API Gateway
    """
    # Check if this is a GET request (show form) or POST request (process form)
    http_method = event.get('httpMethod', 'GET')

    if http_method == 'POST':
        # Process form submission for password change
        event_body = event.get('body', '')
        event_body = event_body if event_body is not None else ''

        if event_body != '':
            # Parse form data more robustly
            form_data = {}
            for item in event_body.split('&'):
                if '=' in item:
                    key, value = item.split('=', 1)
                    form_data[key] = value

            username = form_data.get('username', '')
            new_password = form_data.get('password', '')

            # Check if user exists
            if not user_exists(username):
                body = (
                    '<!DOCTYPE HTML>'
                    '<html lang="en">'
                    '<head>'
                    "<title>User Management</title>"
                    '</head>'
                    '<body>'
                    "<h1>Password Change Failed</h1>"
                    '<p>User does not exist. Please check your username.</p>'
                    '<p><a href="/user-management">Try Again</a></p>'
                    '</body>'
                    '</html>'
                )

                return {
                    'statusCode': 404,  # Not Found
                    'headers': {'Content-Type': 'text/html; charset=utf-8'},
                    'body': body,
                    'isBase64Encoded': False
                }

            # Update the user's password
            update_user_password(username, new_password)

            body = (
                '<!DOCTYPE HTML>'
                '<html lang="en">'
                '<head>'
                "<title>User Management</title>"
                '</head>'
                '<body>'
                "<h1>Password Changed Successfully</h1>"
                '<p>Your password has been updated.</p>'
                '<p><a href="/">Back to the HomePage</href></p>'
                '</body>'
                '</html>'
            )

            return {
                'statusCode': 200,
                'headers': {'Content-Type': 'text/html; charset=utf-8'},
                'body': body,
                'isBase64Encoded': False
            }

    # Default: show the password change form
    body = (
        '<!DOCTYPE HTML>'
        '<html lang="en">'
        '<head>'
        "<title>User Management</title>"
        '<script type="text/javascript">'
        'function validateForm() {'
        '  var password = document.getElementById("password").value;'
        '  var confirmPassword = document.getElementById("confirm_password").value;'
        '  if (password != confirmPassword) {'
        '    alert("Passwords do not match!");'
        '    return false;'
        '  }'
        '  return true;'
        '}'
        '</script>'
        '</head>'
        '<body>'
        "<h1>Change Password</h1>"
        '<p>Enter your username and new password:</p>'
        '<form action="/user-management" method="POST" onsubmit="return validateForm();">'
        '<p>Username: <input type="text" name="username" required /></p>'
        '<p>New Password: <input type="password" name="password" id="password" required /></p>'
        '<p>Confirm Password: <input type="password" name="confirm_password" id="confirm_password" required /></p>'
        '<p><input type="submit" value="Change Password" /></p>'
        '</form>'
        '</body>'
        '</html>'
    )

    return {
        'statusCode': 200,
        'headers': {'Content-Type': 'text/html; charset=utf-8'},
        'body': body,
        'isBase64Encoded': False
    }
