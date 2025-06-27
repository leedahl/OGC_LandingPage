# Copyright (c) 2025
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
from ogc_landing.security import user_exists, update_user_password, delete_user
import base64
from datetime import datetime


# noinspection PyUnusedLocal
def lambda_handler(event, context):
    """
    Lambda handler for user management operations.
    Supports changing user passwords and deleting user accounts.

    Args:
        event: The event dict from API Gateway
        context: The Lambda context

    Returns:
        dict: The response to be sent back to API Gateway
    """
    # Check the HTTP method
    http_method = event.get('httpMethod', 'GET')
    headers = event.get('headers', {})
    host = headers.get('Host', '')
    # Extract protocol from CloudFront-Forwarded-Proto header, default to https if not present
    protocol = headers.get('CloudFront-Forwarded-Proto', 'https')

    # Extract username from the Authorization header (Basic Authentication)
    username = ""
    headers = event.get('headers', {})
    auth_header = headers.get('Authorization', '') or headers.get('authorization', '')

    if auth_header.startswith('Basic '):
        try:
            # Extract and decode the base64 part
            encoded_credentials = auth_header[6:]  # Remove 'Basic ' prefix
            decoded_credentials = base64.b64decode(encoded_credentials).decode('utf_8')
            # Split into username and password
            if ':' in decoded_credentials:
                username, _ = decoded_credentials.split(':', 1)

        except Exception as ex:
            # If there's any error in decoding, continue with other methods
            print(f'WARNING: {ex}')

    if http_method == 'DELETE':
        # Process account deletion
        event_body = event.get('body', '')
        event_body = event_body if event_body is not None else ''

        if event_body != '':
            # Parse form data
            form_data = {}
            for item in event_body.split('&'):
                if '=' in item:
                    key, value = item.split('=', 1)
                    form_data[key] = value

            # Use the username from the Authorization header if available, otherwise use form data
            if not username:
                username = form_data.get('username', '')

            # Check if user exists
            if not user_exists(username):
                current_year = datetime.now().year  # Dynamically get the current year
                body = (
                    '<!DOCTYPE HTML>'
                    '<html lang="en">'
                    '<head>'
                    "<title>User Management</title>"
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
                    "<h1>User Management</h1>"
                    '</header>'
                    '<nav>'
                    f'<a href="{protocol}://{host}/">Home</a> &gt; <a href="{protocol}://{host}/user-management">User Management</a>'
                    '</nav>'
                    '<section class="content">'
                    "<h1>Account Deletion Failed</h1>"
                    '<p>User does not exist. Please check your username.</p>'
                    '</section>'
                    '<footer>'
                    f'&copy; {current_year} Michael Leedahl'
                    '</footer>'
                    '<script>showSection();</script>'
                    '</body>'
                    '</html>'
                )

                return {
                    'statusCode': 404,  # Not Found
                    'headers': {'Content-Type': 'text/html; charset=utf-8'},
                    'body': body,
                    'isBase64Encoded': False
                }

            # Delete the user account
            delete_user(username)

            current_year = datetime.now().year  # Dynamically get the current year
            body = (
                '<!DOCTYPE HTML>'
                '<html lang="en">'
                '<head>'
                "<title>User Management</title>"
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
                "<h1>User Management</h1>"
                '</header>'
                '<nav>'
                f'<a href="{protocol}://{host}/">Home</a> &gt; <a href="{protocol}://{host}/user-management">User Management</a>'
                '</nav>'
                '<section class="content">'
                "<h1>Account Deleted Successfully</h1>"
                '<p>Your account has been deleted along with all associated data.</p>'
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

    elif http_method == 'POST':
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

            # Use the username from the Authorization header if available, otherwise use form data
            if not username:
                username = form_data.get('username', '')
            action = form_data.get('action', 'change_password')

            if action == 'change_password':
                new_password = form_data.get('password', '')

                # Check if user exists
                if not user_exists(username):
                    current_year = datetime.now().year  # Dynamically get the current year
                    body = (
                        '<!DOCTYPE HTML>'
                        '<html lang="en">'
                        '<head>'
                        "<title>User Management</title>"
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
                        "<h1>User Management</h1>"
                        '</header>'
                        '<nav>'
                        f'<a href="{protocol}://{host}/">Home</a> &gt; <a href="{protocol}://{host}/user-management">User Management</a>'
                        '</nav>'
                        '<section class="content">'
                        "<h1>Password Change Failed</h1>"
                        '<p>User does not exist. Please check your username.</p>'
                        '</section>'
                        '<footer>'
                        f'&copy; {current_year} Michael Leedahl'
                        '</footer>'
                        '<script>showSection();</script>'
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

                current_year = datetime.now().year  # Dynamically get the current year
                body = (
                    '<!DOCTYPE HTML>'
                    '<html lang="en">'
                    '<head>'
                    "<title>User Management</title>"
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
                    "<h1>User Management</h1>"
                    '</header>'
                    '<nav>'
                    f'<a href="{protocol}://{host}/">Home</a> &gt; <a href="{protocol}://{host}/user-management">User Management</a>'
                    '</nav>'
                    '<section class="content">'
                    "<h1>Password Changed Successfully</h1>"
                    '<p>Your password has been updated.</p>'
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

            elif action == 'delete_account':
                # Redirect to confirmation page
                current_year = datetime.now().year  # Dynamically get the current year
                body = (
                    '<!DOCTYPE HTML>'
                    '<html lang="en">'
                    '<head>'
                    "<title>User Management</title>"
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
                    "<h1>User Management</h1>"
                    '</header>'
                    '<nav>'
                    f'<a href="{protocol}://{host}/">Home</a> &gt; <a href="{protocol}://{host}/user-management">User Management</a>'
                    '</nav>'
                    '<section class="content">'
                    "<h1>Confirm Account Deletion</h1>"
                    '<p>Are you sure you want to delete your account? This will remove your account and all associated data.</p>'
                    f'<form action="/user-management" method="DELETE">'
                    f'<input type="hidden" name="username" value="{username}" />'
                    '<p><input type="submit" value="Yes, Delete My Account" /></p>'
                    '</form>'
                    '<p><a href="/user-management">Cancel</a> | <a href="/">Back to the HomePage</a></p>'
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

    # Default: show the user management form with radio buttons
    current_year = datetime.now().year  # Dynamically get the current year

    body = (
        '<!DOCTYPE HTML>'
        '<html lang="en">'
        '<head>'
        "<title>User Management</title>"
        '<style>'
        '  body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }'
        '  header, nav, section, footer { margin-bottom: 20px; }'
        '  header { background-color: #f5f5f5; padding: 10px; }'
        '  nav { background-color: #eee; padding: 10px; }'
        '  .content { padding: 20px; border: 1px solid #ddd; }'
        '  .hidden { display: none; }'
        '  footer { text-align: center; font-size: 0.8em; color: #666; }'
        '</style>'
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
        'function showSection() {'
        '  var action = document.querySelector("input[name=\'action\']:checked").value;'
        '  document.getElementById("password_section").style.display = (action === "change_password") ? "block" : "none";'
        '  document.getElementById("delete_section").style.display = (action === "delete_account") ? "block" : "none";'
        '}'
        'function confirmDelete() {'
        '  document.getElementById("delete_section").style.display = "none";'
        '  document.getElementById("confirm_delete_section").style.display = "block";'
        '}'
        'function cancelDelete() {'
        '  document.getElementById("confirm_delete_section").style.display = "none";'
        '  document.getElementById("delete_section").style.display = "block";'
        '}'
        'function submitDelete() {'
        '  var username = document.getElementById("delete_username").value;'
        '  var xhr = new XMLHttpRequest();'
        '  xhr.open("DELETE", "/user-management", true);'
        '  xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");'
        '  xhr.onreadystatechange = function() {'
        '    if (xhr.readyState === 4) {'
        '      if (xhr.status === 200) {'
        '        window.location.href = "/register";'
        '      } else {'
        '        alert("Error deleting account. Please try again.");'
        '      }'
        '    }'
        '  };'
        '  xhr.send("username=" + encodeURIComponent(username));'
        '}'
        '</script>'
        '</head>'
        '<body>'
        '<header>'
        "<h1>User Management</h1>"
        '</header>'
        '<nav>'
        f'<a href="{protocol}://{host}/">Home</a> &gt; User Management'
        '</nav>'
        '<section class="content">'
        '<p>Please select an action:</p>'
        '<form id="user_form" action="/user-management" method="POST" onsubmit="return validateForm();">'
        '<p>'
        '<input type="radio" name="action" value="change_password" id="change_password" checked onclick="showSection()" />'
        '<label for="change_password">Change Password</label>'
        '</p>'
        '<p>'
        '<input type="radio" name="action" value="delete_account" id="delete_account" onclick="showSection()" />'
        '<label for="delete_account">Delete Account</label>'
        '</p>'
        '<div id="password_section">'
        '<p>Enter your username and new password:</p>'
        f'<p>Username: <input type="text" name="username" value="{username}" readonly required /></p>'
        '<p>New Password: <input type="password" name="password" id="password" required /></p>'
        '<p>Confirm Password: <input type="password" name="confirm_password" id="confirm_password" required /></p>'
        '<p><input type="submit" value="Change Password" /></p>'
        '</div>'
        '<div id="delete_section" class="hidden">'
        '<p>Enter your username to delete your account:</p>'
        f'<p>Username: <input type="text" id="delete_username" name="username" value="{username}" readonly required /></p>'
        '<p><button type="button" onclick="confirmDelete()">Delete Account</button></p>'
        '</div>'
        '</form>'
        '<div id="confirm_delete_section" class="hidden">'
        '<p><strong>Warning:</strong> Deleting your account will remove your account and all associated data. This action cannot be undone.</p>'
        '<p>'
        '<button type="button" onclick="submitDelete()">Continue</button>'
        '<button type="button" onclick="cancelDelete()">Cancel</button>'
        '</p>'
        '</div>'
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
