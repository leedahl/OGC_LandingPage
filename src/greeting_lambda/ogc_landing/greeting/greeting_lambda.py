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
import re
import requests
from urllib.parse import unquote


def validate_geojson_point(geojson):
    """
    Validates if the input is a valid GeoJSON Point Geometry.

    :param geojson: The GeoJSON object to validate
    :return: (bool, str) - (is_valid, error_message)
    """
    if not isinstance(geojson, dict):
        return False, 'Input must be a GeoJSON object'

    if not (
            (geojson.get('type', '') == 'Feature' and geojson.get('geometry', dict()).get('type') == 'Point') or
            (geojson.get('type', '') == 'Point')
    ):
        return False, "GeoJSON type must be 'Point' Geometry or a Point Feature"

    if geojson.get('type', '') == 'Feature' and geojson.get('geometry', None) is None:
        return False, "GeoJSON type must be 'Point' Geometry or a 'Point' Feature, not a Null Geometry"

    coordinates = (
        geojson.get('geometry', dict()).get('coordinates', list()) if geojson.get('type', '') == 'Feature'
        else geojson.get('coordinates', list())
    )

    if not coordinates or not isinstance(coordinates, list) or len(coordinates) != 2:
        return False, 'GeoJSON Point must have exactly 2 coordinates [longitude, latitude]'

    longitude, latitude = coordinates

    if not isinstance(longitude, (int, float)) or not isinstance(latitude, (int, float)):
        return False, 'Coordinates must be numbers'

    if longitude < -180 or longitude > 180:
        return False, 'Longitude must be between -180 and 180'

    if latitude < -90 or latitude > 90:
        return False, 'Latitude must be between -90 and 90'

    return True, ''


def get_location_info(longitude, latitude):
    """
    Queries OpenStreetMap's Nominatim API to get location information.

    :param longitude: The longitude coordinates.
    :param latitude: The latitude coordinates.
    :return: Location information or None if not found.
    """
    url = f"https://nominatim.openstreetmap.org/reverse?format=json&lat={latitude}&lon={longitude}&zoom=12"
    headers = {
        "User-Agent": "GreetingLambda/1.0"  # Required by Nominatim's usage policy
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()

    except requests.RequestException as e:
        print(f"Error querying OpenStreetMap: {e}")
        return None


def create_greeting_from_location(location_info):
    """
    Creates a greeting based on the location information.

    :param location_info: Location information from OpenStreetMap
    :return: A greeting string
    """
    if not location_info or 'error' in location_info:
        return "Hello to whoever is out there in the unknown!"

    # Try to get the administrative area (state, province, district)
    admin_area = location_info.get('display_name', '')

    if len(admin_area) > 0:
        return f"Hello to the kind people of {admin_area}!"

    else:
        return f"Hello to whoever is out there in the unknown!"


def get_encoding_from_headers(headers):
    """
    Determines the encoding from request headers.

    :param headers: The request headers
    :return: The encoding to use (utf-8 or utf-16)
    """
    content_type = headers.get('Content-Type', '').lower()
    accept = headers.get('Accept', '').lower()

    # Default to UTF-8 if not specified
    encoding = 'utf-8'

    # Check for encoding in headers
    if 'utf-16' in content_type or 'utf-16' in accept:
        encoding = 'utf-16'

    return encoding


def validate_name(name, headers):
    """
    Validates if the name is a valid Unicode 8 or Unicode 16 value and a proper name.

    :param name: The name to validate
    :param headers: The request headers
    :return: (bool, str) - (is_valid, error_message)
    """
    # Check if the name is empty
    if not name or name.strip() == '':
        return False, "Name cannot be empty"

    # Determine encoding from headers
    encoding = get_encoding_from_headers(headers)

    # Validate Unicode encoding
    try:
        # Try to encode and decode the name with the specified encoding
        encoded = name.encode(encoding)
        decoded = encoded.decode(encoding)

        # Check if the decoded string matches the original
        if decoded != name:
            return False, f"Invalid {encoding.upper()} encoding"

    except UnicodeError:
        return False, f"Invalid {encoding.upper()} encoding"

    # Check if the name contains only letters and spaces
    # \p{L} matches any kind of letter from any language
    if not re.match(r'^[\w ]+$', name, re.UNICODE):
        return False, "Name must contain only letters and spaces"

    # Check if name is a proper name (starts with uppercase)
    if not name[0].isupper():
        return False, "Name must start with an uppercase letter"

    return True, ""


# noinspection PyUnusedLocal
def lambda_handler(event, context):
    # Check if this is a POST request with GeoJSON data
    if event.get('httpMethod') == 'POST' and event.get('body'):
        try:
            # Parse the request body as JSON
            body = json.loads(event.get('body', '{}'))

            # Validate the GeoJSON Point
            is_valid, error_message = validate_geojson_point(body)
            if not is_valid:
                return {
                    'statusCode': 400,
                    'headers': {'Content-Type': 'application/problem+json'},
                    'body': json.dumps({
                        'type': 'https://example.com/probs/bad-geojson',
                        'title': 'Invalid GeoJSON',
                        'status': 400,
                        'detail': error_message
                    }),
                    'isBase64Encoded': False
                }

            # Extract coordinates
            longitude, latitude = body['coordinates'] if body['type'] == 'Point' else body['geometry']['coordinates']

            # Get location information from OpenStreetMap
            location_info = get_location_info(longitude, latitude)

            # Create greeting based on location
            greeting = create_greeting_from_location(location_info)

            # Get headers from the event
            headers = event.get('headers', {}) or {}

            # Determine encoding from headers
            encoding = get_encoding_from_headers(headers)

            return {
                'statusCode': 200,
                'headers': {'Content-Type': f'application/json; charset={encoding}'},
                'body': json.dumps({'greeting': greeting}, ensure_ascii=False).encode(encoding).decode(encoding),
                'isBase64Encoded': False
            }

        except json.JSONDecodeError:
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/problem+json'},
                'body': json.dumps({
                    'type': 'https://example.com/probs/invalid-json',
                    'title': 'Invalid JSON Format',
                    'status': 400,
                    'detail': 'Invalid JSON in request body'
                }),
                'isBase64Encoded': False
            }

        except Exception as e:
            print(f"Error processing request: {e}")
            return {
                'statusCode': 500,
                'headers': {'Content-Type': 'application/problem+json'},
                'body': json.dumps({
                    'type': 'https://example.com/probs/server-error',
                    'title': 'Internal Server Error',
                    'status': 500,
                    'detail': 'An unexpected error occurred while processing the request'
                }),
                'isBase64Encoded': False
            }

    # Handle GET request (original behavior)
    name = event['pathParameters']['name'] if ('pathParameters' in event) and (
                event['pathParameters'] is not None) and ('name' in event['pathParameters']) else 'World'

    # Get headers from the event
    headers = event.get('headers', {}) or {}

    # Skip validation for default 'World' name
    if name != 'World':
        # Validate the name
        name = unquote(name)
        is_valid, error_message = validate_name(name, headers)
        if not is_valid:
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/problem+json'},
                'body': json.dumps({
                    'type': 'https://example.com/probs/invalid-name',
                    'title': 'Invalid Name',
                    'status': 400,
                    'detail': error_message
                }),
                'isBase64Encoded': False
            }

    # Determine encoding from headers
    encoding = get_encoding_from_headers(headers)

    return {
        'statusCode': 200,
        'headers': {'Content-Type': f'application/json; charset={encoding}'},
        'body': json.dumps({'greeting': f'Hello {name}!'}, ensure_ascii=False).encode(encoding).decode(encoding),
        'isBase64Encoded': False
    }
