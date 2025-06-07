import json
from urllib.parse import unquote


# noinspection PyUnusedLocal
def lambda_handler(event, context):
    print(event)
    name = event['pathParameters']['name'] if ('pathParameters' in event) and (
                event['pathParameters'] is not None) and ('name' in event['pathParameters']) else 'World'

    name = unquote(name)
    print({'name': name})

    return {
        'statusCode': 200,
        "headers": {"Content-Type": "application/json"},
        'body': json.dumps({'greeting': f'Hello {name}!'}),
        "isBase64Encoded": False
    }
