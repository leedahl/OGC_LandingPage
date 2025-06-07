import boto3


# noinspection PyUnusedLocal
def lambda_handler(event, context):

    event_body = event.get('body', '')
    event_body = event_body if event_body is not None else ''
    if event_body != '':
        values = event_body.split('&')
        username = values[0].split('=')[1]
        password = values[1].split('=')[1]

        kms_client = boto3.client('kms')
        response = kms_client.encrypt(
            Plaintext=password.encode('utf_8'),
            KeyId='alias/hello_world'
        )

        db_password = response['CiphertextBlob']

        dynamodb_client = boto3.resource('dynamodb')
        table = dynamodb_client.Table('user_store')
        table.put_item(Item={'username': username, 'password': db_password})

        body = (
            '<!DOCTYPE HTML>'
            '<html>'
            '<head>'
            "<title>Michael's Wonderful API Registration</title>"
            '</head>'
            '<body>'
            "<h1>Thank you for registering for Michael's Wonderful APIs!</h1>"
            '<p>You may now use the the APIs as described in the API documentation on the homepage.<br>'
            '<a href="/">Back to the HomePage</href></p>'
            '</body>'
            '</html>'
        )

    else:

        body = (
            '<!DOCTYPE HTML>'
            '<html>'
            '<head>'
            "<title>Michael's Wonderful API Registration</title>"
            '</head>'
            '<body>'
            "<h1>Welcome to Michael's Wonderful API Registration</h1>"
            '<p>You can register to use the Greeting API by creating a username and password:</p>'
            '<form action="/register" method="POST">'
            '<p>Username: <input type="text" name="username" /></p>'
            '<p>Password: <input type="password" name="password" /></p>'
            '<p><input type="submit" value="Register" /></p>'
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
