import boto3
import datetime
import pickle
import os
import re
import json
from typing import Dict, Any, List, Optional


def get_ohio_s3_client():
    """
    Returns an S3 client configured for the Ohio region (us-east-2).

    Returns:
        An S3 client for the Ohio region.
    """
    return boto3.client('s3', region_name='us-east-2')


def create_problem_response(status: int, detail: str, type_uri: str = "about:blank", 
                           title: Optional[str] = None) -> Dict[str, Any]:
    """
    Creates a standardized application/problem+json response according to RFC 7807.

    Args:
        status: The HTTP status code
        detail: A human-readable explanation specific to this occurrence of the problem
        type_uri: A URI reference that identifies the problem type (default: "about:blank")
        title: A short, human-readable summary of the problem type (default: based on status code)

    Returns:
        A response dict formatted according to the application/problem+json standard
    """
    # Default titles based on common HTTP status codes
    default_titles = {
        400: "Bad Request",
        404: "Not Found",
        500: "Internal Server Error"
    }

    # Use provided title or default based on status code
    if title is None:
        title = default_titles.get(status, "Error")

    # Create the problem details object
    problem = {
        "type": type_uri,
        "title": title,
        "status": status,
        "detail": detail
    }

    # Return the API Gateway response format with headers
    return {
        'statusCode': status,
        'headers': {'Content-Type': 'application/problem+json'},
        'body': json.dumps(problem),
        'isBase64Encoded': False
    }


def get_tables() -> List[str]:
    """
    Returns the list of tables to back up.

    Returns:
        A list of table names.
    """
    return [
        'api_catalog',
        'api_conformance',
        'openapi_documents',
        'openapi_servers',
        'openapi_paths',
        'openapi_operations',
        'openapi_components',
        'openapi_tags',
        'openapi_security_schemes'
    ]


def create_backup() -> Dict[str, Any]:
    """
    Creates a backup of all DynamoDB tables to S3.

    Returns:
        A response dict containing status and information about the backup.
    """
    try:
        # Get the current timestamp in the required format
        timestamp = datetime.datetime.now().strftime('%Y%m%dT%H%M%S')

        # List of tables to back up
        tables = get_tables()

        # Initialize DynamoDB and S3 clients
        dynamodb = boto3.resource('dynamodb')
        s3 = get_ohio_s3_client()

        # Get the S3 bucket name from environment variable
        bucket_name = os.environ.get('BACKUP_BUCKET_NAME')

        # Create a prefix for this backup
        prefix = f"backup/{timestamp}/"

        # Track successful backups
        successful_backups = []

        # Backup each table
        for table_name in tables:
            try:
                # Get the table
                table = dynamodb.Table(table_name)

                # Scan the table to get all items
                response = table.scan()
                items = response['Items']

                # Continue scanning if we haven't got all items
                while 'LastEvaluatedKey' in response:
                    response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
                    items.extend(response['Items'])

                # Serialize the items using pickle
                serialized_data = pickle.dumps(items)

                # Upload to S3
                s3_key = f"{prefix}{table_name}.pickle"
                s3.put_object(
                    Bucket=bucket_name,
                    Key=s3_key,
                    Body=serialized_data
                )

                successful_backups.append(table_name)

            except Exception as e:
                print(f"Error backing up table {table_name}: {str(e)}")

        # Return success response
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'message': f'Backup completed successfully for {len(successful_backups)} tables',
                'backupId': timestamp,
                'tables': successful_backups
            }),
            'isBase64Encoded': False
        }

    except Exception as e:
        # Return error response using application/problem+json format
        return create_problem_response(
            status=500,
            detail=f'Error during backup: {str(e)}',
            title="Backup Operation Failed"
        )


def list_backups() -> Dict[str, Any]:
    """
    Lists all backups in the S3 bucket.

    Returns:
        A response dict containing status and information about the backups.
    """
    try:
        # Initialize S3 client for Ohio region
        s3 = get_ohio_s3_client()

        # Get the S3 bucket name from environment variable
        bucket_name = os.environ.get('BACKUP_BUCKET_NAME')

        # List objects with the backup/ prefix
        response = s3.list_objects_v2(
            Bucket=bucket_name,
            Prefix='backup/',
            Delimiter='/'
        )

        # Extract unique prefixes (these are the backup timestamps)
        prefixes = []
        if 'CommonPrefixes' in response:
            # noinspection SpellCheckingInspection
            for prefix in response['CommonPrefixes']:
                # Extract the timestamp from the prefix (format: backup/YYYYMMDDTHHMMSS/)
                prefix_path = prefix.get('Prefix', '')
                match = re.match(r'backup/(\d{8}T\d{6})/', prefix_path)
                if match:
                    timestamp = match.group(1)
                    prefixes.append({
                        'id': timestamp,
                        'prefix': prefix_path,
                        'timestamp': timestamp
                    })

        # Sort prefixes by timestamp (newest first)
        prefixes.sort(key=lambda x: x['timestamp'], reverse=True)

        # Return success response
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'message': f'Found {len(prefixes)} backups',
                'backups': prefixes
            }),
            'isBase64Encoded': False
        }

    except Exception as e:
        # Return error response using application/problem+json format
        return create_problem_response(
            status=500,
            detail=f'Error listing backups: {str(e)}',
            title="List Operation Failed"
        )


def get_most_recent_backup() -> Optional[str]:
    """
    Gets the most recent backup prefix.

    Returns:
        The most recent backup prefix or None if no backups exist.
    """
    try:
        # Initialize S3 client for Ohio region
        s3 = get_ohio_s3_client()

        # Get the S3 bucket name from environment variable
        bucket_name = os.environ.get('BACKUP_BUCKET_NAME')

        # List objects with the backup/ prefix
        response = s3.list_objects_v2(
            Bucket=bucket_name,
            Prefix='backup/',
            Delimiter='/'
        )

        # Extract unique prefixes and find the most recent one
        if 'CommonPrefixes' in response:
            prefixes = [prefix.get('Prefix', '') for prefix in response['CommonPrefixes']]
            if prefixes:
                # Sort prefixes by timestamp (newest first)
                prefixes.sort(reverse=True)
                return prefixes[0]

        return None

    except Exception as e:
        print(f"Error getting most recent backup: {str(e)}")
        return None


def delete_backup(backup_id: str) -> Dict[str, Any]:
    """
    Deletes a specific backup from the S3 bucket.

    Args:
        backup_id: The backup ID (timestamp) to delete.

    Returns:
        A response dict containing status and information about the delete operation.
    """
    try:
        # Initialize S3 client for Ohio region
        s3 = get_ohio_s3_client()

        # Get the S3 bucket name from environment variable
        bucket_name = os.environ.get('BACKUP_BUCKET_NAME')

        # Determine the backup prefix to use
        prefix = f"backup/{backup_id}/"

        # List objects with the specified prefix
        response = s3.list_objects_v2(
            Bucket=bucket_name,
            Prefix=prefix
        )

        if 'Contents' not in response:
            return create_problem_response(
                status=404,
                detail=f'No backup found with ID {backup_id}',
                title="Delete Failed - Backup Not Found"
            )

        # Delete each object in the backup
        deleted_objects = []
        for obj in response['Contents']:
            key = obj['Key']
            s3.delete_object(
                Bucket=bucket_name,
                Key=key
            )
            deleted_objects.append(key)

        # Return success response
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'message': f'Backup {backup_id} deleted successfully',
                'backupId': backup_id,
                'deletedObjects': deleted_objects
            }),
            'isBase64Encoded': False
        }

    except Exception as e:
        # Return error response using application/problem+json format
        return create_problem_response(
            status=500,
            detail=f'Error during delete: {str(e)}',
            title="Delete Operation Failed"
        )


def restore_backup(backup_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Restores data from a backup.

    Args:
        backup_id: The backup ID (timestamp) to restore from. If None, restores from the most recent backup.

    Returns:
        A response dict containing status and information about the restore operation.
    """
    try:
        # Initialize DynamoDB and S3 clients
        dynamodb = boto3.resource('dynamodb')
        s3 = get_ohio_s3_client()

        # Get the S3 bucket name from environment variable
        bucket_name = os.environ.get('BACKUP_BUCKET_NAME')

        # Determine the backup prefix to use
        if backup_id:
            prefix = f"backup/{backup_id}/"

        else:
            prefix = get_most_recent_backup()
            if not prefix:
                return create_problem_response(
                    status=404,
                    detail='No backups found to restore from',
                    title="Restore Failed - No Backups"
                )
            backup_id = prefix.split('/')[1]  # Extract timestamp from prefix

        # List objects with the specified prefix
        response = s3.list_objects_v2(
            Bucket=bucket_name,
            Prefix=prefix
        )

        if 'Contents' not in response:
            return create_problem_response(
                status=404,
                detail=f'No backup found with ID {backup_id}',
                title="Restore Failed - Backup Not Found"
            )

        # Track successful restores
        successful_restores = []

        # Restore each table
        for obj in response['Contents']:
            table_name = ''
            try:
                # Get the object key
                key = obj['Key']

                # Extract table name from the key
                table_name = key.split('/')[-1].replace('.pickle', '')

                # Get the object from S3
                obj_response = s3.get_object(
                    Bucket=bucket_name,
                    Key=key
                )

                # Deserialize the data
                items = pickle.loads(obj_response['Body'].read())

                # Get the table
                table = dynamodb.Table(table_name)

                # Get table description to determine key schema
                table_description = table.meta.client.describe_table(TableName=table_name)
                key_schema = table_description['Table']['KeySchema']

                # Extract primary key and sort key names
                partition_key = next((item['AttributeName'] for item in key_schema if item['KeyType'] == 'HASH'), None)
                sort_key = next((item['AttributeName'] for item in key_schema if item['KeyType'] == 'RANGE'), None)

                # Build projection expression for scanning keys
                projection_parts = []
                expression_attr_names = {}

                if partition_key:
                    projection_parts.append(f"#pk")
                    expression_attr_names["#pk"] = partition_key

                if sort_key:
                    projection_parts.append(f"#sk")
                    expression_attr_names["#sk"] = sort_key

                projection_expression = ", ".join(projection_parts)

                # Clear the table first
                scan = table.scan(
                    ProjectionExpression=projection_expression,
                    ExpressionAttributeNames=expression_attr_names
                )

                with table.batch_writer() as batch:
                    for item in scan['Items']:
                        key = {}
                        if partition_key:
                            key[partition_key] = item[partition_key]
                        if sort_key:
                            key[sort_key] = item[sort_key]
                        batch.delete_item(Key=key)

                # Write the items back to the table
                with table.batch_writer() as batch:
                    for item in items:
                        batch.put_item(Item=item)

                successful_restores.append(table_name)

            except Exception as e:
                print(f"Error restoring table {table_name}: {str(e)}")

        # Return success response
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'message': f'Restore completed successfully for {len(successful_restores)} tables',
                'backupId': backup_id,
                'tables': successful_restores
            }),
            'isBase64Encoded': False
        }

    except Exception as e:
        # Return error response using application/problem+json format
        return create_problem_response(
            status=500,
            detail=f'Error during restore: {str(e)}',
            title="Restore Operation Failed"
        )


# noinspection PyUnusedLocal
def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda function to handle data management operations (backup, restore, list).

    Args:
        event: The event dict that contains the parameters passed when the function is invoked.
        context: The context in which the function is called.

    Returns:
        A response dict containing status and information about the operation.
    """
    try:
        # Determine the operation based on the path
        path = event.get('path', '')

        if path.endswith('/data_management/backup'):
            # Backup operation
            return create_backup()

        elif path.endswith('/data_management/list'):
            # List operation
            return list_backups()

        elif path.endswith('/data_management/restore'):
            # Restore operation (the most recent backup)
            return restore_backup()

        elif '/data_management/restore/' in path:
            # Restore operation with specific backup ID
            backup_id = event.get('pathParameters', {}).get('backup_id')
            return restore_backup(backup_id)

        elif '/data_management/delete/' in path:
            # Delete operation with specific backup ID
            backup_id = event.get('pathParameters', {}).get('backup_id')
            return delete_backup(backup_id)

        else:
            # Unknown operation - return error in application/problem+json format
            return create_problem_response(
                status=400,
                detail=f'Unknown operation: {path}',
                title="Invalid Operation"
            )

    except Exception as e:
        # Return error response using application/problem+json format
        return create_problem_response(
            status=500,
            detail=f'Error processing request: {str(e)}',
            title="Request Processing Failed"
        )
