"""
Lambda function for PR database cleanup.

Runs inside VPC to access private RDS instance.
Invoked by GitHub Actions workflow when PR is closed.
"""

import json
import os
import boto3
import pg8000.native


def get_db_credentials():
    """Retrieve database credentials from Secrets Manager."""
    secret_name = os.environ.get('DB_SECRET_NAME')
    if not secret_name:
        raise ValueError("DB_SECRET_NAME environment variable not set")

    client = boto3.client('secretsmanager')
    response = client.get_secret_value(SecretId=secret_name)
    return json.loads(response['SecretString'])


def handler(event, context):
    """
    Drop a PR database from shared RDS.

    Expected event format:
    {
        "pr_number": 123,
        "action": "drop"  # optional, defaults to "drop"
    }

    Returns:
    {
        "statusCode": 200,
        "body": {"message": "...", "database": "pr_123", "action": "dropped|skipped|error"}
    }
    """
    print(f"Received event: {json.dumps(event)}")

    # Parse input
    pr_number = event.get('pr_number')
    if not pr_number:
        return {
            'statusCode': 400,
            'body': {'message': 'pr_number is required', 'action': 'error'}
        }

    db_name = f"pr_{pr_number}"
    action = event.get('action', 'drop')

    if action != 'drop':
        return {
            'statusCode': 400,
            'body': {'message': f'Unknown action: {action}', 'action': 'error'}
        }

    try:
        # Get credentials
        creds = get_db_credentials()

        # Connect to postgres database (not the PR database)
        conn = pg8000.native.Connection(
            host=creds['host'],
            port=int(creds['port']),
            user=creds['username'],
            password=creds['password'],
            database='postgres',
            ssl_context=True
        )

        try:
            # Check if database exists
            result = conn.run(
                "SELECT 1 FROM pg_database WHERE datname = :db_name",
                db_name=db_name
            )

            if not result:
                print(f"Database {db_name} does not exist, skipping")
                return {
                    'statusCode': 200,
                    'body': {
                        'message': f'Database {db_name} does not exist',
                        'database': db_name,
                        'action': 'skipped'
                    }
                }

            # Terminate existing connections to the database
            print(f"Terminating connections to {db_name}")
            conn.run(
                """
                SELECT pg_terminate_backend(pid)
                FROM pg_stat_activity
                WHERE datname = :db_name AND pid <> pg_backend_pid()
                """,
                db_name=db_name
            )

            # Drop the database
            # Note: Can't use parameters for database names in DROP DATABASE
            # Must sanitize manually - pr_number should only be digits
            if not str(pr_number).isdigit():
                raise ValueError(f"Invalid pr_number: {pr_number}")

            print(f"Dropping database {db_name}")
            conn.run(f"DROP DATABASE IF EXISTS {db_name}")

            print(f"Successfully dropped database {db_name}")
            return {
                'statusCode': 200,
                'body': {
                    'message': f'Successfully dropped database {db_name}',
                    'database': db_name,
                    'action': 'dropped'
                }
            }

        finally:
            conn.close()

    except Exception as e:
        print(f"Error: {str(e)}")
        return {
            'statusCode': 500,
            'body': {
                'message': f'Error: {str(e)}',
                'database': db_name,
                'action': 'error'
            }
        }
