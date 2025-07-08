#!/usr/bin/env python3
# Copyright (c) 2025
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from os import environ
from shutil import copytree, rmtree
from aws_cdk import App, Environment
from security_stacks_cdk.main_stack import SecurityMainStack
from security_stacks_cdk.regional_api_gateway_stack import SecurityApiGatewayRegionalStack
from security_stacks_cdk.kms_replica_stack import KmsReplicaStack

# Define regions for CloudFront PRICE_CLASS_100 (North America and Europe)
regions = {
    "us-east-1": 'Virginia',
    "us-east-2": 'Ohio',
    "us-west-1": 'NorthCalifornia',
    "us-west-2": 'Oregon',
    "eu-west-1": 'Ireland',
    "eu-central-1": 'Frankfurt'
}

deploy_account = environ.get('SECURITY_ACCOUNT')
production_account = environ.get('PRODUCTION_ACCOUNT')

# Copy a security library to Lambda directories
copytree(
    '../../src/security_library/ogc_landing/security/',
    '../../src/registration_lambda/ogc_landing/security/'
)
copytree(
    '../../src/security_library/ogc_landing/security/',
    '../../src/user_management_lambda/ogc_landing/security/'
)

try:
    app = App()

    # Define the primary region for the API Gateway stack
    primary_region = "us-east-2"

    # Define the environment for deployment of the main stack
    env_primary = Environment(account=deploy_account, region=primary_region)

    # Create the main stack with DynamoDB tables and KMS key
    main_stack = SecurityMainStack(
        app, "SecurityMainStack", cross_region_references=True, regions=regions, env=env_primary
    )

    # Create regional API Gateway stacks in each region
    for region, region_name in regions.items():
        kms_key_stack = main_stack
        if region != primary_region:  # Skip the primary region
            # Define the environment for the replica key
            env_region = Environment(account=deploy_account, region=region)

            # Create a replica key stack in this region
            replica_stack = KmsReplicaStack(
                app, f"KmsReplicaStack-{region}",
                primary_key_arn=main_stack.kms_key.key_arn,
                primary_encryption_key_arn=main_stack.encryption_key.key_arn,
                cross_region_references=True,
                env=env_region
            )

            # Add dependency to ensure the main stack (with the primary key) is created first
            replica_stack.add_dependency(main_stack)
            kms_key_stack = replica_stack

        # Create the regional API Gateway stack
        regional_stack = SecurityApiGatewayRegionalStack(
            app, f"SecurityApiGateway{region_name}Stack",
            user_table=main_stack.user_table,
            api_security_table=main_stack.api_security_table,
            registration_id_table=main_stack.registration_id_table,
            kms_key=main_stack.kms_key if region == primary_region else kms_key_stack.kms_key,
            encryption_key=main_stack.encryption_key if region == primary_region else kms_key_stack.encryption_key,
            region_name=region_name,
            cross_region_references=True,
            env=Environment(account=deploy_account, region=region)
        )

        # Add dependency to ensure certificate stack and main stack are created first
        regional_stack.add_dependency(kms_key_stack)

    app.synth()

finally:
    rmtree('../../src/registration_lambda/ogc_landing/security')
    rmtree('../../src/user_management_lambda/ogc_landing/security')
