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
from aws_cdk import App, Environment
from my_api_landing_cdk.main_stack import ApiMainStack
from my_api_landing_cdk.regional_api_gateway_stack import ApiGatewayRegionalStack

# Define regions for CloudFront PRICE_CLASS_100 (North America and Europe)
regions = {
    "us-east-1": 'Virginia',
    "us-east-2": 'Ohio',
    "us-west-1": 'NorthCalifornia',
    "us-west-2": 'Oregon',
    "eu-west-1": 'Ireland',
    "eu-central-1": 'Frankfurt'
}

app = App()

deploy_account = environ.get('PRODUCTION_ACCOUNT')
security_account = environ.get('SECURITY_ACCOUNT')

# Define the environment for us-east-1 region
env_us_east_1 = Environment(account=deploy_account, region="us-east-1")

# Define the primary region for the API Gateway stack
primary_region = "us-east-2"

# Define the environment for deployment of the main stack
env_primary = Environment(account=deploy_account, region=primary_region)

# Create the main stack with DynamoDB tables
main_stack = ApiMainStack(
    app, "ApiMainStack", cross_region_references=True, regions=regions, env=env_primary
)

# Create regional API Gateway stacks in each region
for region, region_name in regions.items():
    # Define the environment for the regional stack
    env_region = Environment(account=deploy_account, region=region)

    # Create the regional API Gateway stack
    regional_stack = ApiGatewayRegionalStack(
        app, f"ApiGateway{region_name}Stack",
        api_catalog=main_stack.api_catalog,
        api_conformance=main_stack.api_conformance,
        openapi_documents=main_stack.openapi_documents,
        openapi_servers=main_stack.openapi_servers,
        openapi_paths=main_stack.openapi_paths,
        openapi_operations=main_stack.openapi_operations,
        openapi_components=main_stack.openapi_components,
        openapi_tags=main_stack.openapi_tags,
        openapi_security_schemes=main_stack.openapi_security_schemes,
        security_account=security_account,
        region_name=region_name,
        cross_region_references=True,
        env=env_region
    )

    # Add dependency to ensure the main stack is created first
    regional_stack.add_dependency(main_stack)

app.synth()
