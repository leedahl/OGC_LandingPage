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
from aws_cdk import App, Environment
from os import environ
from greeting_stacks_cdk.regional_api_gateway_stack import GreetingApiGatewayRegionalStack

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

# Define the primary region for the API Gateway stack
primary_region = "us-east-2"

# Define the environment for deployment of the main stack
env_primary = Environment(account=deploy_account, region=primary_region)

# Create regional API Gateway stacks in each region
for region, region_name in regions.items():
    # Define the environment for the regional stack
    env_region = Environment(account=deploy_account, region=region)

    # Create the regional API Gateway stack
    regional_stack = GreetingApiGatewayRegionalStack(
        app, f"GreetingApiGateway{region_name}Stack",
        security_account=security_account,
        region_name=region_name,
        cross_region_references=True,
        env=env_region
    )

app.synth()
