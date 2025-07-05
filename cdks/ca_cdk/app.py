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

import os
import aws_cdk as cdk
from ca_stacks.regional_api_gateway_stack import CARegionalApiGatewayStack
from ca_stacks.main_stack import CAMainStack

# Get account IDs from environment variables or use defaults
security_account = os.environ.get('SECURITY_ACCOUNT', '123456789012')

# Define regions for CloudFront PRICE_CLASS_100 (North America and Europe)
regions = {
    "us-east-1": 'Virginia',
    "us-east-2": 'Ohio',
    "us-west-1": 'NorthCalifornia',
    "us-west-2": 'Oregon',
    "eu-west-1": 'Ireland',
    "eu-central-1": 'Frankfurt'
}

# Create the app
app = cdk.App()

# No longer need a separate certificate stack as certificates are created in each region

# Create the DynamoDB stack in the us-east-2
primary_region = 'us-east-2'
main_stack = CAMainStack(
    app, f"CAMainStack",
    regions=regions,  # Pass the list of all regions for global table replication
    cross_region_references=True,
    env=cdk.Environment(account=security_account, region=primary_region)
)

# Create API Gateway stacks in each region
for region, region_name in regions.items():
    # Create the regional API Gateway stack
    regional_stack = CARegionalApiGatewayStack(
        app, f"CAApiGateway{region_name}Stack",
        certificate_store_table=main_stack.certificate_store_table,
        certificate_metadata_table=main_stack.certificate_metadata_table,
        primary_kms_key=main_stack.kms_key,
        region_name=region_name,
        primary_region=primary_region,
        cross_region_references=True,
        env=cdk.Environment(account=security_account, region=region)
    )

    # Add dependency to ensure DynamoDB stack is created first
    regional_stack.add_dependency(main_stack)

app.synth()
