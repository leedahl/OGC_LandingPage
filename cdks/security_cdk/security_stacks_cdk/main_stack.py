# Copyright (c) 2025
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from typing import Dict

from aws_cdk import (
    Stack,
    aws_dynamodb as dynamodb,
    aws_kms as kms,
    RemovalPolicy,
)
from constructs import Construct


class SecurityMainStack(Stack):
    def __init__(
            self, scope: Construct, construct_id: str, regions: Dict[str, str], **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Filter out the current region from replication regions to avoid duplicates
        replication_regions = [region for region in regions.keys() if region != self.region]

        # Create KMS key for password encryption
        self.kms_key = kms.Key(
            self, 'SecurityUserStoreAPIKey',
            alias='alias/security_user_store_key',
            enable_key_rotation=True,
            multi_region=True,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # Create DynamoDB table for user store as a global table
        self.user_table = dynamodb.Table(
            self, 'UserStore',
            table_name='user_store',
            partition_key=dynamodb.Attribute(
                name='username',
                type=dynamodb.AttributeType.STRING
            ),
            removal_policy=RemovalPolicy.DESTROY,
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            stream=dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
            replication_regions=replication_regions
        )

        # Create DynamoDB table for API security (mapping username to api_id) as a global table
        self.api_security_table = dynamodb.Table(
            self, 'ApiSecurity',
            table_name='api_security',
            partition_key=dynamodb.Attribute(
                name='username',
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name='api_id',
                type=dynamodb.AttributeType.STRING
            ),
            removal_policy=RemovalPolicy.DESTROY,
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            stream=dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
            replication_regions=replication_regions
        )