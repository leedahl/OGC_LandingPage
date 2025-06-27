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
    RemovalPolicy
)
from aws_cdk.aws_dynamodb import StreamViewType
from constructs import Construct


class CAMainStack(Stack):
    def __init__(
            self, scope: Construct, construct_id: str, regions: Dict[str, str], **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Create DynamoDB tables for certificate storage as global tables
        # Filter out the current region from replication regions to avoid duplicates
        replication_regions = [region for region in regions.keys() if region != self.region]

        self.certificate_store_table = dynamodb.Table(
            self, 'CertificateStore',
            table_name='certificate_store',
            partition_key=dynamodb.Attribute(
                name='certificate_id',
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.RETAIN,
            stream=StreamViewType.NEW_AND_OLD_IMAGES,
            replication_regions=replication_regions
        )

        self.certificate_metadata_table = dynamodb.Table(
            self, 'CertificateMetadata',
            table_name='certificate_metadata',
            partition_key=dynamodb.Attribute(
                name='username',
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name='certificate_id',
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.RETAIN,
            stream=StreamViewType.NEW_AND_OLD_IMAGES,
            replication_regions=replication_regions
        )

        self.kms_key = kms.Key(
            self, f'CAKey',
            alias='alias/ca_key',
            enable_key_rotation=True,
            multi_region=True,
            removal_policy=RemovalPolicy.DESTROY,
        )
