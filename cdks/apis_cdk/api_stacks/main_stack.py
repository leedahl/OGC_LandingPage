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
    RemovalPolicy,
)
from constructs import Construct


class ApiMainStack(Stack):
    def __init__(
            self, scope: Construct, construct_id: str, regions: Dict[str, str], **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Filter out the current region from replication regions to avoid duplicates
        replication_regions = [region for region in regions.keys() if region != self.region]

        # Create DynamoDB table for API catalog as a global table
        self.api_catalog = dynamodb.Table(
            self, 'ApiCatalog',
            table_name='api_catalog',
            partition_key=dynamodb.Attribute(
                name='api_id',
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name='catalog_order',
                type=dynamodb.AttributeType.NUMBER
            ),
            removal_policy=RemovalPolicy.DESTROY,
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            stream=dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
            replication_regions=replication_regions
        )

        # Create DynamoDB table for API conformance as a global table
        self.api_conformance = dynamodb.Table(
            self, 'ApiConformance',
            table_name='api_conformance',
            partition_key=dynamodb.Attribute(
                name='api_id',
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name='alias',
                type=dynamodb.AttributeType.STRING
            ),
            removal_policy=RemovalPolicy.DESTROY,
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            stream=dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
            replication_regions=replication_regions
        )

        # Create DynamoDB tables for OpenAPI 3.0 schema as global tables

        # 1. openapi_documents table
        self.openapi_documents = dynamodb.Table(
            self, 'OpenApiDocuments',
            table_name='openapi_documents',
            partition_key=dynamodb.Attribute(
                name='api_id',
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name='version',
                type=dynamodb.AttributeType.STRING
            ),
            removal_policy=RemovalPolicy.DESTROY,
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            stream=dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
            replication_regions=replication_regions
        )

        # 2. openapi_servers table
        self.openapi_servers = dynamodb.Table(
            self, 'OpenApiServers',
            table_name='openapi_servers',
            partition_key=dynamodb.Attribute(
                name='api_id',
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name='server_id',
                type=dynamodb.AttributeType.STRING
            ),
            removal_policy=RemovalPolicy.DESTROY,
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            stream=dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
            replication_regions=replication_regions
        )

        # 3. openapi_paths table
        self.openapi_paths = dynamodb.Table(
            self, 'OpenApiPaths',
            table_name='openapi_paths',
            partition_key=dynamodb.Attribute(
                name='api_id',
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name='path',
                type=dynamodb.AttributeType.STRING
            ),
            removal_policy=RemovalPolicy.DESTROY,
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            stream=dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
            replication_regions=replication_regions
        )

        # 4. openapi_operations table
        self.openapi_operations = dynamodb.Table(
            self, 'OpenApiOperations',
            table_name='openapi_operations',
            partition_key=dynamodb.Attribute(
                name='api_id#path',
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name='method',
                type=dynamodb.AttributeType.STRING
            ),
            removal_policy=RemovalPolicy.DESTROY,
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            stream=dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
            replication_regions=replication_regions
        )

        # 5. openapi_components table
        self.openapi_components = dynamodb.Table(
            self, 'OpenApiComponents',
            table_name='openapi_components',
            partition_key=dynamodb.Attribute(
                name='api_id',
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name='component_type#component_name',
                type=dynamodb.AttributeType.STRING
            ),
            removal_policy=RemovalPolicy.DESTROY,
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            stream=dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
            replication_regions=replication_regions
        )

        # 6. openapi_tags table
        self.openapi_tags = dynamodb.Table(
            self, 'OpenApiTags',
            table_name='openapi_tags',
            partition_key=dynamodb.Attribute(
                name='api_id',
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name='tag_name',
                type=dynamodb.AttributeType.STRING
            ),
            removal_policy=RemovalPolicy.DESTROY,
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            stream=dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
            replication_regions=replication_regions
        )

        # 7. openapi_security_schemes table
        self.openapi_security_schemes = dynamodb.Table(
            self, 'OpenApiSecuritySchemes',
            table_name='openapi_security_schemes',
            partition_key=dynamodb.Attribute(
                name='api_id',
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name='scheme_name',
                type=dynamodb.AttributeType.STRING
            ),
            removal_policy=RemovalPolicy.DESTROY,
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            stream=dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
            replication_regions=replication_regions
        )