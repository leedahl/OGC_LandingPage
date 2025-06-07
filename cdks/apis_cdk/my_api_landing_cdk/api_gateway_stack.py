# Copyright (c) 2025
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
from aws_cdk import (
    Stack,
    aws_apigateway as api_gateway,
    aws_lambda,
    aws_dynamodb as dynamodb,
    aws_route53 as route53,
    aws_route53_targets as targets,
    RemovalPolicy
)
from constructs import Construct


class MyApiGatewayStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, certificate_stack: Stack, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Create DynamoDB table for storing api method metadata.
        api_methods = dynamodb.Table(
            self, 'ApiMethods',
            table_name='api_methods',
            partition_key=dynamodb.Attribute(
                name='api_type',
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name='method_name',
                type=dynamodb.AttributeType.STRING
            ),
            removal_policy=RemovalPolicy.DESTROY,
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
        )

        api_catalog = dynamodb.Table(
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
        )

        api_conformance = dynamodb.Table(
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
        )

        # Create the well-known Lambda function
        # noinspection PyTypeChecker
        well_known_lambda = aws_lambda.Function(
            self, 'WellKnownLambda',
            runtime=aws_lambda.Runtime.PYTHON_3_12,
            handler='well_known_lambda.lambda_handler',
            code=aws_lambda.Code.from_asset('../../src/ogc_landing/well_known'),
        )

        # Grant the WellKnown Lambda permission to access DynamoDB
        api_methods.grant_read_data(well_known_lambda)
        api_catalog.grant_read_data(well_known_lambda)
        api_conformance.grant_read_data(well_known_lambda)

        # Create API Gateway
        api = api_gateway.RestApi(
            self, 'MyApis',
            rest_api_name='My APIs',
            description='Landing Page for My APIs.',
        )

        # Create API resources and methods
        index_resource = api.root.add_resource('index.html')
        well_known_resource = api.root.add_resource('.well-known')
        well_known_name_resource = well_known_resource.add_resource('{well_known_name}')
        conformance_resource = api.root.add_resource('conformance')
        conformance_alias_resource = conformance_resource.add_resource('{conformance_alias}')
        api_resource = api.root.add_resource('api')
        documentation_resource = api.root.add_resource('documentation')

        # Add Get method with well-known name endpoint.
        # noinspection PyTypeChecker
        api_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE,
        )

        # Add Get method with well-known name endpoint.
        # noinspection PyTypeChecker
        documentation_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE,
        )

        # Add Get method with well-known name endpoint.
        # noinspection PyTypeChecker
        conformance_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE,
        )

        # Add Get method with well-known name endpoint.
        # noinspection PyTypeChecker
        conformance_alias_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE,
        )

        # Add Get method with well-known name endpoint.
        # noinspection PyTypeChecker
        well_known_name_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE,
        )

        # Add Get method with well-known endpoint.
        # noinspection PyTypeChecker
        well_known_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE,
        )

        # Add an index page
        # noinspection PyTypeChecker
        api.root.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE,
        )

        # Add an index page as index.html
        # noinspection PyTypeChecker
        index_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE,
        )

        # Look up the hosted zone name
        hosted_zone = route53.HostedZone.from_lookup(
            self, 'HostedZone',
            domain_name='i7es.click'
        )

        # Create custom domain for API Gateway
        # noinspection PyTypeChecker,PyUnresolvedReferences
        domain = api_gateway.DomainName(
            self, 'LandingDomain',
            domain_name='i7es.click',
            certificate=certificate_stack.certificate,
            endpoint_type=api_gateway.EndpointType.EDGE
        )

        # Map the custom domain to the API
        domain.add_base_path_mapping(api, stage=api.deployment_stage)

        # Create DNS record to point to the API Gateway domain
        route53.ARecord(
            self, 'LandingApiGatewayAliasRecord',
            zone=hosted_zone,
            record_name='',
            target=route53.RecordTarget.from_alias(
                targets.ApiGatewayDomain(domain)
            )
        )
