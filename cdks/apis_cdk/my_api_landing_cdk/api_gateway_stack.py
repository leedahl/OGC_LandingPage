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
    aws_kms as kms,
    aws_route53 as route53,
    aws_route53_targets as targets,
    Duration,
    RemovalPolicy
)
from aws_cdk.aws_apigateway import ResponseType
from constructs import Construct


class MyApiGatewayStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, certificate_stack: Stack, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

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

        # Create DynamoDB tables for OpenAPI 3.0 schema as recommended in openapi_dynamodb_schema.md

        # 1. openapi_documents table
        openapi_documents = dynamodb.Table(
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
        )

        # 2. openapi_servers table
        openapi_servers = dynamodb.Table(
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
        )

        # 3. openapi_paths table
        openapi_paths = dynamodb.Table(
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
        )

        # 4. openapi_operations table
        openapi_operations = dynamodb.Table(
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
        )

        # 5. openapi_components table
        openapi_components = dynamodb.Table(
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
        )

        # 6. openapi_tags table
        openapi_tags = dynamodb.Table(
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
        )

        # 7. openapi_security_schemes table
        openapi_security_schemes = dynamodb.Table(
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
        )

        # Create KMS key for password encryption
        kms_key = kms.Key(
            self, 'PortfolioUserStoreAPIKey',
            alias='portfolio_user_store_key',
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # Create DynamoDB table for user store
        user_table = dynamodb.Table(
            self, 'UserStore',
            table_name='user_store',
            partition_key=dynamodb.Attribute(
                name='username',
                type=dynamodb.AttributeType.STRING
            ),
            removal_policy=RemovalPolicy.DESTROY,
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
        )

        # Create DynamoDB table for API security (mapping username to api_id)
        api_security_table = dynamodb.Table(
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
        )

        # Create the well-known Lambda function
        # noinspection PyTypeChecker
        well_known_lambda = aws_lambda.Function(
            self, 'WellKnownLambda',
            runtime=aws_lambda.Runtime.PYTHON_3_12,
            handler='ogc_landing.well_known.well_known_lambda.lambda_handler',
            code=aws_lambda.Code.from_asset('../../src'),
            environment={
                'PYTHONPATH': '/var/task'
            },
        )

        # Create the OpenAPI Lambda function
        # noinspection PyTypeChecker
        openapi_lambda = aws_lambda.Function(
            self, 'OpenApiLambda',
            runtime=aws_lambda.Runtime.PYTHON_3_12,
            handler='ogc_landing.openapi.openapi_lambda.lambda_handler',
            code=aws_lambda.Code.from_asset('../../src'),
            environment={
                'PYTHONPATH': '/var/task'
            },
        )

        # Grant the WellKnown Lambda permission to access DynamoDB
        api_catalog.grant_read_data(well_known_lambda)
        api_conformance.grant_read_data(well_known_lambda)

        # Grant the WellKnown Lambda permission to access OpenAPI DynamoDB tables
        openapi_documents.grant_read_data(well_known_lambda)
        openapi_servers.grant_read_data(well_known_lambda)
        openapi_paths.grant_read_data(well_known_lambda)
        openapi_operations.grant_read_data(well_known_lambda)
        openapi_components.grant_read_data(well_known_lambda)
        openapi_tags.grant_read_data(well_known_lambda)
        openapi_security_schemes.grant_read_data(well_known_lambda)

        # Grant the OpenAPI Lambda permission to access DynamoDB
        api_catalog.grant_read_write_data(openapi_lambda)

        # Grant the OpenAPI Lambda permission to access OpenAPI DynamoDB tables
        openapi_documents.grant_read_write_data(openapi_lambda)
        openapi_servers.grant_read_write_data(openapi_lambda)
        openapi_paths.grant_read_write_data(openapi_lambda)
        openapi_operations.grant_read_write_data(openapi_lambda)
        openapi_components.grant_read_write_data(openapi_lambda)
        openapi_tags.grant_read_write_data(openapi_lambda)
        openapi_security_schemes.grant_read_write_data(openapi_lambda)

        # Create the Authorizer Lambda function
        # noinspection PyTypeChecker
        authorizer_lambda = aws_lambda.Function(
            self, 'AuthorizerLambda',
            runtime=aws_lambda.Runtime.PYTHON_3_12,
            handler='ogc_landing.authorizer.authorizer_lambda.lambda_handler',
            code=aws_lambda.Code.from_asset('../../src'),
            environment={
                'PYTHONPATH': '/var/task',
                'key_alias': 'portfolio_user_store_key'
            },
        )

        # Grant the Authorizer Lambda permissions to access DynamoDB and KMS
        user_table.grant_read_data(authorizer_lambda)
        api_security_table.grant_read_data(authorizer_lambda)
        kms_key.grant_decrypt(authorizer_lambda)

        # Create the register Lambda function
        # noinspection PyTypeChecker
        register_lambda = aws_lambda.Function(
            self, 'RegisterLambda',
            runtime=aws_lambda.Runtime.PYTHON_3_12,
            handler='ogc_landing.registration.register_lambda.lambda_handler',
            code=aws_lambda.Code.from_asset('../../src'),
            environment={
                'PYTHONPATH': '/var/task',
                'key_alias': 'portfolio_user_store_key'
            },
        )

        # Create User Management Lambda
        # noinspection PyTypeChecker
        user_management_lambda = aws_lambda.Function(
            self, 'UserManagementLambda',
            runtime=aws_lambda.Runtime.PYTHON_3_12,
            handler='ogc_landing.user_management.user_management_lambda.lambda_handler',
            code=aws_lambda.Code.from_asset('../../src'),
            environment={
                'PYTHONPATH': '/var/task',
                'key_alias': 'portfolio_user_store_key'
            },
        )

        # Grant the Register Lambda permission to access DynamoDB
        user_table.grant_read_write_data(register_lambda)
        kms_key.grant_encrypt(register_lambda)

        # Grant the User Management Lambda permission to access DynamoDB and KMS
        user_table.grant_read_write_data(user_management_lambda)
        api_security_table.grant_read_write_data(user_management_lambda)
        kms_key.grant_encrypt_decrypt(user_management_lambda)

        # Create API Gateway
        api = api_gateway.RestApi(
            self, 'MyApis',
            rest_api_name='My APIs',
            description='Landing Page for My APIs.',
        )

        # Configure 401 Gateway Response to include WWW-Authenticate header
        # noinspection PyTypeChecker
        api.add_gateway_response(
            'Unauthorized',
            type=ResponseType.UNAUTHORIZED,
            response_headers={
                'WWW-Authenticate': "'Basic realm=\"Personalized Greeting API\"'"
            }
        )

        # Create Lambda authorizer
        # noinspection PyTypeChecker
        authorizer = api_gateway.RequestAuthorizer(
            self, 'ApiAuthorizer',
            handler=authorizer_lambda,
            identity_sources=[api_gateway.IdentitySource.header('Authorization')],
            results_cache_ttl=Duration.seconds(0)  # Disable caching for testing
        )

        # Create API resources and methods
        index_resource = api.root.add_resource('index.html')
        well_known_resource = api.root.add_resource('.well-known')
        well_known_name_resource = well_known_resource.add_resource('{well_known_name}')
        conformance_resource = api.root.add_resource('conformance')
        conformance_alias_resource = conformance_resource.add_resource('{conformance_alias}')
        api_resource = api.root.add_resource('api')
        documentation_resource = api.root.add_resource('documentation')
        register_resource = api.root.add_resource('register')
        user_management_resource = api.root.add_resource('user-management')

        # Create OpenAPI resources
        openapi_resource = api_resource.add_resource('openapi')
        openapi_api_id_resource = openapi_resource.add_resource('{api_id}')

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

        # Add POST method to upload OpenAPI documents
        # noinspection PyTypeChecker
        openapi_resource.add_method(
            'POST',
            api_gateway.LambdaIntegration(
                openapi_lambda,
                timeout=Duration.seconds(10)  # Set timeout to 10 seconds
            ),
            authorizer=authorizer,
            authorization_type=api_gateway.AuthorizationType.CUSTOM,
        )

        # Add GET method to retrieve OpenAPI documents by API ID
        # noinspection PyTypeChecker
        openapi_api_id_resource.add_method(
            'POST',
            api_gateway.LambdaIntegration(
                openapi_lambda,
                timeout=Duration.seconds(10)  # Set timeout to 10 seconds
            ),
            authorizer=authorizer,
            authorization_type=api_gateway.AuthorizationType.CUSTOM,
        )

        # Add GET method for register resource
        # noinspection PyTypeChecker
        register_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(register_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE,
        )

        # Add POST method for register resource
        # noinspection PyTypeChecker
        register_resource.add_method(
            'POST',
            api_gateway.LambdaIntegration(register_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE,
        )

        # Add GET method to user management endpoint
        # noinspection PyTypeChecker
        user_management_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(user_management_lambda),
            authorizer=authorizer,
            authorization_type=api_gateway.AuthorizationType.CUSTOM,
        )

        # Add POST method to user management endpoint
        # noinspection PyTypeChecker
        user_management_resource.add_method(
            'POST',
            api_gateway.LambdaIntegration(user_management_lambda),
            authorizer=authorizer,
            authorization_type=api_gateway.AuthorizationType.CUSTOM,
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
