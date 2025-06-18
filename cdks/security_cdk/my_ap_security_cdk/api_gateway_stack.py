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
    RemovalPolicy,
    aws_iam as iam
)
from aws_cdk.aws_apigateway import ResponseType
from constructs import Construct


class MySecurityApiGatewayStack(Stack):
    def __init__(
            self, scope: Construct, construct_id: str, certificate_stack: Stack, api_account: str, **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

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

        # Create KMS key for password encryption
        kms_key = kms.Key(
            self, 'SecurityUserStoreAPIKey',
            alias='security_user_store_key',
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # Create the Authorizer Lambda function
        # noinspection PyTypeChecker
        authorizer_lambda = aws_lambda.Function(
            self, 'AuthorizerLambda',
            function_name='AuthorizerLambda',  # Custom name without stack prefix or random suffix
            runtime=aws_lambda.Runtime.PYTHON_3_12,
            architecture=aws_lambda.Architecture.ARM_64,
            handler='ogc_landing.authorizer.authorizer_lambda.lambda_handler',
            code=aws_lambda.Code.from_asset('../../src/authorizer_lambda'),
            environment={
                'key_alias': 'portfolio_user_store_key'
            }
        )

        # Grant the Authorizer Lambda permissions to access DynamoDB and KMS
        user_table.grant_read_data(authorizer_lambda)
        api_security_table.grant_read_data(authorizer_lambda)
        kms_key.grant_decrypt(authorizer_lambda)

        # Create the register Lambda function
        # noinspection PyTypeChecker
        register_lambda = aws_lambda.Function(
            self, 'RegisterLambda',
            function_name='RegisterLambda',  # Custom name without stack prefix or random suffix
            runtime=aws_lambda.Runtime.PYTHON_3_12,
            architecture=aws_lambda.Architecture.ARM_64,
            handler='ogc_landing.registration.register_lambda.lambda_handler',
            code=aws_lambda.Code.from_asset('../../src/registration_lambda'),
            environment={
                'key_alias': 'security_user_store_key'
            }
        )

        # Create User Management Lambda
        # noinspection PyTypeChecker
        user_management_lambda = aws_lambda.Function(
            self, 'UserManagementLambda',
            function_name='UserManagementLambda',  # Custom name without stack prefix or random suffix
            runtime=aws_lambda.Runtime.PYTHON_3_12,
            architecture=aws_lambda.Architecture.ARM_64,
            handler='ogc_landing.user_management.user_management_lambda.lambda_handler',
            code=aws_lambda.Code.from_asset('../../src/user_management_lambda'),
            environment={
                'key_alias': 'portfolio_user_store_key'
            }
        )

        # Grant the Register Lambda permission to access DynamoDB
        user_table.grant_read_write_data(register_lambda)
        kms_key.grant_encrypt(register_lambda)

        # Grant the User Management Lambda permission to access DynamoDB and KMS
        user_table.grant_read_write_data(user_management_lambda)
        api_security_table.grant_read_write_data(user_management_lambda)
        kms_key.grant_encrypt_decrypt(user_management_lambda)

        # Create a role with a fixed name for the well-known proxy Lambda function
        well_known_proxy_role = iam.Role(
            self, 'WellKnownProxyRole',
            role_name='WellKnownProxyLambdaRole',  # Fixed name without stack prefix or random suffix
            assumed_by=iam.ServicePrincipal('lambda.amazonaws.com'),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name('service-role/AWSLambdaBasicExecutionRole')
            ]
        )

        # Grant the well-known proxy Lambda permission to invoke the well-known Lambda in the other account
        well_known_proxy_role.add_to_policy(
            iam.PolicyStatement(
                actions=['lambda:InvokeFunction'],
                resources=[f'arn:aws:lambda:us-east-2:{api_account}:function:WellKnownLambda'],
                effect=iam.Effect.ALLOW
            )
        )

        # Create the well-known proxy Lambda function
        # noinspection PyTypeChecker
        well_known_proxy_lambda = aws_lambda.Function(
            self, 'WellKnownProxyLambda',
            function_name='WellKnownProxyLambda',  # Custom name without stack prefix or random suffix
            runtime=aws_lambda.Runtime.PYTHON_3_12,
            architecture=aws_lambda.Architecture.ARM_64,
            handler='ogc_landing.well_known.well_known_proxy_lambda.lambda_handler',
            code=aws_lambda.Code.from_asset('../../src/well_known_proxy_lambda'),
            timeout=Duration.seconds(10),
            role=well_known_proxy_role,  # Use the fixed role
            environment={
                'TARGET_ACCOUNT_ID': api_account,
                'TARGET_FUNCTION_NAME': 'WellKnownLambda',
                'TARGET_REGION': 'us-east-2'
            }
        )

        # Create API Gateway
        api = api_gateway.RestApi(
            self, 'MyApiSecurity',
            rest_api_name='My API Security Service',
            description='Security services for APIs.',
        )

        # Configure 401 Gateway Response to include WWW-Authenticate header
        # noinspection PyTypeChecker
        api.add_gateway_response(
            'Unauthorized',
            type=ResponseType.UNAUTHORIZED,
            response_headers={
                'WWW-Authenticate': "'Basic realm=\"Security Management API\"'"
            }
        )

        # Create Lambda authorizer
        # noinspection PyTypeChecker
        authorizer = api_gateway.RequestAuthorizer(
            self, 'ApiAuthorizer',
            handler=authorizer_lambda,
            identity_sources=[api_gateway.IdentitySource.header('Authorization')],
            results_cache_ttl=Duration.seconds(0)  # Disable caching
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

        # Add Get method with well-known name endpoint.
        # noinspection PyTypeChecker
        api_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_proxy_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE,
        )

        # Add Get method with well-known name endpoint.
        # noinspection PyTypeChecker
        documentation_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_proxy_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE,
        )

        # Add Get method with well-known name endpoint.
        # noinspection PyTypeChecker
        conformance_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_proxy_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE,
        )

        # Add Get method with well-known name endpoint.
        # noinspection PyTypeChecker
        conformance_alias_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_proxy_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE,
        )

        # Add Get method with well-known name endpoint.
        # noinspection PyTypeChecker
        well_known_name_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_proxy_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE,
        )

        # Add Get method with well-known endpoint.
        # noinspection PyTypeChecker
        well_known_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_proxy_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE,
        )

        # Add an index page
        # noinspection PyTypeChecker
        api.root.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_proxy_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE,
        )

        # Add an index page as index.html
        # noinspection PyTypeChecker
        index_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(
                well_known_proxy_lambda,
                timeout = Duration.seconds(10)  # Set timeout to 10 seconds
            ),
            authorization_type=api_gateway.AuthorizationType.NONE,
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
            domain_name='security.i7es.click'
        )

        # Create custom domain for API Gateway
        # noinspection PyTypeChecker,PyUnresolvedReferences
        domain = api_gateway.DomainName(
            self, 'SecurityDomain',
            domain_name='security.i7es.click',
            certificate=certificate_stack.certificate,
            endpoint_type=api_gateway.EndpointType.EDGE
        )

        # Map the custom domain to the API
        domain.add_base_path_mapping(api, stage=api.deployment_stage)

        # Create DNS record to point to the API Gateway domain
        route53.ARecord(
            self, 'SecurityApiGatewayAliasRecord',
            zone=hosted_zone,
            record_name='',
            target=route53.RecordTarget.from_alias(
                targets.ApiGatewayDomain(domain)
            )
        )
