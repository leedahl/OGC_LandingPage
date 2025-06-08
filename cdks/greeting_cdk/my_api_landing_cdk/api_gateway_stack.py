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


class MyApiGatewayStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, certificate_stack: Stack, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Create KMS key for password encryption
        kms_key = kms.Key(
            self, 'HelloWorldKey',
            alias='hello_world',
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

        # Create the Authorizer Lambda function
        # noinspection PyTypeChecker
        authorizer_lambda = aws_lambda.Function(
            self, 'AuthorizerLambda',
            function_name='AuthorizerLambda',  # Custom name without stack prefix or random suffix
            runtime=aws_lambda.Runtime.PYTHON_3_12,
            handler='ogc_landing.authorizer.authorizer_lambda.lambda_handler',
            code=aws_lambda.Code.from_asset('../../src'),
            environment={
                'PYTHONPATH': '/var/task',
                'key_alias': 'hello_world'
            },
        )

        # Grant the Authorizer Lambda permissions to access DynamoDB and KMS
        user_table.grant_read_data(authorizer_lambda)
        kms_key.grant_decrypt(authorizer_lambda)

        # Create the Greeting Lambda function
        # noinspection PyTypeChecker
        greeting_lambda = aws_lambda.Function(
            self, 'GreetingLambda',
            function_name='GreetingLambda',  # Custom name without stack prefix or random suffix
            runtime=aws_lambda.Runtime.PYTHON_3_12,
            handler='ogc_landing.greeting.greeting_lambda.lambda_handler',
            code=aws_lambda.Code.from_asset('../../src'),
            environment={
                'PYTHONPATH': '/var/task'
            },
        )

        # Create the register Lambda function
        # noinspection PyTypeChecker
        register_lambda = aws_lambda.Function(
            self, 'RegisterLambda',
            function_name='RegisterLambda',  # Custom name without stack prefix or random suffix
            runtime=aws_lambda.Runtime.PYTHON_3_12,
            handler='ogc_landing.registration.register_lambda.lambda_handler',
            code=aws_lambda.Code.from_asset('../../src'),
            environment={
                'PYTHONPATH': '/var/task',
                'key_alias': 'hello_world'
            },
        )

        # Create the well-known proxy Lambda function
        # noinspection PyTypeChecker
        well_known_proxy_lambda = aws_lambda.Function(
            self, 'WellKnownProxyLambda',
            function_name='WellKnownProxyLambda',  # Custom name without stack prefix or random suffix
            runtime=aws_lambda.Runtime.PYTHON_3_12,
            handler='ogc_landing.well_known.well_known_proxy_lambda.lambda_handler',
            code=aws_lambda.Code.from_asset('../../src'),
            environment={
                'PYTHONPATH': '/var/task',
                'TARGET_ACCOUNT_ID': '047988295961',
                'TARGET_FUNCTION_NAME': 'WellKnownLambda',
                'TARGET_REGION': 'us-east-2'
            },
        )

        # Grant the well-known proxy Lambda permission to invoke the well-known Lambda in the other account
        well_known_proxy_lambda.add_to_role_policy(
            iam.PolicyStatement(
                actions=['lambda:InvokeFunction'],
                resources=[f'arn:aws:lambda:us-east-2:047988295961:function:WellKnownLambda'],
                effect=iam.Effect.ALLOW
            )
        )

        # Create the user management Lambda function
        # noinspection PyTypeChecker
        user_management_lambda = aws_lambda.Function(
            self, 'UserManagementLambda',
            function_name='UserManagementLambda',  # Custom name without stack prefix or random suffix
            runtime=aws_lambda.Runtime.PYTHON_3_12,
            handler='ogc_landing.user_management.user_management_lambda.lambda_handler',
            code=aws_lambda.Code.from_asset('../../src'),
            environment={
                'PYTHONPATH': '/var/task',
                'key_alias': 'hello_world'
            },
        )

        # Grant the Register Lambda permission to access DynamoDB
        user_table.grant_read_write_data(register_lambda)
        kms_key.grant_encrypt(register_lambda)

        # Grant the User Management Lambda permission to access DynamoDB and KMS
        user_table.grant_read_write_data(user_management_lambda)
        kms_key.grant_encrypt_decrypt(user_management_lambda)

        # Create API Gateway
        api = api_gateway.RestApi(
            self, 'GreetingApi',
            rest_api_name='Greeting API',
            description='Personalized Greeting API.',
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
        register_resource = api.root.add_resource('register')
        greeting_resource = api.root.add_resource('retrieve')
        greeting_name_resource = greeting_resource.add_resource('{name}')
        user_management_resource = api.root.add_resource('user-management')
        well_known_resource = api.root.add_resource('.well_known')
        well_known_name_resource = well_known_resource.add_resource('{well_known_name}')
        api_resource = api.root.add_resource('api')
        documentation_resource = api.root.add_resource('documentation')
        conformance_resource = api.root.add_resource('conformance')
        conformance_name_resource = conformance_resource.add_resource('{conformance_name}')

        # Add GET method with authorizer to the greeting endpoint
        # noinspection PyTypeChecker
        greeting_name_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(greeting_lambda),
            authorizer=authorizer,
            authorization_type=api_gateway.AuthorizationType.CUSTOM,
        )

        # Also add a default greeting endpoint without a name parameter
        # noinspection PyTypeChecker
        register_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(register_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE,
        )

        # Add a registration submit endpoint
        # noinspection PyTypeChecker
        register_resource.add_method(
            'POST',
            api_gateway.LambdaIntegration(register_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE,
        )

        # Add a default registration endpoint
        # noinspection PyTypeChecker
        greeting_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(greeting_lambda),
            authorizer=authorizer,
            authorization_type=api_gateway.AuthorizationType.CUSTOM,
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

        # Add GET method to the well-known endpoint
        # noinspection PyTypeChecker
        well_known_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_proxy_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE
        )

        # Add GET method to the well-known endpoint
        # noinspection PyTypeChecker
        well_known_name_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_proxy_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE
        )

        # Add GET method to the well-known endpoint
        # noinspection PyTypeChecker
        api_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_proxy_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE
        )

        # Add GET method to the well-known endpoint
        # noinspection PyTypeChecker
        documentation_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_proxy_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE
        )

        # Add GET method to the well-known endpoint
        # noinspection PyTypeChecker
        conformance_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_proxy_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE
        )

        # Add GET method to the well-known endpoint
        # noinspection PyTypeChecker
        conformance_name_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_proxy_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE
        )

        # Look up the hosted zone name
        hosted_zone = route53.HostedZone.from_lookup(
            self, 'HostedZone',
            domain_name='greeting.i7es.click'
        )

        # Create custom domain for API Gateway
        # noinspection PyTypeChecker,PyUnresolvedReferences
        domain = api_gateway.DomainName(
            self, 'GreetingDomain',
            domain_name='greeting.i7es.click',
            certificate=certificate_stack.certificate,
            endpoint_type=api_gateway.EndpointType.EDGE
        )

        # Map the custom domain to the API
        domain.add_base_path_mapping(api, stage=api.deployment_stage)

        # Create DNS record to point to the API Gateway domain
        route53.ARecord(
            self, 'GreetingApiGatewayAliasRecord',
            zone=hosted_zone,
            record_name='',
            target=route53.RecordTarget.from_alias(
                targets.ApiGatewayDomain(domain)
            )
        )
