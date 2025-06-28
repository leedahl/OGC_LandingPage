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
    aws_route53 as route53,
    aws_route53_targets as targets,
    Duration,
    aws_iam as iam,
    aws_logs as logs
)
from aws_cdk.aws_apigateway import ResponseType
from constructs import Construct


class MyApiGatewayStack(Stack):
    def __init__(
            self, scope: Construct, construct_id: str, certificate_stack: Stack, security_account: str,
            production_account: str, **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Create a role with a fixed name for the well-known proxy Lambda function
        authorizer_proxy_role = iam.Role(
            self, 'GreetingAuthorizerProxyRole',
            role_name='GreetingAuthorizerProxyLambdaRole',  # Fixed name without stack prefix or random suffix
            assumed_by=iam.ServicePrincipal('lambda.amazonaws.com'),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name('service-role/AWSLambdaBasicExecutionRole')
            ]
        )

        # Grant the well-known proxy Lambda permission to invoke the well-known Lambda in the other account
        authorizer_proxy_role.add_to_policy(
            iam.PolicyStatement(
                actions=['lambda:InvokeFunction'],
                resources=[f'arn:aws:lambda:us-east-2:{security_account}:function:AuthorizerOhioLambda'],
                effect=iam.Effect.ALLOW
            )
        )

        # Create the Authorizer Lambda function
        # noinspection PyTypeChecker
        authorizer_lambda = aws_lambda.Function(
            self, 'AuthorizerProxyLambda',
            function_name='AuthorizerProxyLambda',  # Custom name without stack prefix or random suffix
            runtime=aws_lambda.Runtime.PYTHON_3_12,
            architecture=aws_lambda.Architecture.ARM_64,
            handler='ogc_landing.proxy.proxy_lambda.lambda_handler',
            code=aws_lambda.Code.from_asset('../../src/proxy_lambda'),
            timeout=Duration.seconds(10),
            role=authorizer_proxy_role,  # Use the fixed role
            environment = {
                'TARGET_ACCOUNT_ID': security_account,
                'TARGET_FUNCTION_NAME': 'AuthorizerOhioLambda',
                'TARGET_REGION': 'us-east-2'
            }
        )

        # Configure CloudWatch logs with 7-day retention policy
        logs.LogRetention(
            self, 'AuthorizerLambdaLogRetention',
            log_group_name=f'/aws/lambda/{authorizer_lambda.function_name}',
            retention=logs.RetentionDays.ONE_WEEK
        )

        # Create the Greeting Lambda function
        # noinspection PyTypeChecker
        greeting_lambda = aws_lambda.Function(
            self, 'GreetingLambda',
            function_name='GreetingLambda',  # Custom name without stack prefix or random suffix
            runtime=aws_lambda.Runtime.PYTHON_3_12,
            architecture=aws_lambda.Architecture.ARM_64,
            handler='ogc_landing.greeting.greeting_lambda.lambda_handler',
            code=aws_lambda.Code.from_asset('../../src/greeting_lambda')
        )

        # Configure CloudWatch logs with 7-day retention policy
        logs.LogRetention(
            self, 'GreetingLambdaLogRetention',
            log_group_name=f'/aws/lambda/{greeting_lambda.function_name}',
            retention=logs.RetentionDays.ONE_WEEK
        )

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
                resources=[f'arn:aws:lambda:us-east-2:{production_account}:function:WellKnownLambda'],
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
            handler='ogc_landing.proxy.proxy_lambda.lambda_handler',
            code=aws_lambda.Code.from_asset('../../src/proxy_lambda'),
            timeout=Duration.seconds(10),
            role=well_known_proxy_role,  # Use the fixed role
            environment={
                'TARGET_ACCOUNT_ID': production_account,
                'TARGET_FUNCTION_NAME': 'WellKnownLambda',
                'TARGET_REGION': 'us-east-2'
            }
        )

        # Configure CloudWatch logs with 7-day retention policy
        logs.LogRetention(
            self, 'WellKnownProxyLambdaLogRetention',
            log_group_name=f'/aws/lambda/{well_known_proxy_lambda.function_name}',
            retention=logs.RetentionDays.ONE_WEEK
        )

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
        index_resource = api.root.add_resource('index.html')
        basic_authentication_resource = api.root.add_resource('basic_authentication.html')
        basic_authentication_issues_resource = api.root.add_resource('basic_authentication_issues.html')
        describe_security_controls_resource = api.root.add_resource('describe_security_controls.html')
        greeting_resource = api.root.add_resource('retrieve')
        greeting_name_resource = greeting_resource.add_resource('{name}')
        well_known_resource = api.root.add_resource('.well-known')
        well_known_name_resource = well_known_resource.add_resource('{well_known_name}')
        api_resource = api.root.add_resource('api')
        documentation_resource = api.root.add_resource('documentation')
        conformance_resource = api.root.add_resource('conformance')
        conformance_name_resource = conformance_resource.add_resource('{conformance_alias}')

        # Add GET method to the well-known endpoint
        # noinspection PyTypeChecker
        index_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_proxy_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE
        )

        # Add GET method to the well-known endpoint
        # noinspection PyTypeChecker
        basic_authentication_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_proxy_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE
        )

        # Add GET method to the well-known endpoint
        # noinspection PyTypeChecker
        basic_authentication_issues_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_proxy_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE
        )

        # Add GET method to the well-known endpoint
        # noinspection PyTypeChecker
        describe_security_controls_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_proxy_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE
        )

        # Add GET method to the well-known endpoint
        # noinspection PyTypeChecker
        api.root.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_proxy_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE
        )

        # Add GET method with authorizer to the greeting endpoint
        # noinspection PyTypeChecker
        greeting_name_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(greeting_lambda),
            authorizer=authorizer,
            authorization_type=api_gateway.AuthorizationType.CUSTOM,
        )

        # Add a default registration endpoint
        # noinspection PyTypeChecker
        greeting_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(greeting_lambda),
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
