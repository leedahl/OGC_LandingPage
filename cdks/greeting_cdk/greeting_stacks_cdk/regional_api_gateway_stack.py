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
    aws_logs as logs,
    aws_certificatemanager as acm, BundlingOptions
)
from aws_cdk.aws_apigateway import ResponseType
from constructs import Construct


class GreetingApiGatewayRegionalStack(Stack):
    def __init__(
            self, scope: Construct, construct_id: str, security_account: str, region_name: str, **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Create a role with a region-specific name for the authorizer proxy Lambda function
        authorizer_proxy_role = iam.Role(
            self, 'GreetingAuthorizerProxyRole',
            role_name=f'GreetingAuthorizerProxy{region_name}Role',  # Region-specific name matching what's expected in security_cdk
            assumed_by=iam.ServicePrincipal('lambda.amazonaws.com'),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name('service-role/AWSLambdaBasicExecutionRole')
            ]
        )

        # Grant the authorizer proxy Lambda permission to invoke the Authorizer Lambda in the security account
        # in the same region
        authorizer_proxy_role.add_to_policy(
            iam.PolicyStatement(
                actions=['lambda:InvokeFunction'],
                resources=[f'arn:aws:lambda:{self.region}:{security_account}:function:Authorizer{region_name}Lambda'],
                effect=iam.Effect.ALLOW
            )
        )

        # Create the Authorizer Proxy Lambda function with region-specific name
        # noinspection PyTypeChecker
        authorizer_lambda = aws_lambda.Function(
            self, 'AuthorizerProxyLambda',
            function_name=f'AuthorizerProxy{region_name}Lambda',  # Region-specific name
            runtime=aws_lambda.Runtime.PYTHON_3_12,
            architecture=aws_lambda.Architecture.ARM_64,
            handler='ogc_landing.authorizer_proxy.proxy_lambda.lambda_handler',
            timeout=Duration.seconds(29),
            role=authorizer_proxy_role,  # Use the region-specific role
            code = aws_lambda.Code.from_asset(
                '../../src/authorizer_proxy_lambda',
                bundling=BundlingOptions(
                    image=aws_lambda.Runtime.PYTHON_3_12.bundling_image,
                    command=[
                        "bash", "-c",
                        "pip install --no-cache-dir -r requirements.txt -t /asset-output && cp -au . /asset-output"
                    ],
                    environment={
                        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
                        "PIP_NO_CACHE_DIR": "1"
                    }
                )
            )
        )

        # Configure CloudWatch logs with 7-day retention policy
        logs.LogRetention(
            self, 'AuthorizerLambdaLogRetention',
            log_group_name=f'/aws/lambda/{authorizer_lambda.function_name}',
            retention=logs.RetentionDays.ONE_WEEK
        )

        # Create the Greeting Lambda function with region-specific name
        # noinspection PyTypeChecker
        greeting_lambda = aws_lambda.Function(
            self, 'GreetingLambda',
            function_name=f'Greeting{region_name}Lambda',  # Region-specific name
            runtime=aws_lambda.Runtime.PYTHON_3_12,
            architecture=aws_lambda.Architecture.ARM_64,
            handler='ogc_landing.greeting.greeting_lambda.lambda_handler',
            code=aws_lambda.Code.from_asset('../../src/greeting_lambda'),
            timeout=Duration.seconds(29)
        )

        # Configure CloudWatch logs with 7-day retention policy
        logs.LogRetention(
            self, 'GreetingLambdaLogRetention',
            log_group_name=f'/aws/lambda/{greeting_lambda.function_name}',
            retention=logs.RetentionDays.ONE_WEEK
        )

        # Create custom domain name and Route53 record
        # Look up the hosted zone
        hosted_zone = route53.HostedZone.from_lookup(
            self, 'HostedZone',
            domain_name='greeting.i7es.click'
        )

        # Create ACM certificate for the domain
        self.certificate = acm.Certificate(
            self, 'GreetingCertificate',
            domain_name='greeting.i7es.click',
            validation=acm.CertificateValidation.from_dns(hosted_zone)
        )

        # Create API Gateway
        api = api_gateway.RestApi(
            self, 'GreetingApi',
            rest_api_name=f'Greeting {region_name} API',
            description=f'Personalized Greeting API for {region_name} region.',
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

        well_known_lambda = aws_lambda.Function.from_function_name(
            self, 'GreetingWellKnownLambda', f'WellKnown{region_name}Lambda'
        )

        # Add GET method to the index endpoint
        # noinspection PyTypeChecker
        index_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE
        )

        # Add GET method to the basic authentication endpoint
        # noinspection PyTypeChecker
        basic_authentication_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE
        )

        # Add GET method to the basic authentication issues endpoint
        # noinspection PyTypeChecker
        basic_authentication_issues_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE
        )

        # Add GET method to the describing security controls endpoint
        # noinspection PyTypeChecker
        describe_security_controls_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE
        )

        # Add GET method to the root endpoint
        # noinspection PyTypeChecker
        api.root.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_lambda),
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
            api_gateway.LambdaIntegration(well_known_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE
        )

        # Add GET method to the well-known name endpoint
        # noinspection PyTypeChecker
        well_known_name_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE
        )

        # Add GET method to the api endpoint
        # noinspection PyTypeChecker
        api_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE
        )

        # Add GET method to the documentation endpoint
        # noinspection PyTypeChecker
        documentation_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE
        )

        # Add GET method to the conformance endpoint
        # noinspection PyTypeChecker
        conformance_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE
        )

        # Add GET method to the conformance name endpoint
        # noinspection PyTypeChecker
        conformance_name_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE
        )

        # Create custom domain for API Gateway
        # noinspection PyTypeChecker,PyUnresolvedReferences
        domain = api_gateway.DomainName(
            self, 'GreetingDomain',
            domain_name='greeting.i7es.click',
            certificate=self.certificate,
            endpoint_type=api_gateway.EndpointType.REGIONAL,
            security_policy = api_gateway.SecurityPolicy.TLS_1_2
        )

        # Map the custom domain to the API
        domain.add_base_path_mapping(api, stage=api.deployment_stage)

        # Create DNS record to point to the API Gateway domain
        route53.ARecord(
            self, 'GreetingApiGatewayAliasRecordA',
            zone=hosted_zone,
            record_name='',
            target=route53.RecordTarget.from_alias(
                targets.ApiGatewayDomain(domain)
            ),
            region=self.region
        )

        route53.AaaaRecord(
            self, 'GreetingApiGatewayAliasRecordAaaa',
            zone=hosted_zone,
            record_name='',
            target=route53.RecordTarget.from_alias(
                targets.ApiGatewayDomain(domain)
            ),
            region=self.region
        )
