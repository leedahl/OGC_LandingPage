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
    Duration,
    aws_iam as iam,
    aws_route53 as route53,
    aws_route53_targets as targets,
    aws_certificatemanager as acm,
    aws_logs as logs, BundlingOptions
)
from aws_cdk.aws_apigateway import ResponseType
from constructs import Construct


class SecurityApiGatewayRegionalStack(Stack):
    def __init__(
            self, scope: Construct, construct_id: str,
            user_table: dynamodb.Table, api_security_table: dynamodb.Table,
            registration_id_table: dynamodb.Table, kms_key: kms.Key, encryption_key: kms.Key, region_name: str, **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Store the DynamoDB tables and KMS keys
        self.user_table = user_table
        self.encryption_key = encryption_key
        self.api_security_table = api_security_table
        self.registration_id_table = registration_id_table
        self.kms_key = kms_key

        # Create custom domain name and Route53 record
        # Look up the hosted zone
        hosted_zone = route53.HostedZone.from_lookup(
            self, 'HostedZone',
            domain_name='security.i7es.click'
        )

        # Create ACM certificate for the domain
        self.certificate = acm.Certificate(
            self, 'SecurityCertificate',
            domain_name='security.i7es.click',
            validation=acm.CertificateValidation.from_dns(hosted_zone)
        )

        # Create the Authorizer Lambda function
        # noinspection PyTypeChecker
        authorizer_lambda = aws_lambda.Function(
            self, 'AuthorizerLambda',
            function_name=f'Authorizer{region_name}Lambda',
            runtime=aws_lambda.Runtime.PYTHON_3_12,
            architecture=aws_lambda.Architecture.ARM_64,
            handler='ogc_landing.authorizer.authorizer_lambda.lambda_handler',
            code=aws_lambda.Code.from_asset('../../src/authorizer_lambda'),
            timeout=Duration.seconds(29),
            environment={
                'key_alias': 'security_user_store_key'
            }
        )

        # Configure CloudWatch logs with 7-day retention policy
        logs.LogRetention(
            self, 'AuthorizerLambdaLogRetention',
            log_group_name=f'/aws/lambda/{authorizer_lambda.function_name}',
            retention=logs.RetentionDays.ONE_WEEK
        )

        # Grant the Authorizer Lambda permissions to access DynamoDB and KMS
        self.user_table.grant_read_data(authorizer_lambda)
        self.api_security_table.grant_read_data(authorizer_lambda)
        self.kms_key.grant_decrypt(authorizer_lambda)

        # Create the register Lambda function
        # noinspection PyTypeChecker
        register_lambda = aws_lambda.Function(
            self, 'RegisterLambda',
            function_name=f'Register{region_name}Lambda',
            runtime=aws_lambda.Runtime.PYTHON_3_12,
            architecture=aws_lambda.Architecture.ARM_64,
            handler='ogc_landing.registration.register_lambda.lambda_handler',
            code=aws_lambda.Code.from_asset(
                '../../src/registration_lambda',
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
            ),
            timeout=Duration.seconds(29),
            environment={
                'key_alias': 'security_user_store_key',
                'registration_id_table': self.registration_id_table.table_name,
                'encryption_key_arn': self.encryption_key.key_arn
            }
        )

        # Configure CloudWatch logs with 7-day retention policy
        logs.LogRetention(
            self, 'RegisterLambdaLogRetention',
            log_group_name=f'/aws/lambda/{register_lambda.function_name}',
            retention=logs.RetentionDays.ONE_WEEK
        )

        # Create User Management Lambda
        # noinspection PyTypeChecker
        user_management_lambda = aws_lambda.Function(
            self, 'UserManagementLambda',
            function_name=f'UserManagement{region_name}Lambda',
            runtime=aws_lambda.Runtime.PYTHON_3_12,
            architecture=aws_lambda.Architecture.ARM_64,
            handler='ogc_landing.user_management.user_management_lambda.lambda_handler',
            code=aws_lambda.Code.from_asset('../../src/user_management_lambda'),
            timeout=Duration.seconds(29),
            environment={
                'key_alias': 'security_user_store_key'
            }
        )

        # Configure CloudWatch logs with 7-day retention policy
        logs.LogRetention(
            self, 'UserManagementLambdaLogRetention',
            log_group_name=f'/aws/lambda/{user_management_lambda.function_name}',
            retention=logs.RetentionDays.ONE_WEEK
        )

        # Grant the Register Lambda permission to access DynamoDB, KMS, and ACM
        self.user_table.grant_read_write_data(register_lambda)
        self.registration_id_table.grant_read_write_data(register_lambda)
        self.kms_key.grant_encrypt(register_lambda)
        self.encryption_key.grant_decrypt(register_lambda)
        self.encryption_key.grant(register_lambda, 'kms:GetPublicKey')

        # Grant the User Management Lambda permission to access DynamoDB and KMS
        self.user_table.grant_read_write_data(user_management_lambda)
        self.api_security_table.grant_read_write_data(user_management_lambda)
        self.kms_key.grant_encrypt_decrypt(user_management_lambda)

        # Create a role with a fixed name for the well-known proxy Lambda function
        # noinspection SpellCheckingInspection
        well_known_proxy_role = iam.Role(
            self, 'WellKnownProxyRole',
            role_name=f'WellKnownProxyLambda{region_name}Role',
            assumed_by=iam.ServicePrincipal('lambda.amazonaws.com'),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name('service-role/AWSLambdaBasicExecutionRole')
            ]
        )

        # Create the well-known proxy Lambda function
        # noinspection PyTypeChecker
        well_known_proxy_lambda = aws_lambda.Function(
            self, 'SecurityWellKnownProxyLambda',
            function_name=f'SecurityWellKnownProxy{region_name}Lambda',
            runtime=aws_lambda.Runtime.PYTHON_3_12,
            architecture=aws_lambda.Architecture.ARM_64,
            handler='ogc_landing.proxy.proxy_lambda.lambda_handler',
            code = aws_lambda.Code.from_asset(
                '../../src/proxy_lambda',
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
            ),
            timeout=Duration.seconds(29),
            role=well_known_proxy_role  # Use the fixed role
        )

        # Configure CloudWatch logs with 7-day retention policy
        logs.LogRetention(
            self, 'WellKnownProxyLambdaLogRetention',
            log_group_name=f'/aws/lambda/{well_known_proxy_lambda.function_name}',
            retention=logs.RetentionDays.ONE_WEEK
        )

        # Create API Gateway
        self.api = api_gateway.RestApi(
            self, 'MyApiSecurity',
            rest_api_name=f'API Security Service in {self.region}',  # Region-specific name
            description='Security services for APIs.',
        )

        # Create custom domain name for API Gateway
        # noinspection PyTypeChecker
        domain_name = api_gateway.DomainName(
            self, 'SecurityApiDomain',
            domain_name='security.i7es.click',
            certificate=self.certificate,
            endpoint_type=api_gateway.EndpointType.REGIONAL,
            security_policy=api_gateway.SecurityPolicy.TLS_1_2
        )

        # Add base path mapping to connect the domain name to the API
        domain_name.add_base_path_mapping(
            self.api,
            base_path=''  # Empty string means root path
        )

        # Create Route53 record with latency routing policy
        route53.ARecord(
            self, 'SecurityApiAliasRecordA',
            zone=hosted_zone,
            record_name='',  # Empty string means apex domain
            target=route53.RecordTarget.from_alias(
                targets.ApiGatewayDomain(domain_name)
            ),
            region=self.region
        )

        route53.AaaaRecord(
            self, 'SecurityApiAliasRecordAaaa',
            zone=hosted_zone,
            record_name='',  # Empty string means apex domain
            target=route53.RecordTarget.from_alias(
                targets.ApiGatewayDomain(domain_name)
            ),
            region=self.region
        )

        # Configure 401 Gateway Response to include WWW-Authenticate header
        # noinspection PyTypeChecker
        self.api.add_gateway_response(
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
        index_resource = self.api.root.add_resource('index.html')
        well_known_resource = self.api.root.add_resource('.well-known')
        well_known_name_resource = well_known_resource.add_resource('api-catalog')
        conformance_resource = self.api.root.add_resource('conformance')
        conformance_alias_resource = conformance_resource.add_resource('{conformance_alias}')
        api_resource = self.api.root.add_resource('api')
        documentation_resource = self.api.root.add_resource('documentation')
        register_resource = self.api.root.add_resource('register')
        registration_id_resource = self.api.root.add_resource('registration-id')
        public_key_resource = self.api.root.add_resource('public-key')
        user_management_resource = self.api.root.add_resource('user-management')
        decision_resource = self.api.root.add_resource('decision')

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
        self.api.root.add_method(
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

        # Add GET method for registration ID resource
        # noinspection PyTypeChecker
        registration_id_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(register_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE,
        )

        # Add GET method for public key resource
        # noinspection PyTypeChecker
        public_key_resource.add_method(
            'GET',
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

        # Add DELETE method to user management endpoint
        # noinspection PyTypeChecker
        user_management_resource.add_method(
            'DELETE',
            api_gateway.LambdaIntegration(user_management_lambda),
            authorizer=authorizer,
            authorization_type=api_gateway.AuthorizationType.CUSTOM,
        )

        # Add POST method to decision endpoint without an authorizer
        # noinspection PyTypeChecker
        decision_resource.add_method(
            'POST',
            api_gateway.LambdaIntegration(authorizer_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE,
        )
