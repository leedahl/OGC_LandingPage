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
    Duration,
    BundlingOptions,
    aws_iam as iam,
    aws_route53 as route53,
    aws_route53_targets as targets,
    aws_certificatemanager as acm,
    aws_kms as kms,
    aws_logs as logs
)
from aws_cdk.aws_apigateway import ResponseType
from aws_cdk.aws_iam import PolicyStatement
from aws_cdk.aws_kms import IKey
from constructs import Construct


class CARegionalApiGatewayStack(Stack):
    def __init__(
            self, scope: Construct, construct_id: str, certificate_store_table: dynamodb.Table,
            certificate_metadata_table: dynamodb.Table, primary_kms_key: IKey, region_name: str,
            primary_region: str, **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Store the DynamoDB tables
        self.certificate_store_table = certificate_store_table
        self.certificate_metadata_table = certificate_metadata_table
        self.primary_kms_key = primary_kms_key

        # Create the CSR Lambda function
        # noinspection SpellCheckingInspection
        csr_lambda_role = iam.Role(
            self, 'CSRLambdaRole',
            role_name=f'CSRLambda{region_name}Role',
            assumed_by=iam.ServicePrincipal('lambda.amazonaws.com'),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name('service-role/AWSLambdaBasicExecutionRole')
            ]
        )

        # Grant the CSR Lambda permission to access the DynamoDB tables
        self.certificate_store_table.grant_read_write_data(csr_lambda_role)
        self.certificate_metadata_table.grant_read_write_data(csr_lambda_role)

        if self.region != primary_region:
            # Create a replica of the primary KMS key in this region
            key_policy = iam.PolicyDocument()
            key_policy.add_statements(
                PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    principals=[iam.AccountPrincipal(self.account)],
                    actions=['kms:*'],
                    resources=['*']
                )
            )

            self.replica_key = kms.CfnReplicaKey(
                self, 'CAReplicaKey',
                primary_key_arn=primary_kms_key.key_arn,
                key_policy=key_policy,
                description='Replica of the CA key.',
            )

            self.kms_key = kms.Key.from_key_arn(self, 'ReplicaKey', self.replica_key.attr_arn)
            self.kms_key.add_alias('alias/ca_key')

        else:
            self.kms_key = primary_kms_key

        self.kms_key.grant_encrypt_decrypt(csr_lambda_role)

        # Create a role with a fixed name for the authorizer proxy Lambda function
        # noinspection SpellCheckingInspection
        authorizer_proxy_role = iam.Role(
            self, 'APIAuthorizerProxyRole',
            role_name=f'APIAuthorizerProxy{region_name}LambdaRole',
            assumed_by=iam.ServicePrincipal('lambda.amazonaws.com'),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name('service-role/AWSLambdaBasicExecutionRole')
            ]
        )

        # Create the Authorizer Proxy Lambda function with region-specific name
        # noinspection PyTypeChecker
        authorizer_lambda = aws_lambda.Function(
            self, 'APIAuthorizerProxyLambda',
            function_name=f'APIAuthorizerProxy{region_name}Lambda',
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
            role=authorizer_proxy_role  # Use the fixed role
        )

        # Configure CloudWatch logs with 7-day retention policy
        logs.LogRetention(
            self, 'AuthorizerLambdaLogRetention',
            log_group_name=f'/aws/lambda/{authorizer_lambda.function_name}',
            retention=logs.RetentionDays.ONE_WEEK
        )

        # Create the CSR Lambda function
        # noinspection PyTypeChecker
        csr_lambda = aws_lambda.Function(
            self, 'CSRLambda',
            function_name=f'CSR{region_name}Lambda',
            runtime=aws_lambda.Runtime.PYTHON_3_12,
            architecture=aws_lambda.Architecture.ARM_64,
            handler='ogc_landing.ca.csr_lambda.lambda_handler',
            code=aws_lambda.Code.from_asset(
                '../../src/csr_lambda',
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
            role=csr_lambda_role,
            environment = {
                'CERTIFICATE_STORE_TABLE': self.certificate_store_table.table_name,
                'CERTIFICATE_METADATA_TABLE': self.certificate_metadata_table.table_name,
                'KEY_ALIAS': 'ca_key'
            }
        )

        # Configure CloudWatch logs with 7-day retention policy
        logs.LogRetention(
            self, 'CSRLambdaLogRetention',
            log_group_name=f'/aws/lambda/{csr_lambda.function_name}',
            retention=logs.RetentionDays.ONE_WEEK
        )

        # Create API Gateway
        self.api = api_gateway.RestApi(
            self, 'CAApi',
            rest_api_name=f'Certificate Authority API - {self.region}',
            description='API for Certificate Authority operations',
        )

        # Configure 401 Gateway Response to include WWW-Authenticate header
        # noinspection PyTypeChecker
        self.api.add_gateway_response(
            'Unauthorized',
            type=ResponseType.UNAUTHORIZED,
            response_headers={
                'WWW-Authenticate': "'Basic realm=\"Certificate Authority API\"'"
            }
        )

        # Create Lambda authorizer
        # noinspection PyTypeChecker
        authorizer = api_gateway.RequestAuthorizer(
            self, 'CAAuthorizer',
            handler=authorizer_lambda,
            identity_sources=[api_gateway.IdentitySource.header('Authorization')],
            results_cache_ttl=Duration.seconds(0)  # Disable caching for testing
        )

        # Create API resources and methods
        csr_resource = self.api.root.add_resource('csr')

        # Add GET method to the CSR endpoint (to display the form)
        # noinspection PyTypeChecker
        csr_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(csr_lambda),
            authorization_type=api_gateway.AuthorizationType.CUSTOM,
            authorizer=authorizer
        )

        # Add POST method to the CSR endpoint (to submit the form)
        # noinspection PyTypeChecker
        csr_resource.add_method(
            'POST',
            api_gateway.LambdaIntegration(csr_lambda),
            authorization_type=api_gateway.AuthorizationType.CUSTOM,
            authorizer=authorizer
        )

        # Add a resource for retrieving a specific CSR by ID
        csr_id_resource = csr_resource.add_resource('{csr_id}')

        # Add GET method to retrieve a CSR as a PEM file
        # noinspection PyTypeChecker
        csr_id_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(csr_lambda),
            authorization_type=api_gateway.AuthorizationType.CUSTOM,
            authorizer=authorizer
        )

        # Add DELETE method to delete a CSR
        # noinspection PyTypeChecker
        csr_id_resource.add_method(
            'DELETE',
            api_gateway.LambdaIntegration(csr_lambda),
            authorization_type=api_gateway.AuthorizationType.CUSTOM,
            authorizer=authorizer
        )

        # Add a resource for retrieving the private key for a specific CSR by ID
        private_key_resource = csr_id_resource.add_resource('private_key')

        # Add GET method to retrieve the private key as a PEM file
        # noinspection PyTypeChecker
        private_key_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(csr_lambda),
            authorization_type=api_gateway.AuthorizationType.CUSTOM,
            authorizer=authorizer
        )

        # Create custom domain name and Route53 record
        # Look up the hosted zone
        hosted_zone = route53.HostedZone.from_lookup(
            self, 'HostedZone',
            domain_name='ca.i7es.click'
        )

        # Create ACM certificate for the domain
        self.certificate = acm.Certificate(
            self, 'CACertificate',
            domain_name='ca.i7es.click',
            validation=acm.CertificateValidation.from_dns(hosted_zone)
        )

        # Create custom domain name for API Gateway
        # noinspection PyTypeChecker
        domain_name = api_gateway.DomainName(
            self, 'CAApiDomain',
            domain_name='ca.i7es.click',
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
            self, 'CAApiAliasRecordA',
            zone=hosted_zone,
            record_name='',  # Empty string means apex domain
            target=route53.RecordTarget.from_alias(
                targets.ApiGatewayDomain(domain_name)
            ),
            region=self.region
        )

        route53.AaaaRecord(
            self, 'CAApiAliasRecordAaaa',
            zone=hosted_zone,
            record_name='',  # Empty string means apex domain
            target=route53.RecordTarget.from_alias(
                targets.ApiGatewayDomain(domain_name)
            ),
            region=self.region
        )
