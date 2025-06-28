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
    Duration,
    RemovalPolicy,
    aws_iam as iam,
    aws_s3 as s3,
    aws_logs as logs,
    aws_certificatemanager as acm
)
from aws_cdk.aws_apigateway import ResponseType
from constructs import Construct


class ApiGatewayRegionalStack(Stack):
    def __init__(
            self, scope: Construct, construct_id: str, 
            api_catalog: dynamodb.Table,
            api_conformance: dynamodb.Table,
            openapi_documents: dynamodb.Table,
            openapi_servers: dynamodb.Table,
            openapi_paths: dynamodb.Table,
            openapi_operations: dynamodb.Table,
            openapi_components: dynamodb.Table,
            openapi_tags: dynamodb.Table,
            openapi_security_schemes: dynamodb.Table,
            security_account: str,
            region_name: str,
            **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Store the DynamoDB tables
        self.api_catalog = api_catalog
        self.api_conformance = api_conformance
        self.openapi_documents = openapi_documents
        self.openapi_servers = openapi_servers
        self.openapi_paths = openapi_paths
        self.openapi_operations = openapi_operations
        self.openapi_components = openapi_components
        self.openapi_tags = openapi_tags
        self.openapi_security_schemes = openapi_security_schemes

        # Only create the logging and backup buckets in the Ohio region
        if region_name == 'Ohio':
            # Create S3 bucket for logging with Ohio region-specific name
            # noinspection PyTypeChecker
            logging_bucket = s3.Bucket(
                self, 'ApiLoggingBucket',
                bucket_name=f'api-logging-ohio-{self.account}',
                encryption=s3.BucketEncryption.S3_MANAGED,
                versioned=True,
                block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                removal_policy=RemovalPolicy.RETAIN,  # Keep the bucket even if the stack is deleted
                lifecycle_rules=[
                    s3.LifecycleRule(
                        expiration=Duration.days(7),  # Retain data for only 7 days
                        enabled=True
                    )
                ]
            )

            # Create S3 bucket for API backups with Ohio region-specific name
            # noinspection PyTypeChecker
            backup_bucket = s3.Bucket(
                self, 'ApiBackupBucket',
                bucket_name=f'api-backup-ohio-{self.account}',
                encryption=s3.BucketEncryption.S3_MANAGED,
                versioned=True,
                block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                removal_policy=RemovalPolicy.RETAIN,  # Keep the bucket even if the stack is deleted
                server_access_logs_bucket=logging_bucket,
                server_access_logs_prefix='api-backup-logs/'
            )

        else:
            # For non-Ohio regions, import the buckets from the Ohio region
            backup_bucket = s3.Bucket.from_bucket_name(
                self, 'ApiBackupBucket',
                bucket_name=f'api-backup-ohio-{self.account}'
            )

        # Create the well-known Lambda function with region-specific name
        # noinspection PyTypeChecker
        well_known_lambda = aws_lambda.Function(
            self, 'WellKnownLambda',
            function_name=f'WellKnown{region_name}Lambda',
            runtime=aws_lambda.Runtime.PYTHON_3_12,
            architecture=aws_lambda.Architecture.ARM_64,
            handler='ogc_landing.well_known.well_known_lambda.lambda_handler',
            code=aws_lambda.Code.from_asset('../../src/well_known_lambda'),
            timeout=Duration.seconds(29)
        )

        # Configure CloudWatch logs with 7-day retention policy
        logs.LogRetention(
            self, 'WellKnownLambdaLogRetention',
            log_group_name=f'/aws/lambda/{well_known_lambda.function_name}',
            retention=logs.RetentionDays.ONE_WEEK
        )

        # Add permissions for the well-known Lambda to be invoked by the security proxy in the same region
        aws_lambda.CfnPermission(
            self, f'SecurityProxyLambda{region_name}InvokeAccess',
            action='lambda:InvokeFunction',
            function_name=well_known_lambda.function_arn,
            principal=f'arn:aws:iam::{security_account}:role/WellKnownProxyLambda{region_name}Role'
        )

        # Create the OpenAPI Lambda function with region-specific name
        # noinspection PyTypeChecker
        openapi_lambda = aws_lambda.Function(
            self, 'OpenApiLambda',
            function_name=f'OpenApi{region_name}Lambda',
            runtime=aws_lambda.Runtime.PYTHON_3_12,
            architecture=aws_lambda.Architecture.ARM_64,
            handler='ogc_landing.openapi.openapi_lambda.lambda_handler',
            code=aws_lambda.Code.from_asset('../../src/openapi_lambda'),
            timeout=Duration.seconds(29)
        )

        # Configure CloudWatch logs with 7-day retention policy
        logs.LogRetention(
            self, 'OpenApiLambdaLogRetention',
            log_group_name=f'/aws/lambda/{openapi_lambda.function_name}',
            retention=logs.RetentionDays.ONE_WEEK
        )

        # Grant the WellKnown Lambda permission to access DynamoDB
        self.api_catalog.grant_read_data(well_known_lambda)
        self.api_conformance.grant_read_data(well_known_lambda)

        # Grant the WellKnown Lambda permission to access OpenAPI DynamoDB tables
        self.openapi_documents.grant_read_data(well_known_lambda)
        self.openapi_servers.grant_read_data(well_known_lambda)
        self.openapi_paths.grant_read_data(well_known_lambda)
        self.openapi_operations.grant_read_data(well_known_lambda)
        self.openapi_components.grant_read_data(well_known_lambda)
        self.openapi_tags.grant_read_data(well_known_lambda)
        self.openapi_security_schemes.grant_read_data(well_known_lambda)

        # Grant the OpenAPI Lambda permission to access DynamoDB
        self.api_catalog.grant_read_write_data(openapi_lambda)

        # Grant the OpenAPI Lambda permission to access OpenAPI DynamoDB tables
        self.openapi_documents.grant_read_write_data(openapi_lambda)
        self.openapi_servers.grant_read_write_data(openapi_lambda)
        self.openapi_paths.grant_read_write_data(openapi_lambda)
        self.openapi_operations.grant_read_write_data(openapi_lambda)
        self.openapi_components.grant_read_write_data(openapi_lambda)
        self.openapi_tags.grant_read_write_data(openapi_lambda)
        self.openapi_security_schemes.grant_read_write_data(openapi_lambda)

        # Create the Backup Lambda function with region-specific name
        # noinspection PyTypeChecker
        backup_lambda = aws_lambda.Function(
            self, 'APIBackupLambda',
            function_name=f'APIBackup{region_name}Lambda',
            runtime=aws_lambda.Runtime.PYTHON_3_12,
            architecture=aws_lambda.Architecture.ARM_64,
            handler='ogc_landing.backup.backup_lambda.lambda_handler',
            code=aws_lambda.Code.from_asset('../../src/backup_lambda'),
            timeout=Duration.seconds(29),
            environment={
                'BACKUP_BUCKET_NAME': f'api-backup-ohio-{self.account}'
            }
        )

        # Configure CloudWatch logs with 7-day retention policy
        logs.LogRetention(
            self, 'BackupLambdaLogRetention',
            log_group_name=f'/aws/lambda/{backup_lambda.function_name}',
            retention=logs.RetentionDays.ONE_WEEK
        )

        # Grant the Backup Lambda permission to access DynamoDB tables
        self.api_catalog.grant_read_write_data(backup_lambda)
        self.api_conformance.grant_read_write_data(backup_lambda)
        self.openapi_documents.grant_read_write_data(backup_lambda)
        self.openapi_servers.grant_read_write_data(backup_lambda)
        self.openapi_paths.grant_read_write_data(backup_lambda)
        self.openapi_operations.grant_read_write_data(backup_lambda)
        self.openapi_components.grant_read_write_data(backup_lambda)
        self.openapi_tags.grant_read_write_data(backup_lambda)
        self.openapi_security_schemes.grant_read_write_data(backup_lambda)

        # Grant the Backup Lambda permission to read and write to the S3 bucket
        backup_bucket.grant_read_write(backup_lambda)

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

        # Grant the authorizer proxy Lambda permission to invoke the authorizer Lambda in the security account
        authorizer_proxy_role.add_to_policy(
            iam.PolicyStatement(
                actions=['lambda:InvokeFunction'],
                resources=[f'arn:aws:lambda:{self.region}:{security_account}:function:Authorizer{region_name}Lambda'],
                effect=iam.Effect.ALLOW
            )
        )

        # Create the Authorizer Lambda function with region-specific name
        # noinspection PyTypeChecker
        authorizer_lambda = aws_lambda.Function(
            self, 'APIAuthorizerProxyLambda',
            function_name=f'APIAuthorizerProxy{region_name}Lambda',
            runtime=aws_lambda.Runtime.PYTHON_3_12,
            architecture=aws_lambda.Architecture.ARM_64,
            handler='ogc_landing.proxy.proxy_lambda.lambda_handler',
            code=aws_lambda.Code.from_asset('../../src/proxy_lambda'),
            timeout=Duration.seconds(29),
            role=authorizer_proxy_role,  # Use the fixed role
            environment={
                'TARGET_ACCOUNT_ID': security_account,
                'TARGET_FUNCTION_NAME': f'Authorizer{region_name}Lambda',
                'TARGET_REGION': self.region
            }
        )

        # Configure CloudWatch logs with 7-day retention policy
        logs.LogRetention(
            self, 'AuthorizerLambdaLogRetention',
            log_group_name=f'/aws/lambda/{authorizer_lambda.function_name}',
            retention=logs.RetentionDays.ONE_WEEK
        )

        # Create custom domain name and Route53 record
        # Look up the hosted zone
        hosted_zone = route53.HostedZone.from_lookup(
            self, 'HostedZone',
            domain_name='portfolio.i7es.click'
        )

        # Create ACM certificate for the domain
        self.certificate = acm.Certificate(
            self, 'PortfolioCertificate',
            domain_name='portfolio.i7es.click',
            validation=acm.CertificateValidation.from_dns(hosted_zone)
        )

        # Create API Gateway with region-specific name
        api = api_gateway.RestApi(
            self, 'MyApis',
            rest_api_name=f'My APIs in {region_name}',
            description=f'Landing Page for My APIs in {region_name}.',
        )

        # Configure 401 Gateway Response to include WWW-Authenticate header
        # noinspection PyTypeChecker
        api.add_gateway_response(
            'Unauthorized',
            type=ResponseType.UNAUTHORIZED,
            response_headers={
                'WWW-Authenticate': "'Basic realm=\"Portfolio Management API\"'"
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

        # Create data_management resource and sub-resources
        data_management_resource = api.root.add_resource('data_management')
        backup_resource = data_management_resource.add_resource('backup')
        restore_resource = data_management_resource.add_resource('restore')
        restore_id_resource = restore_resource.add_resource('{backup_id}')
        delete_resource = data_management_resource.add_resource('delete')
        delete_id_resource = delete_resource.add_resource('{backup_id}')
        list_resource = data_management_resource.add_resource('list')

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

        # Add Get method with index.html endpoint.
        # noinspection PyTypeChecker
        index_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE,
        )

        # Add Get method with root endpoint.
        # noinspection PyTypeChecker
        api.root.add_method(
            'GET',
            api_gateway.LambdaIntegration(well_known_lambda),
            authorization_type=api_gateway.AuthorizationType.NONE,
        )

        # Add Get method with OpenAPI endpoint.
        # noinspection PyTypeChecker
        openapi_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(openapi_lambda),
            authorization_type=api_gateway.AuthorizationType.CUSTOM,
            authorizer=authorizer
        )

        # Add Get method with OpenAPI API ID endpoint.
        # noinspection PyTypeChecker
        openapi_api_id_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(openapi_lambda),
            authorization_type=api_gateway.AuthorizationType.CUSTOM,
            authorizer=authorizer
        )

        # Add Post method with OpenAPI API ID endpoint.
        # noinspection PyTypeChecker
        openapi_api_id_resource.add_method(
            'POST',
            api_gateway.LambdaIntegration(openapi_lambda),
            authorization_type=api_gateway.AuthorizationType.CUSTOM,
            authorizer=authorizer
        )

        # Add Put method with OpenAPI API ID endpoint.
        # noinspection PyTypeChecker
        openapi_api_id_resource.add_method(
            'PUT',
            api_gateway.LambdaIntegration(openapi_lambda),
            authorization_type=api_gateway.AuthorizationType.CUSTOM,
            authorizer=authorizer
        )

        # Add Delete method with OpenAPI API ID endpoint.
        # noinspection PyTypeChecker
        openapi_api_id_resource.add_method(
            'DELETE',
            api_gateway.LambdaIntegration(openapi_lambda),
            authorization_type=api_gateway.AuthorizationType.CUSTOM,
            authorizer=authorizer
        )

        # Add Post method with backup endpoint.
        # noinspection PyTypeChecker
        backup_resource.add_method(
            'PUT',
            api_gateway.LambdaIntegration(backup_lambda),
            authorization_type=api_gateway.AuthorizationType.CUSTOM,
            authorizer=authorizer
        )

        # Add Get method with restore endpoint.
        # noinspection PyTypeChecker
        restore_resource.add_method(
            'PUT',
            api_gateway.LambdaIntegration(backup_lambda),
            authorization_type=api_gateway.AuthorizationType.CUSTOM,
            authorizer=authorizer
        )

        # Add Post method with restore ID endpoint.
        # noinspection PyTypeChecker
        restore_id_resource.add_method(
            'PUT',
            api_gateway.LambdaIntegration(backup_lambda),
            authorization_type=api_gateway.AuthorizationType.CUSTOM,
            authorizer=authorizer
        )

        # Add Delete method with delete ID endpoint.
        # noinspection PyTypeChecker
        delete_id_resource.add_method(
            'DELETE',
            api_gateway.LambdaIntegration(backup_lambda),
            authorization_type=api_gateway.AuthorizationType.CUSTOM,
            authorizer=authorizer
        )

        # Add Get method with list endpoint.
        # noinspection PyTypeChecker
        list_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(backup_lambda),
            authorization_type=api_gateway.AuthorizationType.CUSTOM,
            authorizer=authorizer
        )

        # Create custom domain name for API Gateway
        # noinspection PyTypeChecker
        domain_name = api_gateway.DomainName(
            self, 'ApiDomain',
            domain_name='portfolio.i7es.click',
            certificate=self.certificate,
            endpoint_type=api_gateway.EndpointType.REGIONAL,
            security_policy=api_gateway.SecurityPolicy.TLS_1_2
        )

        # Add base path mapping to connect the domain name to the API
        domain_name.add_base_path_mapping(
            api,
            base_path=''  # Empty string means root path
        )

        route53.ARecord(
            self, 'ApiAliasRecordA',
            zone=hosted_zone,
            record_name='',  # Empty string means apex domain
            target=route53.RecordTarget.from_alias(
                targets.ApiGatewayDomain(domain_name)
            ),
            region=self.region
        )

        route53.AaaaRecord(
            self, 'ApiAliasRecordAaaa',
            zone=hosted_zone,
            record_name='',  # Empty string means apex domain
            target=route53.RecordTarget.from_alias(
                targets.ApiGatewayDomain(domain_name)
            ),
            region=self.region
        )
