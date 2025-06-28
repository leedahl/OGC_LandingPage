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
    aws_logs as logs
)
from aws_cdk.aws_apigateway import ResponseType
from constructs import Construct


class MyApiGatewayStack(Stack):
    def __init__(
            self, scope: Construct, construct_id: str, certificate_stack: Stack, production_account: str,
            security_account: str, **kwargs
    ) -> None:
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

        # Create S3 bucket for logging
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

        # Create S3 bucket for API backups
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

        # Create the well-known Lambda function
        # noinspection PyTypeChecker
        well_known_lambda = aws_lambda.Function(
            self, 'WellKnownLambda',
            function_name='WellKnownLambda',  # Custom name without stack prefix or random suffix
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

        aws_lambda.CfnPermission(
            self, 'GreetingProxyLambdaInvokeAccess',
            action='lambda:InvokeFunction',
            function_name=well_known_lambda.function_arn,
            principal=f'arn:aws:iam::{production_account}:role/WellKnownProxyLambdaRole'
        )

        aws_lambda.CfnPermission(
            self, 'SecurityProxyLambdaOhioInvokeAccess',
            action='lambda:InvokeFunction',
            function_name=well_known_lambda.function_arn,
            principal=f'arn:aws:iam::{security_account}:role/WellKnownProxyLambdaOhioRole'
        )

        aws_lambda.CfnPermission(
            self, 'SecurityProxyLambdaVirginiaInvokeAccess',
            action='lambda:InvokeFunction',
            function_name=well_known_lambda.function_arn,
            principal=f'arn:aws:iam::{security_account}:role/WellKnownProxyLambdaVirginiaRole'
        )

        aws_lambda.CfnPermission(
            self, 'SecurityProxyLambdaNorthCaliforniaInvokeAccess',
            action='lambda:InvokeFunction',
            function_name=well_known_lambda.function_arn,
            principal=f'arn:aws:iam::{security_account}:role/WellKnownProxyLambdaNorthCaliforniaRole'
        )

        aws_lambda.CfnPermission(
            self, 'SecurityProxyLambdaOregonInvokeAccess',
            action='lambda:InvokeFunction',
            function_name=well_known_lambda.function_arn,
            principal=f'arn:aws:iam::{security_account}:role/WellKnownProxyLambdaOregonRole'
        )

        aws_lambda.CfnPermission(
            self, 'SecurityProxyLambdaIrelandInvokeAccess',
            action='lambda:InvokeFunction',
            function_name=well_known_lambda.function_arn,
            principal=f'arn:aws:iam::{security_account}:role/WellKnownProxyLambdaIrelandRole'
        )

        aws_lambda.CfnPermission(
            self, 'SecurityProxyLambdaFrankfurtInvokeAccess',
            action='lambda:InvokeFunction',
            function_name=well_known_lambda.function_arn,
            principal=f'arn:aws:iam::{security_account}:role/WellKnownProxyLambdaFrankfurtRole'
        )

        # Create the OpenAPI Lambda function
        # noinspection PyTypeChecker
        openapi_lambda = aws_lambda.Function(
            self, 'OpenApiLambda',
            function_name='OpenApiLambda',  # Custom name without stack prefix or random suffix
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

        # Create the Backup Lambda function
        # noinspection PyTypeChecker
        backup_lambda = aws_lambda.Function(
            self, 'APIBackupLambda',
            function_name='APIBackupLambda',  # Custom name without stack prefix or random suffix
            runtime=aws_lambda.Runtime.PYTHON_3_12,
            architecture=aws_lambda.Architecture.ARM_64,
            handler='ogc_landing.backup.backup_lambda.lambda_handler',
            code=aws_lambda.Code.from_asset('../../src/backup_lambda'),
            timeout=Duration.seconds(29),
            environment={
                'BACKUP_BUCKET_NAME': backup_bucket.bucket_name
            }
        )

        # Configure CloudWatch logs with 7-day retention policy
        logs.LogRetention(
            self, 'BackupLambdaLogRetention',
            log_group_name=f'/aws/lambda/{backup_lambda.function_name}',
            retention=logs.RetentionDays.ONE_WEEK
        )

        # Grant the Backup Lambda permission to access DynamoDB tables
        api_catalog.grant_read_data(backup_lambda)
        api_conformance.grant_read_data(backup_lambda)
        openapi_documents.grant_read_data(backup_lambda)
        openapi_servers.grant_read_data(backup_lambda)
        openapi_paths.grant_read_data(backup_lambda)
        openapi_operations.grant_read_data(backup_lambda)
        openapi_components.grant_read_data(backup_lambda)
        openapi_tags.grant_read_data(backup_lambda)
        openapi_security_schemes.grant_read_data(backup_lambda)

        # Grant the Backup Lambda permission to read and write to the S3 bucket
        backup_bucket.grant_read_write(backup_lambda)

        # Create a role with a fixed name for the well-known proxy Lambda function
        authorizer_proxy_role = iam.Role(
            self, 'APIAuthorizerProxyRole',
            role_name='APIAuthorizerProxyLambdaRole',  # Fixed name without stack prefix or random suffix
            assumed_by=iam.ServicePrincipal('lambda.amazonaws.com'),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name('service-role/AWSLambdaBasicExecutionRole')
            ]
        )

        # Grant the authorizer proxy Lambda permission to invoke the authorizer Lambda in the security account
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
            self, 'APIAuthorizerProxyLambda',
            function_name='APIAuthorizerProxyLambda',  # Custom name without stack prefix or random suffix
            runtime=aws_lambda.Runtime.PYTHON_3_12,
            architecture=aws_lambda.Architecture.ARM_64,
            handler='ogc_landing.proxy.proxy_lambda.lambda_handler',
            code=aws_lambda.Code.from_asset('../../src/proxy_lambda'),
            timeout=Duration.seconds(29),
            role=authorizer_proxy_role,  # Use the fixed role
            environment={
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
            api_gateway.LambdaIntegration(
                well_known_lambda
            ),
            authorization_type=api_gateway.AuthorizationType.NONE,
        )

        # Add POST method to upload OpenAPI documents
        # noinspection PyTypeChecker
        openapi_resource.add_method(
            'POST',
            api_gateway.LambdaIntegration(
                openapi_lambda
            ),
            authorizer=authorizer,
            authorization_type=api_gateway.AuthorizationType.CUSTOM,
        )

        # Add GET method to retrieve OpenAPI documents by API ID
        # noinspection PyTypeChecker
        openapi_api_id_resource.add_method(
            'POST',
            api_gateway.LambdaIntegration(
                openapi_lambda
            ),
            authorizer=authorizer,
            authorization_type=api_gateway.AuthorizationType.CUSTOM,
        )

        # Add POST method to trigger backup
        # noinspection PyTypeChecker
        backup_resource.add_method(
            'POST',
            api_gateway.LambdaIntegration(
                backup_lambda
            ),
            authorizer=authorizer,
            authorization_type=api_gateway.AuthorizationType.CUSTOM,
        )

        # Add POST method to restore backup (default to most recent)
        # noinspection PyTypeChecker
        restore_resource.add_method(
            'POST',
            api_gateway.LambdaIntegration(
                backup_lambda
            ),
            authorizer=authorizer,
            authorization_type=api_gateway.AuthorizationType.CUSTOM,
        )

        # Add POST method to restore specific backup by ID
        # noinspection PyTypeChecker
        restore_id_resource.add_method(
            'POST',
            api_gateway.LambdaIntegration(
                backup_lambda
            ),
            authorizer=authorizer,
            authorization_type=api_gateway.AuthorizationType.CUSTOM,
        )

        # Add DELETE method to delete specific backup by ID
        # noinspection PyTypeChecker
        delete_id_resource.add_method(
            'DELETE',
            api_gateway.LambdaIntegration(
                backup_lambda
            ),
            authorizer=authorizer,
            authorization_type=api_gateway.AuthorizationType.CUSTOM,
        )

        # Add GET method to list all backups
        # noinspection PyTypeChecker
        list_resource.add_method(
            'GET',
            api_gateway.LambdaIntegration(
                backup_lambda
            ),
            authorizer=authorizer,
            authorization_type=api_gateway.AuthorizationType.CUSTOM,
        )

        # Look up the hosted zone name
        hosted_zone = route53.HostedZone.from_lookup(
            self, 'HostedZone',
            domain_name='portfolio.i7es.click'
        )

        # Create custom domain for API Gateway
        # noinspection PyTypeChecker,PyUnresolvedReferences
        domain = api_gateway.DomainName(
            self, 'PortfolioDomain',
            domain_name='portfolio.i7es.click',
            certificate=certificate_stack.certificate,
            endpoint_type=api_gateway.EndpointType.EDGE
        )

        # Map the custom domain to the API
        domain.add_base_path_mapping(api, stage=api.deployment_stage)

        # Create DNS record to point to the API Gateway domain
        route53.ARecord(
            self, 'PortfolioApiGatewayAliasRecordA',
            zone=hosted_zone,
            record_name='',
            target=route53.RecordTarget.from_alias(
                targets.ApiGatewayDomain(domain)
            )
        )

        route53.AaaaRecord(
            self, 'PortfolioApiGatewayAliasRecordAaaa',
            zone=hosted_zone,
            record_name='',
            target=route53.RecordTarget.from_alias(
                targets.ApiGatewayDomain(domain)
            )
        )
