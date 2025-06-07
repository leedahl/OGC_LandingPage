#!/usr/bin/env python3

from aws_cdk import App, Environment

from my_api_landing_cdk.api_gateway_stack import MyApiGatewayStack
from my_api_landing_cdk.api_gateway_stack_us_east_1 import MyCertificateStack

app = App()

# Define the environment for deployment of Certificates
env_us_east_1 = Environment(account="911737211406", region="us-east-1")

# Create Certificates
cert_stack = MyCertificateStack(
    app, "GreetingCertificateStack", cross_region_references=True, env=env_us_east_1
)

# Define the environment for deployment of APIs
env = Environment(account="911737211406", region="us-east-2")

# Create the API Gateway stack
MyApiGatewayStack(
    app, "GreetingApiStack", cross_region_references=True, certificate_stack=cert_stack, env=env
)

app.synth()