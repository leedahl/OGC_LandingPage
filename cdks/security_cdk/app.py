#!/usr/bin/env python3
# Copyright (c) 2025
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from os import environ
from shutil import copytree, rmtree
from aws_cdk import App, Environment
from my_ap_security_cdk.api_gateway_stack import MySecurityApiGatewayStack
from my_ap_security_cdk.api_gateway_stack_us_east_1 import MySecurityCertificateStack

app = App()

deploy_account = environ.get('SECURITY_ACCOUNT')
production_account = environ.get('PRODUCTION_ACCOUNT')

# Define the environment for deployment of Certificates
env_us_east_1 = Environment(account=deploy_account, region="us-east-1")

# Create Certificates
cert_stack = MySecurityCertificateStack(
    app, "MySecurityCertificateStack", cross_region_references=True, env=env_us_east_1
)

# Define the environment for deployment of APIs
env = Environment(account=deploy_account, region="us-east-2")

copytree(
    '../../src/security_library/ogc_landing/security/',
    '../../src/registration_lambda/ogc_landing/security/'
)
copytree(
    '../../src/security_library/ogc_landing/security/',
    '../../src/user_management_lambda/ogc_landing/security/'
)

# Create the API Gateway stack
MySecurityApiGatewayStack(
    app, "MyApiSecurityStack", cross_region_references=True, certificate_stack=cert_stack,
     production_account=production_account, env=env
)

app.synth()

rmtree('../../src/registration_lambda/ogc_landing/security')
rmtree('../../src/user_management_lambda/ogc_landing/security')
