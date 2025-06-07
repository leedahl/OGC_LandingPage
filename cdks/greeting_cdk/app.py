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