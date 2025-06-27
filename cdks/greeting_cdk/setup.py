# Copyright (c) 2025
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import setuptools

with open("../../README.md") as fp:
    long_description = fp.read()

setuptools.setup(
    name="security_stacks_cdk",
    version="0.1.0",
    description="AWS CDK app for My Landing API Gateway",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Michael Leedahl",
    package_dir={"": "."},
    packages=setuptools.find_packages(),
    install_requires=[
        "aws-apis_cdk-lib>=2.0.0",
        "constructs>=10.0.0",
    ],
    python_requires=">=3.12",
)