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
    aws_kms as kms,
    aws_iam as iam,
)
from constructs import Construct


class KmsReplicaStack(Stack):
    """
    Stack for creating KMS replica keys in specified regions.
    """
    def __init__(self, scope: Construct, construct_id: str, primary_key_arn: str, **kwargs) -> None:
        """
        Initialize the KMS Replica Stack.
        
        Args:
            scope: The scope in which to define this construct.
            construct_id: The ID of the construct.
            primary_key_arn: The ARN of the primary KMS key to replicate.
            **kwargs: Additional keyword arguments.
        """
        super().__init__(scope, construct_id, **kwargs)

        key_policy = iam.PolicyDocument()
        key_policy.add_statements(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            principals=[iam.AccountPrincipal(self.account)],
            actions=["kms:*"],
            resources=['*']
        ))

        # Create a replica of the primary KMS key in this region
        self.replica_key = kms.CfnReplicaKey(
            self, 'NewSecurityUserStoreReplicaKey',
            primary_key_arn=primary_key_arn,
            key_policy=key_policy,
            description='Replica of the security user store key',
        )

        self.kms_key = kms.Key.from_key_arn(self, 'ReplicaKey', self.replica_key.attr_arn)
        self.kms_key.add_alias('alias/security_user_store_key')