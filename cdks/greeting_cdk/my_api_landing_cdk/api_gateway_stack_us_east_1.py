from aws_cdk import (
    Stack,
    aws_certificatemanager as acm,
    aws_route53 as route53
)
from constructs import Construct


class MyCertificateStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Look up the hosted zone name
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
