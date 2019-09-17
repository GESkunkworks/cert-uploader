from datetime import datetime, timedelta

import boto3
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.x509 import NameOID
from moto import mock_ec2


def generate_certificate(common_name, subject_alt_names=(), issuer=None):
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
        backend=default_backend()
    )

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'Georgia'),
        x509.NameAttribute(NameOID.LOCALITY_NAME, 'Atlanta'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'My Company'),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.utcnow() - timedelta(days=1)

    cert = x509.CertificateBuilder(). \
        subject_name(subject). \
        issuer_name(issuer or subject). \
        public_key(key.public_key()). \
        serial_number(x509.random_serial_number()). \
        not_valid_before(now). \
        not_valid_after(now + timedelta(days=5))

    if subject_alt_names:
        cert = cert.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(name) for name in subject_alt_names
            ]),
            critical=False,
        )

    return cert, key


def create_certificate_chain(common_name, root_name='Root CA', subject_alt_names=('test.com',)):
    # Generate root certificate
    ca_cert, ca_key = generate_certificate(root_name)
    ca_cert = ca_cert.sign(ca_key, hashes.SHA256(), default_backend())

    # Generate certificate
    cert, key = generate_certificate(common_name, subject_alt_names, issuer=ca_cert.subject)
    cert = cert.sign(ca_key, hashes.SHA256(), default_backend())

    return cert, key, ca_cert, ca_key


def generate_pem_data(cert, key, ca_cert=None):
    certificate = cert.public_bytes(serialization.Encoding.PEM)
    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=NoEncryption()
    )

    ca_certificate = None
    if ca_cert:
        ca_certificate = ca_cert.public_bytes(serialization.Encoding.PEM)

    return certificate, private_key, ca_certificate


@mock_ec2
def create_vpc_resources():
    ec2 = boto3.client('ec2')
    vpc = ec2.create_vpc(CidrBlock='10.0.0.0/27')
    subnet = ec2.create_subnet(VpcId=vpc['Vpc']['VpcId'], CidrBlock='10.0.0.0/28')
    return vpc, subnet


def create_alb(name, subnet):
    elbv2 = boto3.client('elbv2')
    return elbv2.create_load_balancer(
        Name=name,
        Subnets=[subnet['Subnet']['SubnetId']],
        SecurityGroups=['dummy'],
        Scheme='internal'
    )['LoadBalancers'][0]


def create_elb(name, subnet, certificate_arn='fake-certificate'):
    elb = boto3.client('elb')
    return elb.create_load_balancer(
        LoadBalancerName=name,
        Listeners=[
            {
                'Protocol': 'HTTP',
                'LoadBalancerPort': 80,
                'InstancePort': 80
            },
            {
                'Protocol': 'HTTPS',
                'LoadBalancerPort': 443,
                'InstancePort': 443,
                'SSLCertificateId': certificate_arn
            }
        ],
        AvailabilityZones=[],
        Scheme='HTTP',
        Subnets=[subnet['Subnet']['SubnetId']]
    )


def create_default_listeners(arn, certificate_arn='dummy'):
    elbv2 = boto3.client('elbv2')
    http_listener = elbv2.create_listener(
        LoadBalancerArn=arn,
        Protocol='HTTP',
        Port=80,
        DefaultActions=[]
    )['Listeners'][0]

    # Create HTTPS listener
    https_listener = elbv2.create_listener(
        LoadBalancerArn=arn,
        Protocol='HTTPS',
        Port=443,
        DefaultActions=[],
        Certificates=[{'CertificateArn': certificate_arn}]
    )['Listeners'][0]

    return http_listener, https_listener
