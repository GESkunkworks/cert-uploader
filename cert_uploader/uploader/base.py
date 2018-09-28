from datetime import datetime

import boto3
import six
from botocore.exceptions import ClientError

from ..exceptions import InvalidProtocolException, ListenerNotFoundException, LoadBalancerNotFoundException, \
    MultipleCertificatesException


class CertificateUploader(object):
    """
    Certificate uploader

    Uploads new certificates and applies them to an ELB
    """

    def __init__(self, profile=None, role=None):
        self.profile = profile
        self.role = role

        # Assume the role if it is specified
        if self.role:
            timestamp = int(datetime.now().timestamp() * 1000000)
            sts = boto3.client('sts')
            response = sts.assume_role(
                RoleArn=self.role,
                RoleSessionName=str(timestamp),
                DurationSeconds=900
            )

            # Create the session with the role's credentials
            self.session = boto3.Session(
                aws_access_key_id=response['Credentials']['AccessKeyId'],
                aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                aws_session_token=response['Credentials']['SessionToken']
            )
        else:
            self.session = boto3.Session(profile_name=profile)

        self._elb_client = self.session.client('elb')
        self._elbv2_client = self.session.client('elbv2')

    def get_server_certificate(self, identifier):
        """
        Get a certificate

        :param str identifier: Certificate identifier
        :return: Certificate information
        :rtype: dict
        """
        raise NotImplementedError

    @staticmethod
    def read_certificate_files(cert_path=None, private_key_path=None, chain_path=None):
        """
        Read data from certificate files.

        :param str cert_path: Path to the certificate file on the local machine
        :param str private_key_path: Path to the private key file on the local machine
        :param str chain_path: Path to the certificate chain file on the local machine
        :return: Tuple of (certificate data, private key data, chain data)
        :rtype: tuple of str
        """

        cert_data = None
        private_key_data = None
        chain_data = None

        if cert_path:
            # Read certificate body
            with open(cert_path, 'r') as f:
                cert_data = f.read()

        if private_key_path:
            # Read private key
            with open(private_key_path, 'r') as f:
                private_key_data = f.read()

        if chain_path:
            # Read certificate chain
            with open(chain_path, 'r') as f:
                chain_data = f.read()

        return cert_data, private_key_data, chain_data

    def upload_certificate(self, cert_data, private_key_data, chain_data, dry_run=False):
        """
        Upload an IAM Server Certificate

        :param str cert_data: Path to the certificate file on the local machine
        :param str private_key_data: Path to the private key file on the local machine
        :param str chain_data: Path to the certificate chain file on the local machine
        :param bool dry_run: Whether to perform a dry run of the operations. Defaults to False.
        :return: Certificate ARN
        :rtype: str
        """
        raise NotImplementedError

    def _get_alb_listeners(self, arn):
        """
        Get all listeners for a particular ALB load balancer

        :param str arn: Load balancer ARN
        :return: List of listeners
        :rtype: list of dict
        """
        listeners = list()
        marker = None

        while True:
            # Fetch the data
            if marker:
                listener_descriptions = self._elbv2_client.describe_listeners(
                    LoadBalancerArn=arn,
                    Marker=marker
                )
            else:
                listener_descriptions = self._elbv2_client.describe_listeners(
                    LoadBalancerArn=arn
                )

            # Add the listeners to the list
            listeners += listener_descriptions['Listeners']

            # Check for the next listener marker
            if listener_descriptions.get('NextMarker'):
                marker = listener_descriptions['NextMarker']
            else:
                break

        return listeners

    def get_load_balancer(self, name):
        """
        Get ELB/ALB information for the name load balancer

        :param name: Load balancer name
        :return: (Load balancer information, Boolean whether the load balancer is an ALB)
        :rtype: (dict, bool)
        :raises: LoadBalancerNotFoundException
        """
        is_alb = False

        try:
            elbs = self._elb_client.describe_load_balancers(LoadBalancerNames=[name])
            lb_descriptions = elbs['LoadBalancerDescriptions']
            lb = lb_descriptions[0]
        except (KeyError, IndexError, ClientError) as e:
            # If this is a ClientError, only catch LoadBalancerNotFound exceptions
            if isinstance(e, ClientError):
                if e.response['Error']['Code'] != 'LoadBalancerNotFound':
                    raise

            # If an ELB couldn't be found, look for an ALB
            try:
                albs = self._elbv2_client.describe_load_balancers(Names=[name])
                lb_descriptions = albs['LoadBalancers']
                lb = lb_descriptions[0]
                is_alb = True
            except (KeyError, IndexError, ClientError):
                # If this is a ClientError, only catch LoadBalancerNotFound exceptions
                if isinstance(e, ClientError):
                    if e.response['Error']['Code'] != 'LoadBalancerNotFound':
                        raise

                raise LoadBalancerNotFoundException('Load balancer %s could not be found' % name)

        return lb, is_alb

    def assign_certificate(self, lb_name, arn, lb_port=443, dry_run=False):
        """
        Assign a certificate to an ELB

        :param str lb_name: ELB name
        :param str arn: Certificate ARN
        :param int lb_port: Load balancer listener port that the certificate will be assigned to
        :param bool dry_run: Whether to perform a dry run of the operations. Defaults to False.
        :return: Response
        :rtype: dict
        """
        # Check that this is a valid ELB
        lb, is_alb = self.get_load_balancer(lb_name)

        # Validate the ALB listener
        listener = None
        if is_alb:
            # Get listeners
            listeners = self._get_alb_listeners(lb['LoadBalancerArn'])

            # Find the desired listener using the port
            for item in listeners:
                if item['Port'] == lb_port:
                    listener = item
                    break

            # Throw error if listener could not be found
            if not listener:
                raise ListenerNotFoundException('Could not find a listener for port %d' % lb_port)

            # Validate the protocol is HTTPS
            if listener['Protocol'] != 'HTTPS':
                raise InvalidProtocolException('Port %s is not a HTTPS listener' % lb_port)

            # Check if there is more than one certificate on the listener
            certs = listener.get('Certificates', [])
            if len(certs) > 1:
                raise MultipleCertificatesException(
                    'There is more than one certificate on the desired listener. This operation is not '
                    'currently supported by cert-uploader and must be performed manually.'
                )

            # Save the existing certificate
            existing_cert = certs[0]['CertificateArn']
        else:
            # Look up the existing certificate
            listener = None
            for item in lb['ListenerDescriptions']:
                if item['Listener']['LoadBalancerPort'] == lb_port:
                    listener = item['Listener']
                    break

            # Throw error if listener could not be found
            if not listener:
                raise ListenerNotFoundException('Could not find a listener for port %d' % lb_port)

            # Validate the protocol is HTTPS
            if listener['Protocol'] != 'HTTPS':
                raise InvalidProtocolException('Port %s is not a HTTPS listener' % lb_port)

            # Save the existing certificate
            existing_cert = listener['SSLCertificateId']

        if not dry_run:
            print('Replacing certificate %(existing_cert_arn)s with %(new_cert_arn)s to load balancer %(lb_name)s '
                  '(%(lb_dns)s) on port %(lb_port)d.' %
                  {
                      'existing_cert_arn': existing_cert,
                      'new_cert_arn': arn,
                      'lb_name': lb_name,
                      'lb_dns': lb['DNSName'],
                      'lb_port': lb_port
                  })

            # Request verification from the user
            if six.PY2:
                input_method = raw_input
            else:
                input_method = input

            if not is_alb:
                # Assign the certificate to the ELB
                response = self._elb_client.set_load_balancer_listener_ssl_certificate(
                    LoadBalancerName=lb_name,
                    LoadBalancerPort=lb_port,
                    SSLCertificateId=arn
                )

                # Check for a successful response
                if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                    print('Certificate %s applied successfully to ELB %s on port %d' % (arn, lb_name, lb_port))
                else:
                    raise Exception('Unable to apply certificate to ELB: %s' % response)

                # Check for rollback
                if input_method('Would you like to roll back? (y/n): ') == 'y':
                    # Roll back the certificate
                    response = self._elb_client.set_load_balancer_listener_ssl_certificate(
                        LoadBalancerName=lb_name,
                        LoadBalancerPort=lb_port,
                        SSLCertificateId=existing_cert
                    )

                    # Check for a successful response
                    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                        print('Rolled back to certificate %s on ELB %s port %d' % (existing_cert, lb_name, lb_port))
                    else:
                        raise Exception('Unable to apply certificate to ELB: %s' % response)

            else:
                # Update the certificate
                certs = [{'CertificateArn': arn}]

                # Modify the listener on the ALB
                self._elbv2_client.modify_listener(
                    ListenerArn=listener['ListenerArn'],
                    Certificates=certs
                )
                print('Certificate %s applied successfully to ALB %s on port %d' % (arn, lb_name, lb_port))

                # Check for rollback
                if input_method('Would you like to keep this change? (y/n): ') == 'n':
                    # Update the certificate
                    certs = [{'CertificateArn': existing_cert}]

                    # Modify the listener on the ALB
                    self._elbv2_client.modify_listener(
                        ListenerArn=listener['ListenerArn'],
                        Certificates=certs
                    )
                    print('Rolled back to certificate %s on ALB %s port %d' % (existing_cert, lb_name, lb_port))

        else:
            print('[DRY RUN] Certificate %(existing_cert_arn)s would be replaced with %(new_cert_arn)s on '
                  'load balancer %(lb_name)s (%(lb_dns)s) on port %(lb_port)d.' %
                  {
                      'existing_cert_arn': existing_cert,
                      'new_cert_arn': arn,
                      'lb_name': lb_name,
                      'lb_dns': lb['DNSName'],
                      'lb_port': lb_port
                  })

    def tag_certificate(self, arn, tags=None):
        """Add tags to a certificate"""
        raise NotImplementedError
