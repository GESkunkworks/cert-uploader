import unittest
from tempfile import NamedTemporaryFile
from mock import patch, MagicMock, call

import boto3
from moto import mock_elbv2, mock_elb

from cert_uploader.exceptions import LoadBalancerNotFoundException, ListenerNotFoundException, InvalidProtocolException
from cert_uploader.tests.utils import create_vpc_resources, create_alb, create_default_listeners, create_elb
from cert_uploader.uploader.base import CertificateUploader


class TestBaseCertificateUploader(unittest.TestCase):
    def setUp(self):
        self.uploader = CertificateUploader()

    @patch('boto3.Session')
    @patch('boto3.client')
    def test_assume_role(self, client, session):
        client.return_value = MagicMock(
            assume_role=MagicMock(
                return_value={
                    'Credentials': {
                        'AccessKeyId': 'access key',
                        'SecretAccessKey': 'secret key',
                        'SessionToken': 'session token'
                    }
                }
            )
        )
        CertificateUploader(role='arn:aws:iam::000000000000:role/test')

        # Make sure assume role was called
        client.return_value.assume_role.assert_called()

        # Make sure session was created
        session.assert_called_with(
            aws_access_key_id='access key',
            aws_secret_access_key='secret key',
            aws_session_token='session token'
        )

    @patch('boto3.Session')
    def test_profile(self, session):
        CertificateUploader(profile='test')

        # Make sure profile was initialized
        session.assert_called_with(profile_name='test')

    @patch('boto3.Session')
    def test_client_creation(self, session):
        session.return_value = MagicMock(client=MagicMock())
        CertificateUploader(profile='test')

        # Make sure ELB clients were created
        session.return_value.client.assert_has_calls([
            call('elb'),
            call('elbv2')
        ])

    def test_read_certificate_files(self):
        with NamedTemporaryFile() as cert_file, NamedTemporaryFile() as key_file, NamedTemporaryFile() as chain_file:
            cert_file.write(b'cert data')
            cert_file.seek(0)
            key_file.write(b'key data')
            key_file.seek(0)
            chain_file.write(b'chain data')
            chain_file.seek(0)

            cert_data, private_key_data, chain_data = self.uploader.read_certificate_files(
                cert_path=cert_file.name,
                private_key_path=key_file.name,
                chain_path=chain_file.name
            )

        self.assertEqual(cert_data, 'cert data')
        self.assertEqual(private_key_data, 'key data')
        self.assertEqual(chain_data, 'chain data')

    def test_upload_certificate(self):
        with self.assertRaises(NotImplementedError):
            self.uploader.upload_certificate(
                cert_data='dummy',
                private_key_data='dummy',
                chain_data='dummy'
            )

    def test_get_server_certificate(self):
        with self.assertRaises(NotImplementedError):
            self.uploader.get_server_certificate('dummy')

    def test_tag_certificate(self):
        with self.assertRaises(NotImplementedError):
            self.uploader.tag_certificate(arn='arn', tags={})

    @mock_elbv2
    def test_get_alb_listeners(self):
        # Create VPC resources and load balancer
        vpc, subnet = create_vpc_resources()
        lb = create_alb('dummy', subnet)

        # Create HTTP listener
        elbv2 = boto3.client('elbv2')
        http_listener = elbv2.create_listener(
            LoadBalancerArn=lb['LoadBalancerArn'],
            Protocol='HTTP',
            Port=80,
            DefaultActions=[]
        )['Listeners'][0]

        # Create HTTPS listener
        https_listener = elbv2.create_listener(
            LoadBalancerArn=lb['LoadBalancerArn'],
            Protocol='HTTPS',
            Port=443,
            DefaultActions=[],
            Certificates=[{'CertificateArn': 'dummy'}]
        )['Listeners'][0]

        # Instantiate and fetch listeners
        uploader = CertificateUploader()
        listeners = uploader._get_alb_listeners(lb['LoadBalancerArn'])

        # Verify the response from _get_alb_listeners matches what was created
        self.assertListEqual([http_listener, https_listener], listeners)

    @mock_elb
    @mock_elbv2
    def test_get_load_balancer_none_found(self):
        with self.assertRaisesRegex(LoadBalancerNotFoundException, 'Load balancer fake could not be found'):
            self.uploader.get_load_balancer('fake')

    @mock_elb
    def test_get_load_balancer_elb(self):
        # Create vpc resources
        vpc, subnet = create_vpc_resources()

        # Create load balancer
        elb = boto3.client('elb')
        elb.create_load_balancer(
            LoadBalancerName='test-elb',
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
                    'SSLCertificateId': 'fake-certificate'
                }
            ],
            AvailabilityZones=[],
            Scheme='HTTP',
            Subnets=[subnet['Subnet']['SubnetId']]
        )

        # Get load balancer and validate
        lb_info, is_alb = self.uploader.get_load_balancer('test-elb')
        self.assertFalse(is_alb)
        self.assertEqual(lb_info['LoadBalancerName'], 'test-elb')

    @mock_elb
    @mock_elbv2
    def test_get_load_balancer_alb(self):
        # Create vpc resources
        vpc, subnet = create_vpc_resources()

        # Create load balancer
        create_alb('test-alb', subnet)

        # Get load balancer and validate
        lb_info, is_alb = self.uploader.get_load_balancer('test-alb')
        self.assertTrue(is_alb)
        self.assertEqual(lb_info['LoadBalancerName'], 'test-alb')

    @mock_elb
    @mock_elbv2
    def test_assign_certificate_alb_missing_port(self):
        # Create vpc resources
        vpc, subnet = create_vpc_resources()

        # Create load balancer and default listeners
        lb = create_alb('alb', subnet)
        create_default_listeners(lb['LoadBalancerArn'])

        with self.assertRaisesRegex(ListenerNotFoundException, 'Could not find a listener for port 1234'):
            self.uploader.assign_certificate('alb', 'arn', lb_port=1234)

    @mock_elb
    @mock_elbv2
    def test_assign_certificate_alb_http_protocol(self):
        # Create vpc resources
        vpc, subnet = create_vpc_resources()

        # Create load balancer
        lb = create_alb('alb', subnet)
        create_default_listeners(lb['LoadBalancerArn'])

        with self.assertRaisesRegex(InvalidProtocolException, 'Port 80 is not a HTTPS listener'):
            self.uploader.assign_certificate('alb', 'arn', lb_port=80)

    @mock_elb
    @mock_elbv2
    @patch('builtins.print')
    @patch('builtins.input', side_effect=['n'])
    def test_assign_certificate_alb_rollback(self, mock_input, mock_print):
        # Create vpc resources
        vpc, subnet = create_vpc_resources()

        # Create load balancer
        lb = create_alb('test-alb', subnet)
        create_default_listeners(lb['LoadBalancerArn'])

        self.uploader.assign_certificate('test-alb', 'new-cert')
        self.assertEqual(
            mock_print.mock_calls,
            [
                call(
                    'Replacing certificate %(existing_cert_arn)s with %(new_cert_arn)s to load balancer %(lb_name)s '
                    '(%(lb_dns)s) on port %(lb_port)d.' %
                    {
                          'existing_cert_arn': 'dummy',
                          'new_cert_arn': 'new-cert',
                          'lb_name': 'test-alb',
                          'lb_dns': lb['DNSName'],
                          'lb_port': 443
                    }
                ),
                call('Certificate %s applied successfully to ALB %s on port %d' % ('new-cert', 'test-alb', 443)),
                call('Rolled back to certificate %s on ALB %s port %d' % ('dummy', 'test-alb', 443))
            ]
        )

    @mock_elb
    @mock_elbv2
    @patch('builtins.print')
    @patch('builtins.input', side_effect=['y'])
    def test_assign_certificate_alb(self, mock_input, mock_print):
        # Create vpc resources
        vpc, subnet = create_vpc_resources()

        # Create load balancer
        lb = create_alb('test-alb', subnet)
        create_default_listeners(lb['LoadBalancerArn'])

        # Assign certificate
        self.uploader.assign_certificate('test-alb', 'new-cert')
        self.assertEqual(
            mock_print.mock_calls,
            [
                call(
                    'Replacing certificate %(existing_cert_arn)s with %(new_cert_arn)s to load balancer %(lb_name)s '
                    '(%(lb_dns)s) on port %(lb_port)d.' %
                    {
                          'existing_cert_arn': 'dummy',
                          'new_cert_arn': 'new-cert',
                          'lb_name': 'test-alb',
                          'lb_dns': lb['DNSName'],
                          'lb_port': 443
                    }
                ),
                call('Certificate %s applied successfully to ALB %s on port %d' % ('new-cert', 'test-alb', 443))
            ]
        )

    @mock_elb
    @mock_elbv2
    @patch('builtins.print')
    def test_assign_certificate_alb_dry_run(self, mock_print):
        # Create vpc resources
        vpc, subnet = create_vpc_resources()

        # Create load balancer
        lb = create_alb('test-alb', subnet)
        create_default_listeners(lb['LoadBalancerArn'])

        # Assign certificate
        self.uploader.assign_certificate('test-alb', 'new-cert', dry_run=True)
        self.assertEqual(
            mock_print.mock_calls,
            [
                call(
                    '[DRY RUN] Certificate %(existing_cert_arn)s would be replaced with %(new_cert_arn)s on '
                    'load balancer %(lb_name)s (%(lb_dns)s) on port %(lb_port)d.' %
                    {
                        'existing_cert_arn': 'dummy',
                        'new_cert_arn': 'new-cert',
                        'lb_name': 'test-alb',
                        'lb_dns': lb['DNSName'],
                        'lb_port': 443
                    }
                )
            ]
        )

    @mock_elb
    @mock_elbv2
    def test_assign_certificate_elb_missing_port(self):
        # Create vpc resources
        vpc, subnet = create_vpc_resources()

        # Create load balancer
        create_elb('test-elb', subnet)

        with self.assertRaisesRegex(ListenerNotFoundException, 'Could not find a listener for port 1234'):
            self.uploader.assign_certificate('test-elb', 'arn', lb_port=1234)

    @mock_elb
    @mock_elbv2
    def test_assign_certificate_elb_http_protocol(self):
        # Create vpc resources
        vpc, subnet = create_vpc_resources()

        # Create load balancer
        create_elb('test-elb', subnet)

        with self.assertRaisesRegex(InvalidProtocolException, 'Port 80 is not a HTTPS listener'):
            self.uploader.assign_certificate('test-elb', 'arn', lb_port=80)

    @mock_elb
    @mock_elbv2
    @patch('builtins.print')
    @patch('builtins.input', side_effect=['n'])
    def test_assign_certificate_elb_rollback(self, mock_input, mock_print):
        # Create vpc resources
        vpc, subnet = create_vpc_resources()

        # Create load balancer
        lb = create_elb('test-elb', subnet)

        self.uploader.assign_certificate('test-elb', 'new-cert')
        self.assertEqual(
            mock_print.mock_calls,
            [
                call(
                    'Replacing certificate %(existing_cert_arn)s with %(new_cert_arn)s to load balancer %(lb_name)s '
                    '(%(lb_dns)s) on port %(lb_port)d.' %
                    {
                          'existing_cert_arn': 'fake-certificate',
                          'new_cert_arn': 'new-cert',
                          'lb_name': 'test-elb',
                          'lb_dns': lb['DNSName'],
                          'lb_port': 443
                    }
                ),
                call('Certificate %s applied successfully to ELB %s on port %d' % ('new-cert', 'test-elb', 443)),
                call('Rolled back to certificate %s on ELB %s port %d' % ('fake-certificate', 'test-elb', 443))
            ]
        )

    @mock_elb
    @mock_elbv2
    @patch('builtins.print')
    @patch('builtins.input', side_effect=['y'])
    def test_assign_certificate_elb(self, mock_input, mock_print):
        # Create vpc resources
        vpc, subnet = create_vpc_resources()

        # Create load balancer
        lb = create_elb('test-elb', subnet)

        self.uploader.assign_certificate('test-elb', 'new-cert')
        self.assertEqual(
            mock_print.mock_calls,
            [
                call(
                    'Replacing certificate %(existing_cert_arn)s with %(new_cert_arn)s to load balancer %(lb_name)s '
                    '(%(lb_dns)s) on port %(lb_port)d.' %
                    {
                          'existing_cert_arn': 'fake-certificate',
                          'new_cert_arn': 'new-cert',
                          'lb_name': 'test-elb',
                          'lb_dns': lb['DNSName'],
                          'lb_port': 443
                    }
                ),
                call('Certificate %s applied successfully to ELB %s on port %d' % ('new-cert', 'test-elb', 443))
            ]
        )

    @mock_elb
    @mock_elbv2
    @patch('builtins.print')
    def test_assign_certificate_elb_dry_run(self, mock_print):
        # Create vpc resources
        vpc, subnet = create_vpc_resources()

        # Create load balancer
        lb = create_elb('test-elb', subnet)

        # Assign certificate
        self.uploader.assign_certificate('test-elb', 'new-cert', dry_run=True)
        self.assertEqual(
            mock_print.mock_calls,
            [
                call(
                    '[DRY RUN] Certificate %(existing_cert_arn)s would be replaced with %(new_cert_arn)s on '
                    'load balancer %(lb_name)s (%(lb_dns)s) on port %(lb_port)d.' %
                    {
                        'existing_cert_arn': 'fake-certificate',
                        'new_cert_arn': 'new-cert',
                        'lb_name': 'test-elb',
                        'lb_dns': lb['DNSName'],
                        'lb_port': 443
                    }
                )
            ]
        )
