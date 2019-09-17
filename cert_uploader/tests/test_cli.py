import argparse
import os
import re
import unittest
from tempfile import NamedTemporaryFile, TemporaryDirectory

import boto3
from mock import patch, call
from moto import mock_acm, mock_iam, mock_elb

from cert_uploader import cli
from cert_uploader.tests.utils import create_certificate_chain, generate_pem_data, create_vpc_resources, create_elb


class TestCLI(unittest.TestCase):

    certificate_file = NamedTemporaryFile()
    certificate_chain_file = NamedTemporaryFile()
    private_key_file = NamedTemporaryFile()
    certificate = None
    private_key = None
    ca_certificate = None
    ca_key = None

    def setUp(self):
        from cert_uploader import version
        version.version = '1.2.3'

        # Seek to start of file
        self.certificate_file.seek(0)
        self.private_key_file.seek(0)
        self.certificate_chain_file.seek(0)

    @classmethod
    def setUpClass(cls):
        # Generate certificate
        cls.certificate, cls.private_key, cls.ca_certificate, cls.ca_key = create_certificate_chain(
            common_name='test.com', subject_alt_names=('www.test.com',)
        )
        cert, key, ca_cert = generate_pem_data(cls.certificate, cls.private_key, cls.ca_certificate)

        # Write to file
        cls.certificate_file.write(cert)
        cls.private_key_file.write(key)
        cls.certificate_chain_file.write(ca_cert)

    @classmethod
    def tearDownClass(cls):
        cls.certificate_file.close()
        cls.certificate_chain_file.close()
        cls.private_key_file.close()

    def test_get_version(self,):
        self.assertEqual('1.2.3', cli.get_version())

    @patch('argparse.ArgumentParser.print_help')
    @patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(type='dummy'))
    def test_help_parser(self, mock_args, mock_print_help):
        cli.main()
        mock_print_help.assert_called()

    @mock_acm
    @patch('cert_uploader.cli.scan_for_certificates')
    @patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(
        type='acm', profile=None, role=None, region='us-east-1', scan=True, dry_run=False, certificate_arn=None,
        certificate_path=None, tag=None, load_balancer=None
    ))
    @patch('builtins.print')
    def test_acm_parser_via_scan(self, mock_print, mock_args, mock_scan):
        with TemporaryDirectory() as temp_dir:
            mock_scan.return_value = {
                'certificate': os.path.join(temp_dir, 'cert.pem'),
                'chain': os.path.join(temp_dir, 'chain.pem'),
                'private_key': os.path.join(temp_dir, 'key.pem')
            }

            certificate, private_key, ca_certificate, ca_key = create_certificate_chain(
                common_name='test.com', subject_alt_names=('www.test.com',)
            )
            cert_data, key_data, ca_cert_data = generate_pem_data(certificate, private_key, ca_certificate)

            with open(os.path.join(temp_dir, 'cert.pem'), 'w') as f:
                f.write(cert_data.decode('utf-8'))

            with open(os.path.join(temp_dir, 'chain.pem'), 'w') as f:
                f.write(ca_cert_data.decode('utf-8'))

            with open(os.path.join(temp_dir, 'key.pem'), 'w') as f:
                f.write(key_data.decode('utf-8'))

            cli.main()

            arn = None
            for item in mock_print.mock_calls:
                arn_match = re.match('\tARN: (arn:aws:acm:.+:\\d+:certificate/.+)$', item.args[0])
                if arn_match:
                    arn = arn_match.group(1)
                    break

            # Should be able to describe certificate without raising an exception
            self.assertIsNotNone(arn)
            acm = boto3.client('acm')
            acm.describe_certificate(CertificateArn=arn)

    @mock_acm
    @patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(
        type='acm', profile=None, role=None, region='us-east-1', scan=False, dry_run=False, certificate_arn=None,
        certificate_path=certificate_file.name, certificate_chain_path=certificate_chain_file.name,
        private_key_path=private_key_file.name, tag=None, load_balancer=None
    ))
    @patch('builtins.print')
    def test_acm_parser(self, mock_print, mock_args):
        acm = boto3.client('acm')
        cli.main()

        arn = None
        for item in mock_print.mock_calls:
            arn_match = re.match('\tARN: (arn:aws:acm:.+:\\d+:certificate/.+)$', item.args[0])
            if arn_match:
                arn = arn_match.group(1)
                break

        # Should be able to describe certificate without raising an exception
        self.assertIsNotNone(arn)
        acm.describe_certificate(CertificateArn=arn)

    @mock_acm
    @patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(
        type='acm', profile=None, role=None, region='us-east-1', scan=False, dry_run=False, certificate_arn=None,
        certificate_path=certificate_file.name, certificate_chain_path=certificate_chain_file.name,
        private_key_path=private_key_file.name, tag=['Test=true', 'Name=test'], load_balancer=None
    ))
    @patch('builtins.print')
    def test_acm_parser_with_tags(self, mock_print, mock_args):
        acm = boto3.client('acm')
        cli.main()

        arn = None
        for item in mock_print.mock_calls:
            arn_match = re.match('\tARN: (arn:aws:acm:.+:\\d+:certificate/.+)$', item.args[0])
            if arn_match:
                arn = arn_match.group(1)
                break

        # Should be able to describe certificate without raising an exception
        self.assertIsNotNone(arn)
        acm.describe_certificate(CertificateArn=arn)
        new_tags = acm.list_tags_for_certificate(CertificateArn=arn)
        self.assertListEqual(
            [
                {'Key': 'Test', 'Value': 'true'},
                {'Key': 'Name', 'Value': 'test'}
            ],
            new_tags['Tags']
        )

    @mock_acm
    @patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(
        type='acm', profile=None, role=None, region='us-east-1', scan=False, dry_run=False, certificate_arn=None,
        certificate_path=certificate_file.name, certificate_chain_path=certificate_chain_file.name,
        private_key_path=private_key_file.name, tag=['asdf'], load_balancer=None
    ))
    @patch('builtins.print')
    def test_acm_parser_bad_tags(self, mock_print, mock_args):
        with self.assertRaises(SystemExit) as e:
            cli.main()

        self.assertEqual(1, e.exception.code)

        mock_print.assert_has_calls([
            call('Invalid tag "asdf". Tag items must be formatted key=value and must be alpha-numeric.')
        ])

    @patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(
        type='acm', profile=None, role=None, region='us-east-1', scan=False,
        certificate_arn=None, certificate_path=None
    ))
    @patch('builtins.print')
    def test_acm_parser_missing_arn(self, mock_print, mock_args):
        with self.assertRaises(SystemExit) as e:
            cli.main()

        self.assertEqual(1, e.exception.code)

        mock_print.assert_has_calls([
            call('Missing required argument --certificate-arn')
        ])

    @mock_acm
    @mock_elb
    @patch('cert_uploader.cli.sleep')
    @patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(
        type='acm', profile=None, role=None, region='us-east-1', scan=False, dry_run=False,
        tag=None, load_balancer='test-lb', port=443, certificate_path=certificate_file.name,
        certificate_chain_path=certificate_chain_file.name, private_key_path=private_key_file.name,
    ))
    @patch('builtins.input', side_effect=['y'])
    @patch('builtins.print')
    def test_acm_parser_attach_new_certificate(self, mock_print, mock_input, mock_args, mock_sleep):
        # Create load balancer
        elb = boto3.client('elb')
        vpc, subnet = create_vpc_resources()
        create_elb('test-lb', subnet)

        # Get LB info
        lb_info = elb.describe_load_balancers(LoadBalancerNames=['test-lb'])['LoadBalancerDescriptions'][0]

        # Check certificate
        self.assertEqual('fake-certificate', lb_info['ListenerDescriptions'][1]['Listener']['SSLCertificateId'])

        # Run CLI. This should not raise any exceptions
        cli.main()

        for i in range(10, 0, -1):
            self.assertIn(
                call('Waiting for certificate to propagate... %d' % i),
                mock_print.mock_calls
            )

        self.assertEqual(
            10,
            mock_sleep.call_count
        )

        arn = None
        for item in mock_print.mock_calls:
            arn_match = re.match('\tARN: (arn:aws:acm:.+:\\d+:certificate/.+)$', item.args[0])
            if arn_match:
                arn = arn_match.group(1)
                break

        # Should be able to describe certificate without raising an exception
        self.assertIsNotNone(arn)
        acm = boto3.client('acm')
        acm.describe_certificate(CertificateArn=arn)

        # Verify ELB has the certificate assigned
        lb_info = elb.describe_load_balancers(LoadBalancerNames=['test-lb'])['LoadBalancerDescriptions'][0]

        # Check certificate
        self.assertEqual(arn, lb_info['ListenerDescriptions'][1]['Listener']['SSLCertificateId'])

    @mock_acm
    @mock_elb
    @patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(
        type='acm', profile=None, role=None, region='us-east-1', scan=False, dry_run=False,
        tag=None, load_balancer='test-lb', certificate_path=None, port=443
    ))
    @patch('builtins.input', side_effect=['y'])
    def test_acm_parser_attach_existing_certificate(self, mock_input, mock_args):
        certificate, private_key, ca_certificate = generate_pem_data(
            self.certificate, self.private_key, self.ca_certificate
        )

        # Create certificate
        acm = boto3.client('acm')
        arn = acm.import_certificate(
            Certificate=certificate,
            PrivateKey=private_key,
            CertificateChain=ca_certificate
        )['CertificateArn']
        mock_args.return_value.certificate_arn = arn

        # Create load balancer
        elb = boto3.client('elb')
        vpc, subnet = create_vpc_resources()
        create_elb('test-lb', subnet)

        # Get LB info
        lb_info = elb.describe_load_balancers(LoadBalancerNames=['test-lb'])['LoadBalancerDescriptions'][0]

        # Check certificate
        self.assertEqual('fake-certificate', lb_info['ListenerDescriptions'][1]['Listener']['SSLCertificateId'])

        # Run CLI. This should not raise any exceptions
        cli.main()

        # Verify ELB has the certificate assigned
        lb_info = elb.describe_load_balancers(LoadBalancerNames=['test-lb'])['LoadBalancerDescriptions'][0]

        # Check certificate
        self.assertEqual(arn, lb_info['ListenerDescriptions'][1]['Listener']['SSLCertificateId'])

    @mock_acm
    @mock_elb
    @patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(
        type='acm', profile=None, role=None, region='us-east-1', scan=False, certificate_path=None,
        certificate_arn='arn:aws:acm:us-east-1:123456789012:certificate/fake'
    ))
    @patch('builtins.print')
    def test_acm_parser_attach_existing_certificate_not_found(self, mock_print, mock_args):
        with self.assertRaises(SystemExit) as e:
            cli.main()

        self.assertEqual(1, e.exception.code)

        mock_print.assert_has_calls([
            call('Certificate with ARN "arn:aws:acm:us-east-1:123456789012:certificate/fake" not found')
        ])

    @mock_iam
    @patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(
        type='iam', profile=None, role=None, region='us-east-1', scan=False, dry_run=False,
        certificate_path=certificate_file.name, certificate_chain_path=certificate_chain_file.name,
        private_key_path=private_key_file.name, load_balancer=None, certificate_name='test-iam-cert', iam_path='/test/'
    ))
    @patch('builtins.print')
    def test_iam_parser(self, mock_print, mock_args):
        iam = boto3.resource('iam')
        cli.main()

        # Should be able to describe certificate without raising an exception
        cert = iam.ServerCertificate('test-iam-cert')
        cert.load()
        self.assertEqual('/test/', cert.server_certificate_metadata['Path'])

    @patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(
        type='iam', profile=None, role=None, region='us-east-1', scan=False,
        certificate_name=None, certificate_path=None
    ))
    @patch('builtins.print')
    def test_iam_parser_missing_name(self, mock_print, mock_args):
        with self.assertRaises(SystemExit) as e:
            cli.main()

        self.assertEqual(1, e.exception.code)

        mock_print.assert_has_calls([
            call('Missing required argument --certificate-name')
        ])

    @mock_iam
    @mock_elb
    @patch('argparse.ArgumentParser.parse_args', return_value=argparse.Namespace(
        type='iam', profile=None, role=None, region='us-east-1', scan=False, dry_run=False,
        load_balancer='test-lb-iam', certificate_path=None, port=443, certificate_name='tester'
    ))
    @patch('builtins.input', side_effect=['y'])
    def test_iam_parser_attach_existing_certificate(self, mock_input, mock_args):
        certificate, private_key, ca_certificate = generate_pem_data(
            self.certificate, self.private_key, self.ca_certificate
        )

        # Create certificate
        iam = boto3.client('iam')
        arn = iam.upload_server_certificate(
            Path='/test/',
            ServerCertificateName='tester',
            CertificateBody=certificate.decode('utf-8'),
            PrivateKey=private_key.decode('utf-8'),
            CertificateChain=ca_certificate.decode('utf-8')
        )['ServerCertificateMetadata']['Arn']

        # Create load balancer
        elb = boto3.client('elb')
        vpc, subnet = create_vpc_resources()
        create_elb('test-lb-iam', subnet)

        # Get LB info
        lb_info = elb.describe_load_balancers(LoadBalancerNames=['test-lb-iam'])['LoadBalancerDescriptions'][0]

        # Check certificate
        self.assertEqual('fake-certificate', lb_info['ListenerDescriptions'][1]['Listener']['SSLCertificateId'])

        # Run CLI. This should not raise any exceptions
        cli.main()

        # Verify ELB has the certificate assigned
        lb_info = elb.describe_load_balancers(LoadBalancerNames=['test-lb-iam'])['LoadBalancerDescriptions'][0]

        # Check certificate
        self.assertEqual(arn, lb_info['ListenerDescriptions'][1]['Listener']['SSLCertificateId'])
