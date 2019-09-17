import unittest
from mock import patch, call

import boto3
from moto import mock_acm

from cert_uploader.tests.utils import create_certificate_chain, generate_pem_data
from cert_uploader.uploader.acm import ACMCertificateUploader


class TestACMCertificateUploader(unittest.TestCase):

    def setUp(self):
        self.uploader = ACMCertificateUploader()

    @mock_acm
    def test_get_server_certificate(self):
        # Generate test certificate
        acm = boto3.client('acm')
        arn = acm.request_certificate(DomainName='test.com')['CertificateArn']

        # Fetch test certificate
        cert = self.uploader.get_server_certificate(arn)

        self.assertIsInstance(cert, dict)
        self.assertEqual('test.com', cert['DomainName'])

    @mock_acm
    def test_tag_certificate(self):
        # Generate test certificate
        acm = boto3.client('acm')
        arn = acm.request_certificate(DomainName='test.com')['CertificateArn']

        # Check existing tags
        existing_tags = acm.list_tags_for_certificate(CertificateArn=arn)
        self.assertListEqual([], existing_tags['Tags'])

        # Set tags
        self.uploader.tag_certificate(arn, {'key': 'value'})

        # Verify the tags were set
        new_tags = acm.list_tags_for_certificate(CertificateArn=arn)
        self.assertListEqual(
            [{
                'Key': 'key',
                'Value': 'value'
            }],
            new_tags['Tags']
        )

    @mock_acm
    def test_tag_certificate_no_tags(self):
        # Generate test certificate
        acm = boto3.client('acm')
        arn = acm.request_certificate(DomainName='test.com')['CertificateArn']

        # Check existing tags
        existing_tags = acm.list_tags_for_certificate(CertificateArn=arn)
        self.assertListEqual([], existing_tags['Tags'])

        # Set tags
        tag_response = self.uploader.tag_certificate(arn, {})
        self.assertIsNone(tag_response)

        # Verify the tags were set
        new_tags = acm.list_tags_for_certificate(CertificateArn=arn)
        self.assertListEqual([], new_tags['Tags'])

    @mock_acm
    @patch('builtins.print')
    def test_upload_certificate(self, mock_print):
        # Generate certificate
        cert, key, ca_cert, ca_key = create_certificate_chain(
            common_name='test.com',
            subject_alt_names=('www.test.com',)
        )
        certificate, private_key, ca_certificate = generate_pem_data(cert, key, ca_cert)

        arn = self.uploader.upload_certificate(
            cert_data=certificate,
            private_key_data=private_key,
            chain_data=ca_certificate
        )

        mock_print.assert_has_calls(
            [
                call('Certificate Uploaded Successfully:'),
                call('\tARN: %s' % arn),
                call('\tCommon Name: %s' % 'test.com'),
                call('\tSubject Alternative Names:'),
                call('\t\twww.test.com'),
                # call('\tValidity: %s to %s' % (cert.not_valid_before, cert.not_valid_after)),
                # call('\tStatus: %s' % 'ISSUED')
            ]
        )

    @mock_acm
    @patch('builtins.print')
    def test_upload_certificate_multiple_san(self, mock_print):
        # Generate certificate
        cert, key, ca_cert, ca_key = create_certificate_chain(
            common_name='test.com',
            subject_alt_names=('www.test.com', 'test.test.com')
        )
        certificate, private_key, ca_certificate = generate_pem_data(cert, key, ca_cert)

        arn = self.uploader.upload_certificate(
            cert_data=certificate,
            private_key_data=private_key,
            chain_data=ca_certificate
        )

        mock_print.assert_has_calls(
            [
                call('Certificate Uploaded Successfully:'),
                call('\tARN: %s' % arn),
                call('\tCommon Name: %s' % 'test.com'),
                call('\tSubject Alternative Names:'),
                call('\t\twww.test.com'),
                call('\t\ttest.test.com'),
                # call('\tValidity: %s to %s' % (cert.not_valid_before, cert.not_valid_after)),
                # call('\tStatus: %s' % 'ISSUED')
            ]
        )

    @mock_acm
    def test_upload_certificate_custom_region(self):
        uploader = ACMCertificateUploader(region='us-east-2')
        self.assertEqual(
            'us-east-2',
            uploader._acm_client.meta.region_name
        )

    @patch('builtins.print')
    def test_upload_certificate_dry_run(self, mock_print):
        self.uploader.upload_certificate(
            cert_data='cert',
            private_key_data='private',
            chain_data='chain',
            dry_run=True
        )

        self.assertEqual(
            [
                call('[DRY RUN] Would upload certificate to ACM:'),
                call('\tCertificate File Path (local system): %s' % 'cert'),
                call('\tPrivate Key File Path (local system): %s' % 'private'),
                call('\tCertificate Chain File Path (local system): %s' % 'chain')
            ],
            mock_print.mock_calls
        )
