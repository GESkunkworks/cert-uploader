import unittest

import boto3
from mock import patch, call
from moto import mock_iam

from cert_uploader.certificate import Certificate
from cert_uploader.exceptions import CertificateExistsException
from cert_uploader.uploader import IAMCertificateUploader


class TestIAMCertificateUploader(unittest.TestCase):

    def setUp(self):
        self.uploader = IAMCertificateUploader()

    @mock_iam
    def test_get_server_certificate(self):
        iam = boto3.client('iam')
        iam.upload_server_certificate(
            ServerCertificateName='test-cert',
            CertificateBody='body',
            PrivateKey='private key'
        )
        cert = self.uploader.get_server_certificate('test-cert')
        self.assertIsInstance(cert, Certificate)

    @mock_iam
    @patch('builtins.print')
    def test_upload_certificate(self, mock_print):
        arn = self.uploader.upload_certificate(
            cert_data='cert',
            private_key_data='private',
            chain_data='chain',
            name='test'
        )

        self.assertEqual(
            [
                call('Certificate Uploaded Successfully:'),
                call('\tCertificate ID: ASCACKCEVSQ6C2EXAMPLE'),
                call('\tCertificate Name: test'),
                call('\tARN: %s' % arn),
                call('\tPath: /'),
                call('\tUpload Date: 2010-05-08 01:02:03.004000+00:00'),
                call('\tExpiration Date: 2012-05-08 01:02:03.004000+00:00')
            ],
            mock_print.mock_calls
        )

    @mock_iam
    @patch('builtins.print')
    def test_upload_certificate_dry_run(self, mock_print):
        self.uploader.upload_certificate(
            cert_data='cert',
            private_key_data='private',
            chain_data='chain',
            name='test',
            dry_run=True
        )

        self.assertEqual(
            [
                call('[DRY RUN] Would upload certificate to IAM:'),
                call('\tName: test'),
                call('\tPath: /'),
                call('\tCertificate File Path (local system): cert'),
                call('\tPrivate Key File Path (local system): private'),
                call('\tCertificate Chain File Path (local system): chain')
            ],
            mock_print.mock_calls
        )

    @mock_iam
    def test_upload_certificate_existing_cert(self):
        iam = boto3.client('iam')
        iam.upload_server_certificate(
            ServerCertificateName='existing-cert',
            CertificateBody='body',
            PrivateKey='private key'
        )
        with self.assertRaisesRegex(CertificateExistsException,
                                    'A certificate named existing-cert already exists in IAM.'):
            self.uploader.upload_certificate(
                cert_data='cert',
                private_key_data='private',
                chain_data='chain',
                name='existing-cert'
            )
