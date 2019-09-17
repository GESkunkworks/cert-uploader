import os
import unittest
from tempfile import NamedTemporaryFile, TemporaryDirectory

import OpenSSL
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import NoEncryption
from mock import patch, call

from cert_uploader.certificate import CertificateChain
from cert_uploader.exceptions import CertificateScanFailedException, DuplicateCertificateException, \
    DuplicatePrivateKeyException, CertificateExpiredException
from cert_uploader.scan import validate_certificates, parse_certificates, scan_for_certificates
from cert_uploader.tests.utils import generate_pem_data, create_certificate_chain


class TestScan(unittest.TestCase):

    certificate_file = NamedTemporaryFile()
    certificate_chain_file = NamedTemporaryFile()
    private_key_file = NamedTemporaryFile()
    ca_key_file = NamedTemporaryFile()
    certificate = None
    private_key = None
    ca_certificate = None
    ca_key = None
    cert_data = b''
    key_data = b''
    ca_cert_data = b''
    ca_key_data = b''

    def setUp(self):
        # Seek to start of file
        self.certificate_file.seek(0)
        self.private_key_file.seek(0)
        self.certificate_chain_file.seek(0)
        self.ca_key_file.seek(0)

    @classmethod
    def setUpClass(cls):
        # Generate certificate
        cls.certificate, cls.private_key, cls.ca_certificate, cls.ca_key = create_certificate_chain(
            common_name='test.com',
            subject_alt_names=('www.test.com',)
        )
        cls.cert_data, cls.key_data, cls.ca_cert_data = generate_pem_data(
            cls.certificate, cls.private_key, cls.ca_certificate
        )
        cls.ca_key_data = cls.ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption()
        )

        # Write to file
        cls.certificate_file.write(cls.cert_data)
        cls.private_key_file.write(cls.key_data)
        cls.certificate_chain_file.write(cls.ca_cert_data)
        cls.ca_key_file.write(cls.ca_key_data)

    @classmethod
    def tearDownClass(cls):
        cls.certificate_file.close()
        cls.certificate_chain_file.close()
        cls.private_key_file.close()
        cls.ca_key_file.close()

    def test_parse_certificates(self):
        certs = [
            {
                'cert': OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.cert_data),
                'path': self.certificate_file.name
            },
            {
                'cert': OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.ca_cert_data),
                'path': self.certificate_chain_file.name
            }
        ]

        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=1024,
            backend=default_backend()
        )

        key_data = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption()
        )

        keys = [
            {
                'key': OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, self.key_data),
                'path': self.private_key_file.name
            },
            {
                'key': OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key_data),
                'path': 'dummy key'
            }
        ]

        cert_info = parse_certificates(certs, keys)

        self.assertEqual(certs[0]['cert'], cert_info['certificate'].cert)
        self.assertEqual(certs[0]['path'], cert_info['certificate'].path)

        self.assertEqual(certs[1]['cert'], cert_info['chain'].cert)
        self.assertEqual(certs[1]['path'], cert_info['chain'].path)

        self.assertEqual(keys[0], cert_info['private_key'])

    def test_parse_certificates_multiple_certificates(self):
        certificate, private_key, ca_certificate, ca_key = create_certificate_chain(
            common_name='test2.com',
            root_name='Root 2 CA',
            subject_alt_names=('www.test2.com',)
        )
        cert_data, key_data, ca_cert_data = generate_pem_data(certificate, private_key, ca_certificate)

        certs = [
            {
                'cert': OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.cert_data),
                'path': 'cert-file-1'
            },
            {
                'cert': OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.ca_cert_data),
                'path': 'ca-cert-file-1'
            },
            {
                'cert': OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_data),
                'path': 'cert-file-2'
            },
            {
                'cert': OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, ca_cert_data),
                'path': 'ca-cert-file-2'
            }
        ]

        keys = [
            {
                'key': OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, self.key_data),
                'path': 'key-1'
            },
            {
                'key': OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key_data),
                'path': 'key-2'
            }
        ]

        with self.assertRaisesRegex(CertificateScanFailedException,
                                    'ERROR: More than one base certificate was found: cert-file-1, cert-file-2'):
            parse_certificates(certs, keys)

    def test_parse_certificates_bad_private_key(self):
        certs = [
            {
                'cert': OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.cert_data),
                'path': self.certificate_file.name
            },
            {
                'cert': OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.ca_cert_data),
                'path': self.certificate_chain_file.name
            }
        ]

        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=1024,
            backend=default_backend()
        )

        key_data = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption()
        )

        keys = [
            {
                'key': OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key_data),
                'path': 'key path'
            }
        ]

        with self.assertRaisesRegex(CertificateScanFailedException,
                                    'ERROR: Could not find corresponding private key for the base certificate "%s"' %
                                    self.certificate_file.name):
            parse_certificates(certs, keys)

    @patch('builtins.print')
    @patch('builtins.input', side_effect=['y'])
    def test_validate_certificates(self, mock_input, mock_print):
        certificate = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.cert_data)
        chain = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.ca_cert_data)

        private_key = {
            'key': OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, self.key_data),
            'path': self.private_key_file.name
        }

        cert_info = {
            'certificate': CertificateChain(certificate, self.certificate_file.name),
            'chain': CertificateChain(chain, self.certificate_chain_file.name),
            'private_key': private_key
        }

        self.assertTrue(validate_certificates(cert_info))

        cert_components = [
            call('%s = %s' % (key.decode(), value.decode()))
            for (key, value) in certificate.get_subject().get_components()
        ]

        ca_cert_components = [
            call('%s = %s' % (key.decode(), value.decode()))
            for (key, value) in chain.get_subject().get_components()
        ]

        self.assertEqual(
            [
                call('Certificate:'),
                call('Path = %s' % self.certificate_file.name)
            ] + cert_components +
            [
                call(''),
                call('Issuer Certificate:'),
                call('Path = %s' % self.certificate_chain_file.name)
            ] + ca_cert_components +
            [
                call(''),
                call('Private Key:'),
                call('Path = %s' % self.private_key_file.name),
                call('')
            ],
            mock_print.mock_calls
        )

    @patch('OpenSSL.crypto.X509.has_expired', return_value=True)
    def test_validate_certificates_certificate_expired(self, mock_cert):
        certificate = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.cert_data)
        chain = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.ca_cert_data)

        private_key = {
            'key': OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, self.key_data),
            'path': 'key'
        }

        cert_info = {
            'certificate': CertificateChain(certificate, 'cert'),
            'chain': CertificateChain(chain, 'chain'),
            'private_key': private_key
        }

        with self.assertRaisesRegex(CertificateExpiredException, 'ERROR: Base certificate "cert" has expired.'):
            validate_certificates(cert_info)

    @patch('OpenSSL.crypto.X509.has_expired', side_effect=[False, True])
    def test_validate_certificates_chain_expired(self, mock_cert):
        certificate = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.cert_data)
        chain = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.ca_cert_data)

        private_key = {
            'key': OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, self.key_data),
            'path': 'key'
        }

        cert_info = {
            'certificate': CertificateChain(certificate, 'cert'),
            'chain': CertificateChain(chain, 'chain'),
            'private_key': private_key
        }

        with self.assertRaisesRegex(CertificateExpiredException, 'ERROR: Issuer certificate "chain" has expired.'):
            validate_certificates(cert_info)

    @patch('cert_uploader.scan.validate_certificates', return_value=True)
    @patch('cert_uploader.scan.parse_certificates')
    def test_scan_for_certificates(self, mock_parse_certificates, mock_validate_certificates):
        with TemporaryDirectory() as temp_dir:
            os.mkdir(os.path.join(temp_dir, 'directory'))

            with open(os.path.join(temp_dir, 'cert.pem'), 'w') as f:
                f.write(self.cert_data.decode('utf-8'))

            with open(os.path.join(temp_dir, 'chain.pem'), 'w') as f:
                f.write(self.ca_cert_data.decode('utf-8'))

            with open(os.path.join(temp_dir, 'key.pem'), 'w') as f:
                f.write(self.key_data.decode('utf-8'))

            with open(os.path.join(temp_dir, 'random.txt'), 'w') as f:
                f.write('random')

            cert = CertificateChain(
                OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.cert_data),
                os.path.join(temp_dir, 'cert.pem')
            )
            chain = CertificateChain(
                OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.ca_cert_data),
                os.path.join(temp_dir, 'chain.pem')
            )
            key = {
                'key': OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, self.key_data),
                'path': os.path.join(temp_dir, 'key.pem')
            }

            mock_parse_certificates.return_value = {
                'certificate': cert,
                'chain': chain,
                'private_key': key
            }

            cert_info = scan_for_certificates(path=temp_dir)

            self.assertDictEqual(
                {
                    'certificate': os.path.join(temp_dir, 'cert.pem'),
                    'chain': os.path.join(temp_dir, 'chain.pem'),
                    'private_key': os.path.join(temp_dir, 'key.pem')
                },
                cert_info
            )

    @patch('cert_uploader.scan.validate_certificates', return_value=False)
    @patch('cert_uploader.scan.parse_certificates')
    def test_scan_for_certificates_validation_failed(self, mock_parse_certificates, mock_validate_certificates):
        with TemporaryDirectory() as temp_dir:
            with open(os.path.join(temp_dir, 'cert.pem'), 'w') as f:
                f.write(self.cert_data.decode('utf-8'))

            with open(os.path.join(temp_dir, 'chain.pem'), 'w') as f:
                f.write(self.ca_cert_data.decode('utf-8'))

            with open(os.path.join(temp_dir, 'key.pem'), 'w') as f:
                f.write(self.key_data.decode('utf-8'))

            cert = CertificateChain(
                OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.cert_data),
                os.path.join(temp_dir, 'cert.pem')
            )
            chain = CertificateChain(
                OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.ca_cert_data),
                os.path.join(temp_dir, 'chain.pem')
            )
            key = {
                'key': OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, self.key_data),
                'path': os.path.join(temp_dir, 'key.pem')
            }

            mock_parse_certificates.return_value = {
                'certificate': cert,
                'chain': chain,
                'private_key': key
            }

            with self.assertRaisesRegex(CertificateScanFailedException,
                                        'ERROR: Unable to automatically find the correct certificates. Please enter the'
                                        ' certificate manually using the command line arguments.'):
                scan_for_certificates(path=temp_dir)

    def test_scan_for_certificates_duplicate_certificate(self):
        with TemporaryDirectory() as temp_dir:
            with open(os.path.join(temp_dir, 'cert.pem'), 'w') as f:
                f.write(self.cert_data.decode('utf-8'))

            with open(os.path.join(temp_dir, 'cert2.pem'), 'w') as f:
                f.write(self.cert_data.decode('utf-8'))

            with open(os.path.join(temp_dir, 'chain.pem'), 'w') as f:
                f.write(self.ca_cert_data.decode('utf-8'))

            with open(os.path.join(temp_dir, 'key.pem'), 'w') as f:
                f.write(self.key_data.decode('utf-8'))

            with open(os.path.join(temp_dir, 'random.txt'), 'w') as f:
                f.write('random')

            with self.assertRaisesRegex(DuplicateCertificateException, 'ERROR: Certificate ".+" duplicates ".+"'):
                scan_for_certificates(path=temp_dir)

    def test_scan_for_certificates_duplicate_key(self):
        with TemporaryDirectory() as temp_dir:
            with open(os.path.join(temp_dir, 'cert.pem'), 'w') as f:
                f.write(self.cert_data.decode('utf-8'))

            with open(os.path.join(temp_dir, 'chain.pem'), 'w') as f:
                f.write(self.ca_cert_data.decode('utf-8'))

            with open(os.path.join(temp_dir, 'key.pem'), 'w') as f:
                f.write(self.key_data.decode('utf-8'))

            with open(os.path.join(temp_dir, 'key2.pem'), 'w') as f:
                f.write(self.key_data.decode('utf-8'))

            with open(os.path.join(temp_dir, 'random.txt'), 'w') as f:
                f.write('random')

            error_message = 'ERROR: Private key "%s" duplicates "%s"' % (
                os.path.join(temp_dir, 'key2.pem'), os.path.join(temp_dir, 'key.pem')
            )

            with self.assertRaisesRegex(DuplicatePrivateKeyException, error_message):
                scan_for_certificates(path=temp_dir)

    def test_scan_for_certificates_no_certificates(self):
        with TemporaryDirectory() as temp_dir:
            with open(os.path.join(temp_dir, 'key.pem'), 'w') as f:
                f.write(self.key_data.decode('utf-8'))

            with open(os.path.join(temp_dir, 'random.txt'), 'w') as f:
                f.write('random')

            with self.assertRaisesRegex(CertificateScanFailedException, 'ERROR: No certificates were found'):
                scan_for_certificates(path=temp_dir)

    def test_scan_for_certificates_no_chain(self):
        with TemporaryDirectory() as temp_dir:
            with open(os.path.join(temp_dir, 'cert.pem'), 'w') as f:
                f.write(self.cert_data.decode('utf-8'))

            with open(os.path.join(temp_dir, 'random.txt'), 'w') as f:
                f.write('random')

            with self.assertRaisesRegex(CertificateScanFailedException,
                                        'ERROR: Only one certificate was found. The chain may be missing.'):
                scan_for_certificates(path=temp_dir)

    def test_scan_for_certificates_no_keys(self):
        with TemporaryDirectory() as temp_dir:
            with open(os.path.join(temp_dir, 'cert.pem'), 'w') as f:
                f.write(self.cert_data.decode('utf-8'))

            with open(os.path.join(temp_dir, 'chain.pem'), 'w') as f:
                f.write(self.ca_cert_data.decode('utf-8'))

            with open(os.path.join(temp_dir, 'random.txt'), 'w') as f:
                f.write('random')

            with self.assertRaisesRegex(CertificateScanFailedException, 'ERROR: No private keys were found'):
                scan_for_certificates(path=temp_dir)
