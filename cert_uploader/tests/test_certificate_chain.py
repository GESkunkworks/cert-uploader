import unittest

import OpenSSL
from moto.acm.models import GOOGLE_ROOT_CA

from cert_uploader.certificate import CertificateChain


class TestCertificateChain(unittest.TestCase):

    def setUp(self):
        self.cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, GOOGLE_ROOT_CA)
        self.chain = CertificateChain(cert=self.cert, path='/')

    def test_constructor(self):
        self.assertEqual(self.cert, self.chain.cert)
        self.assertEqual('/', self.chain.path)
        self.assertIsNone(self.chain.parent)
        self.assertIsNone(self.chain.child)
