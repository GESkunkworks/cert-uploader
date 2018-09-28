from .base import CertificateUploader
from ..certificate import Certificate
from ..exceptions import CertificateExistsException


class IAMCertificateUploader(CertificateUploader):
    """
    Certificate uploader

    Uploads new certificates and applies them to an ELB
    """

    def __init__(self, profile=None, role=None):
        super(IAMCertificateUploader, self).__init__(profile, role)
        self._iam = self.session.resource('iam')
        self._iam_client = self.session.client('iam')

    def get_server_certificate(self, name):
        """
        Create a Certificate object from the metadata of an IAM Server Certificate
        :param str name: IAM Server Certificate name
        :return: Certificate object
        :rtype: Certificate
        """
        cert = self._iam.ServerCertificate(name)
        cert.load()
        return Certificate.from_metadata(cert.server_certificate_metadata)

    def upload_certificate(self, cert_data, private_key_data, chain_data, name='', iam_path='/', dry_run=False):
        """
        Upload an IAM Server Certificate
        :param str cert_data: Path to the certificate file on the local machine
        :param str private_key_data: Path to the private key file on the local machine
        :param str chain_data: Path to the certificate chain file on the local machine
        :param str name: Certificate name
        :param str iam_path: Path to save the certificate within IAM. Defaults to "/"
        :param bool dry_run: Whether to perform a dry run of the operations. Defaults to False.
        :return: Certificate object
        :rtype: Certificate
        """
        # Check if a certificate by this name already exists
        cert = self._iam.ServerCertificate(name)
        try:
            cert.load()
        except self._iam_client.exceptions.NoSuchEntityException:
            pass
        else:
            raise CertificateExistsException('A certificate named %s already exists in IAM.' % name)

        if not dry_run:
            response = self._iam_client.upload_server_certificate(
                Path=iam_path,
                ServerCertificateName=name,
                CertificateBody=cert_data,
                PrivateKey=private_key_data,
                CertificateChain=chain_data
            )

            certificate = Certificate.from_metadata(response['ServerCertificateMetadata'])

            # Print details about the upload
            print('Certificate Uploaded Successfully:')
            print('\tCertificate ID: %s' % certificate.id)
            print('\tCertificate Name: %s' % certificate.name)
            print('\tARN: %s' % certificate.arn)
            print('\tPath: %s' % certificate.path)
            print('\tUpload Date: %s' % certificate.upload_date)
            print('\tExpiration Date: %s' % certificate.expiration_date)

            return certificate.arn
        else:
            print('%sWould upload certificate to IAM:' % '[DRY RUN] ' if dry_run else '')
            print('\tName: %s' % name)
            print('\tPath: %s' % iam_path)
            print('\tCertificate File Path (local system): %s' % cert_data)
            print('\tPrivate Key File Path (local system): %s' % private_key_data)
            print('\tCertificate Chain File Path (local system): %s' % chain_data)
