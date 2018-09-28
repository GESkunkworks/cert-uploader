from pprint import pprint

from .base import CertificateUploader


class ACMCertificateUploader(CertificateUploader):
    """
    Certificate uploader

    Uploads new certificates and applies them to an ELB
    """

    def __init__(self, profile=None, role=None):
        super(ACMCertificateUploader, self).__init__(profile, role)
        self._acm_client = self.session.client('acm')

    def get_server_certificate(self, arn):
        """
        Get a certificate from ACM

        :param str arn: Certificate ARN
        :return: Certificate information
        :rtype: dict
        """
        cert = self._acm_client.describe_certificate(CertificateArn=arn)
        return cert['Certificate']

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
        if not dry_run:
            response = self._acm_client.import_certificate(
                Certificate=cert_data,
                PrivateKey=private_key_data,
                CertificateChain=chain_data
            )

            # Save the ARN
            arn = response['CertificateArn']

            # Get details about the certificate
            certificate = self.get_server_certificate(arn)

            # Print details about the upload
            print('Certificate Uploaded Successfully:')
            print('\tARN: %s' % arn)
            print('\tCommon Name: %s' % certificate['DomainName'])
            if certificate['SubjectAlternativeNames']:
                print('\tSubject Alternative Names:')
                for item in certificate['SubjectAlternativeNames']:
                    print('\t\t%s' % item)
            print('\tValidity: %s to %s' % (certificate['NotBefore'], certificate['NotAfter']))
            print('\tStatus: %s' % certificate['Status'])
            pprint(certificate)

            return arn
        else:
            print('%sWould upload certificate to ACM:' % '[DRY RUN] ' if dry_run else '')
            print('\tCertificate File Path (local system): %s' % cert_data)
            print('\tPrivate Key File Path (local system): %s' % private_key_data)
            print('\tCertificate Chain File Path (local system): %s' % chain_data)

    def tag_certificate(self, arn, tags=None):
        """
        Add tags to a certificate

        :param str arn: Certificate ARN
        :param dict tags: Dictionary of tags formatted as follows:
                    {
                        'abc': '123',
                        'def': '456'
                    }
        :return: Response
        """
        if not tags:
            tags = {}

        # Build the tag list
        tag_list = [{'Key': key, 'Value': value} for key, value in tags.items()]

        # Perform the call
        return self._acm_client.add_tags_to_certificate(
            CertificateArn=arn,
            Tags=tag_list
        )
