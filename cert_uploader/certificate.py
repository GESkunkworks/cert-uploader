class Certificate:
    """Certificate object that stores metadata about an IAM server certificate"""

    def __init__(self, name, id, path, arn, upload_date, expiration_date):
        self.name = name
        self.id = id
        self.path = path
        self.arn = arn
        self.upload_date = upload_date
        self.expiration_date = expiration_date

    @classmethod
    def from_metadata(cls, data):
        return cls(
            name=data['ServerCertificateName'],
            id=data['ServerCertificateId'],
            path=data['Path'],
            arn=data['Arn'],
            upload_date=data['UploadDate'],
            expiration_date=data['Expiration']
        )


class CertificateChain:
    """Object to store the tree of a certificate chain."""

    parent = None
    child = None

    def __init__(self, cert, path):
        """
        Initialize the certificate chain

        :param OpenSSL.crypto.X509 cert: X509 certificate
        :param str path: File path
        """
        self.cert = cert
        self.path = path
