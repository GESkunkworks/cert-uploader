class CertificateExistsException(Exception):
    pass


class CertificateExpiredException(Exception):
    pass


class CertificateScanFailedException(Exception):
    pass


class DuplicatePrivateKeyException(Exception):
    pass


class DuplicateCertificateException(Exception):
    pass


class ListenerNotFoundException(Exception):
    pass


class InvalidProtocolException(Exception):
    pass


class LoadBalancerNotFoundException(Exception):
    pass


class MultipleCertificatesException(Exception):
    pass
