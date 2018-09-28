import os
import re
import six

try:
    from os import scandir
except ImportError:
    from scandir import scandir

import OpenSSL

from .certificate import CertificateChain
from .exceptions import CertificateExpiredException, CertificateScanFailedException, DuplicateCertificateException, \
    DuplicatePrivateKeyException


PATTERN_CERTIFICATE_HEADER = r'-----BEGIN CERTIFICATE-----'
PATTERN_PRIVATE_KEY_HEADER = r'-----BEGIN (RSA )?PRIVATE KEY-----'


def scan_for_certificates(path='.'):
    """
    Scan for certificates in the specified path

    :param str path: Path to directory containing certificates
    :return: Dictionary of certificate paths
    :rtype: dict
    """
    certs = []
    keys = []

    # Scan the specified directory
    for entry in scandir(path=path):
        # Only open files
        if not os.path.isfile(entry.path):
            continue

        # Read the first line of each file and look for a regex
        abs_path = os.path.abspath(entry.path)
        with open(abs_path, 'r') as f:
            line = f.readline()

            if re.match(PATTERN_CERTIFICATE_HEADER, line):
                # Seek to the start of the file and open the certificate
                f.seek(0)
                cert_data = f.read()
                cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_data.encode('utf8'))

                # Check if this certificate already exists
                for item in certs:
                    if item['cert'].get_subject() == cert.get_subject():
                        raise DuplicateCertificateException(
                            'ERROR: Certificate "%s" duplicates "%s"' % (abs_path, item['path'])
                        )

                # Add to the list
                certs.append({'cert': cert, 'path': abs_path})

            elif re.match(PATTERN_PRIVATE_KEY_HEADER, line):
                # Seek to the start of the file and open the key
                f.seek(0)
                private_key_data = f.read()
                private_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, private_key_data)

                # Check if this key already exists
                for item in keys:
                    private_numbers = item['key'].to_cryptography_key().private_numbers()
                    if private_numbers == private_key.to_cryptography_key().private_numbers():
                        raise DuplicatePrivateKeyException(
                            'ERROR: Private key "%s" duplicates "%s"' % (abs_path, item['path'])
                        )

                # Add to the list
                keys.append({'key': private_key, 'path': abs_path})

    # Make sure a certificate and private key was found
    if len(certs) == 0:
        raise CertificateScanFailedException('ERROR: No certificates were found')
    elif len(certs) == 1:
        raise CertificateScanFailedException('ERROR: Only one certificate was found. The chain may be missing.')
    if len(keys) == 0:
        raise CertificateScanFailedException('ERROR: No private keys were found')

    # Parse the certificates
    cert_info = parse_certificates(certs, keys)

    # Perform validation
    if not validate_certificates(cert_info):
        raise CertificateScanFailedException(
            'ERROR: Unable to automatically find the correct certificates. Please enter the certificate manually '
            'using the command line arguments.'
        )

    # Transform the objects to their paths
    for key, value in cert_info.items():
        if isinstance(value, dict) and 'path' in value:
            cert_info[key] = value['path']
        elif isinstance(value, CertificateChain):
            cert_info[key] = value.path

    return cert_info


def validate_certificates(cert_info):
    """
    Validate that the provided certificates have not expired and are correct

    :param dict cert_info: Dictionary containing certificate, chain, and private key information
    :return: Boolean
    :rtype: bool
    """
    # Ensure none of the certificates have expired
    if cert_info['certificate'].cert.has_expired():
        raise CertificateExpiredException('ERROR: Base certificate "%s" has expired.' % cert_info['certificate'].path)
    elif cert_info['chain'].cert.has_expired():
        raise CertificateExpiredException('ERROR: Issuer certificate "%s" has expired.' % cert_info['chain'].path)

    # Print out the certificate details for verification by the user
    print('Certificate:')
    print('Path = %s' % cert_info['certificate'].path)
    for (key, value) in cert_info['certificate'].cert.get_subject().get_components():
        print('%s = %s' % (key.decode(), value.decode()))
    print('')

    # Print out the chain details for verification by the user
    print('Issuer Certificate:')
    print('Path = %s' % cert_info['chain'].path)
    for (key, value) in cert_info['chain'].cert.get_subject().get_components():
        print('%s = %s' % (key.decode(), value.decode()))
    print('')

    # Print out the private key path for verification by the user
    print('Private Key:')
    print('Path = %s' % cert_info['private_key']['path'])
    print('')

    # Request verification from the user
    if six.PY2:
        input_method = raw_input
    else:
        input_method = input

    return input_method('Are these files correct? (y/n): ') == 'y'


def parse_certificates(certs, keys):
    """
    Parse the certificates that have been scanned and find the base certificate, corresponding private key, and issuer.

    :param list of dict certs: List of dictionary objects formatted as {'cert': X509 object, 'path': 'file/path.crt'}
    :param list of dict keys: List of dictionary objects formatted as {'key': PKey object, 'path': 'file/path.pem'}
    :return: Dictionary of information about the certificate, chain, and private key
    :rtype: dict
    """
    # Build the certificate chain
    first_cert = None
    cert_chain = []
    for cert in certs:
        # Create the chain item
        chain_item = CertificateChain(cert['cert'], cert['path'])

        if not first_cert:
            # Save the first certificate
            first_cert = chain_item
        else:
            # Get the subject and issuer for this certificate
            subject = cert['cert'].get_subject()
            issuer = cert['cert'].get_issuer()

            # Evaluate relationships for all items in the chain
            for item in cert_chain:
                # Go to the top
                current = item
                while current.parent:
                    current = current.parent

                # Check for parents/children at the top
                if current.cert.get_issuer() == subject:
                    # chain_item is a parent
                    current.parent = chain_item
                    chain_item.child = current
                elif current.cert.get_subject() == issuer:
                    # chain_item is a child
                    current.child = chain_item
                    chain_item.parent = current

                # Go to the bottom
                while current.child:
                    current = current.child

                # Check for parents/children at the bottom
                if current.cert.get_issuer() == subject:
                    # chain_item is a parent
                    current.parent = chain_item
                    chain_item.child = current
                elif current.cert.get_subject() == issuer:
                    # chain_item is a child
                    current.child = chain_item
                    chain_item.parent = current

        # Add to the chain list
        cert_chain.append(chain_item)

    # Fail out if more than one base certificate was found
    base_certs = [item for item in cert_chain if not item.child]
    if len(base_certs) > 1:
        raise CertificateScanFailedException(
            'ERROR: More than one base certificate was found: %s' % ', '.join([cert.path for cert in base_certs])
        )

    # Save the base cert
    base_cert = base_certs[0]
    del base_certs

    # Get the public key of the base cert
    public_key = base_cert.cert.get_pubkey()

    # Find the private key that goes with this public key
    private_key = None
    for key in keys:
        public_numbers = key['key'].to_cryptography_key().public_key().public_numbers()

        # If the public numbers match, then this is the expected public key
        if public_key.to_cryptography_key().public_numbers() == public_numbers:
            private_key = key
            break

    # If a corresponding private key was not found, raise an error
    if not private_key:
        raise CertificateScanFailedException(
            'ERROR: Could not find corresponding private key for the base certificate "%s".' % base_cert.path
        )

    return {
        'certificate': base_cert,
        'private_key': private_key,
        'chain': base_cert.parent
    }
