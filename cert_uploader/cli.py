from argparse import ArgumentParser
from time import sleep

from .scan import scan_for_certificates
from .uploader import ACMCertificateUploader, IAMCertificateUploader


def main():
    parser = ArgumentParser(
        description='Upload ACM/IAM certificates and apply them to ELBs',
        usage=
        '''
        Scan for certificates in the current directory and upload to IAM:
            cert-uploader \\
                --scan \\
                iam \\
                --certificate-name cert-name
        
        Upload a new certificate to IAM:
            cert-uploader \\
                --certificate-path path/to/certificate.crt \\
                --private-key-path path/to/key.pem \\
                --certificate-chain-path path/to/chain.crt \\
                iam
                --certificate-name cert-name
        
        Upload a new certificate to ACM:
            cert-uploader \\
                --certificate-path path/to/certificate.crt \\
                --private-key-path path/to/key.pem \\
                --certificate-chain-path path/to/chain.crt \\
                acm
                
        Upload a new certificate to ACM and add tags:
            cert-uploader \\
                --certificate-path path/to/certificate.crt \\
                --private-key-path path/to/key.pem \\
                --certificate-chain-path path/to/chain.crt \\
                acm \\
                --tag Name=cert \\
                --tag App=app1
                
        Upload a new certificate to IAM and assign it to a load balancer:
            cert-uploader \\
                --certificate-path path/to/certificate.crt \\
                --private-key-path path/to/key.pem \\
                --certificate-chain-path path/to/chain.crt \\
                --load-balancer load-balancer-name \\
                iam \\
                --certificate-name cert-name
                
        Assign an existing IAM certificate to a load balancer:
            cert-uploader \\
                --load-balancer load-balancer-name \\
                iam \\
                --certificate-name cert-name
                
        Assign an existing ACM certificate to a load balancer:
            cert-uploader \\
                --load-balancer load-balancer-name \\
                acm \\
                --certificate-arn arn:aws:acm:REGION:ACCOUNT:certificate/CERTIFICATE_ID
                
        Upload a new IAM certificate at the path "/test" and assign it to a load balancer:
            cert-uploader \\
                --load-balancer load-balancer-name \\
                --certificate-path path/to/certificate.crt \\
                --private-key-path path/to/key.pem \\
                --certificate-chain-path path/to/chain.crt \\
                iam \\
                --certificate-name cert-name \\
                --iam-path /test
                
        Upload a new ACM certificate and assign it to a load balancer on port 8443:
            cert-uploader \\
                --load-balancer load-balancer-name \\
                --port 8443 \\
                --certificate-path path/to/certificate.crt \\
                --private-key-path path/to/key.pem \\
                --certificate-chain-path path/to/chain.crt \\
                acm
        '''
    )
    parser.set_defaults(type=None)
    subparsers = parser.add_subparsers()

    """
    Global Arguments
    """
    parser.add_argument(
        '--certificate-path',
        '-c',
        help='Path to certificate file'
    )

    parser.add_argument(
        '--private-key-path',
        '-k',
        help='Path to private key file'
    )

    parser.add_argument(
        '--certificate-chain-path',
        '-x',
        help='Path to the certificate chain'
    )

    parser.add_argument(
        '--load-balancer',
        '-l',
        help='Load balancer name'
    )

    parser.add_argument(
        '--port',
        '-P',
        help='Port of the listener on the ELB to assign this certificate to. Defaults to 443.',
        type=int,
        default=443
    )

    parser.add_argument(
        '--dry-run',
        '-d',
        help='Perform a dry run of the operations',
        action='store_true'
    )

    parser.add_argument(
        '--scan',
        '-s',
        help='Scan the current directory for certificates',
        action='store_true'
    )

    parser.add_argument(
        '--profile',
        '-p',
        help='AWS profile to use',
        default=None
    )

    parser.add_argument(
        '--role',
        '-r',
        help='AWS role to assume',
        default=None
    )

    """
    AWS Certificate Manager Arguments
    """
    acm_parser = subparsers.add_parser('acm', help='Upload the certificate to AWS Certificate Manager')
    acm_parser.set_defaults(type='acm')

    acm_parser.add_argument(
        '--certificate-arn',
        '-a',
        help='ARN of the certificate',
    )

    acm_parser.add_argument(
        '--tag',
        '-t',
        help='Add tags to the certificate',
        action='append'
    )

    """
    IAM Server Certificate Arguments
    """
    iam_parser = subparsers.add_parser('iam', help='Upload the certificate as an IAM Server Certificate')
    iam_parser.set_defaults(type='iam')

    iam_parser.add_argument(
        '--certificate-name',
        '-n',
        help='Unique name the certificate will be saved as in IAM',
    )

    iam_parser.add_argument(
        '--iam-path',
        '-i',
        help='Path in IAM in which the certificate will be stored. Defaults to "/"',
        default='/'
    )

    # Parse arguments
    options = parser.parse_args()

    # Create the uploader
    if options.type == 'iam':
        uploader = IAMCertificateUploader(profile=options.profile, role=options.role)
    elif options.type == 'acm':
        uploader = ACMCertificateUploader(profile=options.profile, role=options.role)
    else:
        parser.print_help()
        return

    # Upload certificate only if the corresponding files are passed in the arguments
    arn = None
    is_new_cert = False
    cert_info = {}

    # Get the certificate path information
    if options.scan:
        cert_info = scan_for_certificates()
    elif options.certificate_path and options.certificate_chain_path and options.private_key_path:
        cert_info = {
            'certificate': options.certificate_path,
            'private_key': options.private_key_path,
            'chain': options.certificate_chain_path
        }

    if cert_info:
        is_new_cert = True

        # Read the data
        cert_data, private_key_data, chain_data = uploader.read_certificate_files(
            cert_path=cert_info['certificate'],
            private_key_path=cert_info['private_key'],
            chain_path=cert_info['chain']
        )

        # Build arguments
        upload_kwargs = {
            'cert_data': cert_data,
            'private_key_data': private_key_data,
            'chain_data': chain_data,
            'dry_run': options.dry_run
        }

        if options.type == 'iam':
            upload_kwargs.update({
                'name': options.certificate_name,
                'iam_path': options.iam_path
            })

        # Perform the upload
        arn = uploader.upload_certificate(**upload_kwargs)

    else:
        # Fetch an existing certificate
        if options.type == 'acm' and options.certificate_arn:
            arn = options.certificate_arn
        elif options.type == 'iam' and options.certificate_name:
            certificate = uploader.get_server_certificate(options.certificate_name)
            arn = certificate.arn

    # Add tags to the certificate
    if options.type == 'acm' and options.tag:

        # Make sure an ARN was specified
        if not arn:
            print('Certificate ARN is not defined. Either upload a new certificate or specify an existing ARN.')
            exit(1)

        # Build the tags
        tag_dict = {}
        for item in options.tag:
            tag_parts = item.split('=')
            tag_dict.update({tag_parts[0]: tag_parts[1]})

        # Tag the certificate
        uploader.tag_certificate(arn=arn, tags=tag_dict)

    # Assign certificate to a load balancer
    if options.load_balancer:

        # Ensure an ARN has been found
        if not arn:
            print('ERROR: Certificate could not be found. Either upload a new certificate or specify an existing one.')
            exit(1)

        # Wait a couple seconds for the certificate to be ready
        if is_new_cert and not options.dry_run:
            for i in range(10, 0, -1):
                print('Waiting for certificate to propagate... %d' %i)
                sleep(1)

            # Add some spacing
            print()

        # Apply the certificate to the ELB
        uploader.assign_certificate(
            lb_name=options.load_balancer,
            lb_port=options.port,
            arn=arn,
            dry_run=options.dry_run
        )


if __name__ == '__main__':
    main()
