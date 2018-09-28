# Certificate Uploader

Upload ACM/IAM Server Certificates and apply them to ELBs


## Requirements
Python 2.7 or 3.6

## Installation
```
pip install cert-uploader
```

## Usage

### IAM

Scan for certificates in the current directory and upload to IAM:
```
cert-uploader   --scan \
                iam \
                --certificate-name cert-name
```

Upload a new certificate to IAM:
```
cert-uploader   --certificate-path path/to/certificate.crt \
                --private-key-path path/to/key.pem \
                --certificate-chain-path path/to/chain.crt \
                iam \
                --certificate-name cert-name
```

Upload a new certificate to IAM and assign it to a load balancer:
```
cert-uploader   --certificate-path path/to/certificate.crt \
                --private-key-path path/to/key.pem \
                --certificate-chain-path path/to/chain.crt \
                --load-balancer load-balancer-name \
                iam \
                --certificate-name cert-name
```

Upload a new IAM certificate at the path "/test" and assign it to a load balancer:
```
cert-uploader   --certificate-path path/to/certificate.crt \
                --private-key-path path/to/key.pem \
                --certificate-chain-path path/to/chain.crt \
                --load-balancer load-balancer-name \
                iam \
                --certificate-name cert-name \
                --iam-path /test
```

Upload a new IAM certificate and assign it to a load balancer on port 8443:
```
cert-uploader   --load-balancer load-balancer-name \
                --port 8443 \
                --certificate-path path/to/certificate.crt \
                --private-key-path path/to/key.pem \
                --certificate-chain-path path/to/chain.crt \
                iam \
                --certificate-name cert-name
```

Assign an existing IAM certificate to a load balancer:
```
cert-uploader   --load-balancer load-balancer-name \
                iam \
                --certificate-name cert-name
```

### ACM

Scan for certificates in the current directory and upload to ACM:
```
cert-uploader   --scan \
                acm
```

Upload a new certificate to ACM:
```
cert-uploader   --certificate-path path/to/certificate.crt \
                --private-key-path path/to/key.pem \
                --certificate-chain-path path/to/chain.crt \
                acm
```

Upload a new certificate to ACM and add tags:
```
cert-uploader   --certificate-path path/to/certificate.crt \
                --private-key-path path/to/key.pem \
                --certificate-chain-path path/to/chain.crt \
                acm \
                --tag Name=cert \
                --tag App=app1
```

Upload a new certificate to ACM and assign it to a load balancer:
```
cert-uploader   --certificate-path path/to/certificate.crt \
                --private-key-path path/to/key.pem \
                --certificate-chain-path path/to/chain.crt \
                --load-balancer load-balancer-name \
                acm \
                --tag Name=cert \
                --tag App=app1
```

Upload a new ACM certificate and assign it to a load balancer on port 8443:
```
cert-uploader   --load-balancer load-balancer-name \
                --port 8443 \
                --certificate-path path/to/certificate.crt \
                --private-key-path path/to/key.pem \
                --certificate-chain-path path/to/chain.crt \
                acm
```

Assign an existing ACM certificate to a load balancer:
```
cert-uploader   --load-balancer load-balancer-name \
                acm \
                --certificate-arn arn:aws:acm:REGION:ACCOUNT:certificate/CERTIFICATE_ID
```

## Credentials

### Profile

AWS credentials can be passed in using the `--profile` command line argument:

```
cert-uploader   --certificate-path path/to/certificate.crt \
                --private-key-path path/to/key.pem \
                --certificate-chain-path path/to/chain.crt \
                --profile profile-name \
                acm
```

or by setting the `AWS_PROFILE` environment variable:

```
export AWS_PROFILE=profile-name
cert-uploader   --certificate-path path/to/certificate.crt \
                --private-key-path path/to/key.pem \
                --certificate-chain-path path/to/chain.crt \
                acm
```

### Access Keys

If a profile is not configured, the `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_DEFAULT_REGION`
environment variables can be set and used for authentication.

### Roles

Roles can be assumed using the `--role` command line argument:

```
cert-uploader   --certificate-path path/to/certificate.crt \
                --private-key-path path/to/key.pem \
                --certificate-chain-path path/to/chain.crt \
                --role role-arn \
                acm
```