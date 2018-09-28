## Unreleased

## 1.1.4
- Added support for rolling back a certificate assignment

## 1.1.3
- Add support for assuming a role

## 1.1.2
- Change input of `upload_certificate` to accept the certificate data instead of file paths

## 1.1.1
- Fix exception not being caught when a named ELB and ALB do not exist
- Created helper method for getting ELB/ALB

## 1.1.0
- Added support for specifying the AWS profile via command line (`--profile`)
- Added support for scanning the current directory for certificates and keys using the `--scan` argument

## 1.0.0
- Initial release
