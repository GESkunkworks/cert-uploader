from setuptools import setup, find_packages

with open('README.md', 'r') as f:
    long_description = f.read()

setup(
    name='cert-uploader',
    description='Upload ACM/IAM Server Certificates to AWS and apply them to ELBs',
    long_description=long_description,
    long_description_content_type='text/markdown',
    keywords='certificate cert uploader tools aws iam acm',
    url='https://github.com/GESkunkworks/cert-uploader',
    use_scm_version=True,
    author='Michael Palmer',
    author_email='github@michaeldpalmer.com',
    packages=find_packages(),
    setup_requires=['setuptools_scm~=3.1.0'],
    install_requires=[
        'boto3~=1.7.16',
        'cryptography~=2.3.0',
        'pyOpenSSL~=17.5.0',
        'scandir~=1.7;python_version<"3.0"',
        'six~=1.11.0'
    ],
    entry_points={
        'console_scripts': [
            'cert-uploader = cert_uploader.cli:main',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.6',
        'Development Status :: 4 - Beta',
        'Topic :: Utilities'
    ]
)
