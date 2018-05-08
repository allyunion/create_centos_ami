#!/usr/bin/env python

"""This program helps create an AMI in AWS China regions"""

# pylint ignores
# pylint: disable=fixme
# pylint: disable=too-many-arguments
# pylint: disable=too-many-branches

# Python standard libraries
import argparse
import datetime
from hashlib import sha256
#import json
import logging
import os
import re
from urllib.request import HTTPError
import subprocess
import sys
#import time

# Custom Libraries

# boto libraries
from botocore.client import ClientError, Config
import boto3
#from boto3.s3.key import Key
#from boto3 import ec2

# Downloader library
from pySmartDL import SmartDL

SHA256SUM = ('http://cloud.centos.org/centos/{centos_version}/vagrant/'
             'x86_64/images/sha256sum.txt')
BASE_URL = ('http://cloud.centos.org/centos/{centos_version}/vagrant/'
              'x86_64/images/CentOS-{centos_version}-x86_64-Vagrant-{revision}'
              '.VirtualBox.box')
BASE_FILENAME = ('CentOS-{centos_version}-x86_64-Vagrant-{revision}'
                   '.VirtualBox.box')

def calculate_sha256_sum(filename):
    with open(filename, 'rb') as fopen:
        return sha256(fopen.read()).hexdigest()

class CentOSVagrantBox(object):
    """A CentOS Vagrant Box object"""
    def __init__(self, centos_version, revision, tmpdir='./tmpdir'):
        """Constructor"""
        self.data = {
            'CentOS Version': centos_version,
            'Revision': revision}
        self.filename = BASE_FILENAME.format(
            centos_version=centos_version,
            revision=revision)
        self.url = BASE_URL.format(
            centos_version=centos_version,
            revision=revision)
        self.tmpdir = tmpdir
        self.sha256sum = self.__get_sha256sum__()
        self.vmdkfile = None

    def __get_sha256sum__(self):
        """Returns the sha256sum file you want to download"""
        sha256sum_url = SHA256SUM.format(
            centos_version=self.data['CentOS Version'])
        shadl = SmartDL(sha256sum_url, self.tmpdir)
        try:
            shadl.start()
        except HTTPError as error:
            raise ValueError(
                str("Invalid CentOS Version: {}!".format(
                    self.data['CentOS Version']))) from error

        sha256sum_filename = os.path.join(self.tmpdir, 'sha256sum.txt')

        with open(sha256sum_filename) as fopen:
            for line in fopen.readlines():
                if self.filename in line:
                    return line.split(' ')[0]

        raise FileNotFoundError(self.filename + \
            " not found in sha256sum.txt file")

    def download(self):
        """Download the CentOS vagrant box file from cloud.centos.org"""

        downloader = SmartDL(
            self.url,
            self.tmpdir)

        downloader.add_hash_verification(
            'sha256',
            self.sha256sum)

        try:
            downloader.start()
        except HTTPError as error:
            raise ValueError(
                str(
                    "Invalid specified revision: {}".format(
                        self.data['Revision']))) from error

    def verify_local_copy(self):
        """Verify the local copy against known SHA256 hash"""

        fullpath = os.path.join(self.tmpdir, self.filename)
        return calculate_sha256_sum(fullpath) == self.sha256sum

    def convert_to_vmdk(self):
        """Extract box file and convert to OVA, as required for AWS Import"""

        fullpath = os.path.join(self.tmpdir, self.filename)

        try:
            # split basename/dirname;
            # use regexp as basename may contain dot for version
            parsed_vbox_filename = re.search(r'(.+)\.([A-Za-z]+)', fullpath)
            vboxprefix, vboxsuffix = parsed_vbox_filename.group(1), parsed_vbox_filename.group(2)
            subprocess.check_call(
                ["gunzip",
                 "-S",
                 "."+vboxsuffix,
                 os.path.basename(fullpath)
                ], cwd=self.tmpdir)
            subprocess.check_call(
                ["tar",
                 "xf",
                 os.path.basename(vboxprefix)
                ], cwd=self.tmpdir)

            self.vmdkfile = [
                file for file in os.listdir(
                    self.tmpdir) if '.vmdk' in file][0]

        except subprocess.CalledProcessError as error:
            raise Exception(
                str(
                    "Error while extracting supplied vbox file: {}".format(
                        self.filename))) from error
        except IndexError as error:
            raise Exception(
                str("Found more than one .vmdk files after extracting "
                    "{}").format(self.filename)) from error

    def get_tmpdir(self):
        """Returns the temp directory"""
        return self.tmpdir

    def get_vmdkfile(self):
        """Return vmdk filename"""
        return self.vmdkfile

class AWSConvertVMDK2AMI(object):
    """A class that handles the conversion of a VMDK file to AMI"""

    def __init__(
            self,
            filename,
            centos_version,
            revision,
            source_region,
            destination_regions=None,
            verification=False,
            aws_access_key=None,
            aws_secret_key=None,
            aws_profile=None):
        """Constructor"""
        if not os.path.exists(filename):
            raise FileNotFoundError(str(
                "Unable to locate vagrant box file: '{}'").format(
                    filename))
        self.fullpath = filename
        self.filename = os.path.basename(filename)
        self.source_region = source_region
        self.destination_regions = destination_regions
        self.verification = verification
        self.aws_credentials = {
            'AWS Access Key': aws_access_key,
            'AWS Secret Key': aws_secret_key,
            'AWS Profile': aws_profile,
            'Session': None
        }
        self.data = {
            'CentOS Version': centos_version,
            'Revision': revision
        }
        self.temporary = True
        if aws_profile is not None:
            if aws_access_key is None and aws_secret_key is None:
                self.aws_credentials['Session'] = boto3.Session(
                    profile_name=aws_profile,
                    region_name=source_region)
            else:
                raise ValueError(
                    'Cannot specify aws_profile & aws_access_key'
                    '/aws_secret_key')
        else:
            if aws_access_key is None and aws_secret_key is None:
                # If not specified, assume default
                self.aws_credentials['Session'] = boto3.Session(
                    profile_name='default',
                    region_name=source_region)
            else:
                self.aws_credentials['Session'] = boto3.Session(
                    aws_access_key_id=aws_access_key,
                    aws_secret_access_key=aws_secret_key,
                    region_name=source_region)

        if not isinstance(destination_regions, list):
            if destination_regions is None:
                destination_regions = [source_region]
            else:
                raise ValueError(
                    "Expected list or NoneType for destination_regions!")

        if re.match('^cn-', source_region):
            if not self.verification:
                raise ValueError(
                    'SHA256 verification must be True for AWS China!')

            # Make sure that only China region handle only in
            # an AWS China account
            for region in destination_regions:
                if not re.match('^cn-', region):
                    raise ValueError(str(
                        '{} is not located in China!'.format(region)))
        else:
            # Make sure no China region is in the list
            for region in destination_regions:
                if re.match('^cn-', region):
                    raise ValueError(str(
                        'Cannot handle an AWS China region with given '
                        'source_region of {}').format(source_region))

    def check_s3_bucket(self, bucketname=None, s3_access_key=None, s3_secret_key=None):
        """Check if the S3 bucket exists"""
        session = self.aws_credentials['Session']
        if s3_access_key and s3_secret_key:
            session = boto3.Session(
                aws_access_key_id=s3_access_key,
                aws_secret_access_key=s3_secret_key,
                region_name=self.source_region)
        client = session.client(
            's3',
            config=Config(signature_version='s3v4'))
        resource = session.resource('s3')
        bucket = None

        if bucketname is not None:
            try:
                response = client.head_bucket(Bucket=bucketname)
                self.temporary = False
            except ClientError:
                bucketname = None

        if bucketname is None:
            bucketname = 'CentOS.AMI.{}.{}'.format(
                self.filename,
                datetime.datetime.utcnow().strftime('%Y%m%d.%H%M%S'))
            if self.source_region != 'us-east-1':
                bucket = resource.create_bucket(
                    Bucket=bucketname,
                    ACL='private',
                    CreateBucketConfiguration={
                        'LocationConstraint': self.source_region})
            else:
                bucket = resource.create_bucket(
                    Bucket=bucketname,
                    ACL='private')

            # Enable encryption
            client.put_bucket_encryption(
                Bucket=bucket.name,
                ServerSideEncryptionConfiguration={
                    'Rules': [
                        {
                            'ApplyServerSideEncryptionByDefault': {
                                'SEEAlgorithm': 'AES256'
                            }
                        }
                    ]
                }
            )
        else:
            bucket = resource.Bucket(name=bucketname)

        return bucket

    def upload_to_s3(self, bucketname=None, s3_access_key=None, s3_secret_key=None):
        """Upload the VMDK file to S3 using s3_access_key & s3_secret_key
        credentials (if given) otherwise, default to aws_profile or
        aws_access_key/aws_secret key combination given when initialized"""
        session = self.aws_credentials['Session']
        if s3_access_key and s3_secret_key:
            session = boto3.Session(
                aws_access_key_id=s3_access_key,
                aws_secret_access_key=s3_secret_key,
                region_name=self.source_region)
        client = session.client(
            's3',
            config=Config(signature_version='s3v4'))
        resource = session.resource('s3')
        bucket = self.check_s3_bucket(
            bucketname=bucketname,
            s3_access_key=s3_access_key,
            s3_secret_key=s3_secret_key)

        if self.verification:
            sha256sum = calculate_sha256_sum(self.filename)

            extra_args = {'Metadata':
                {'x-amz-content-sha256': sha256sum}
            }

            # Upload the file
            client.upload_file(
                self.fullpath,
                bucket.name,
                self.filename,
                extra_args)

            # Re-download the file to verify
            s3_object = s3.Object(
                bucket.name,
                self.filename)
            s3_object.download_file(self.fullpath + '.verify')
            test_sha256 = calculate_sha256_sum(self.fullpath + '.verify')
            os.remove(self.fullpath + '.verify')
            if sha256sum != test_sha256:
                raise IOError(str(
                    'Calculated S3 SHA256 sum does '
                    'not match local copy:\n'
                    'local: "{}" != remote: "{}"').format(
                        sha256sum, test_sha256))
        else:
            client.upload_file(
                self.fullpath,
                bucket.name,
                self.filename,
                extra_args)

        return bucket.name

    def export_ami(self, bucketname=None, alt_access_key=None, alt_secret_key=None):
        session = self.aws_credentials['Session']
        if alt_access_key and alt_secret_key:
            session = boto3.Session(
                aws_access_key_id=alt_access_key,
                aws_secret_access_key=alt_secret_key,
                region_name=self.source_region)

        if bucketname is None:
           bucketname = self.upload_to_s3(bucketname, alt_access_key, alt_secret_key)

#        version, revision = re.findall(
#            'CentOS-(\d+)-x86_64-Vagrant-(\d+_\d+)\.VirtualBox',
#            self.filename)[0]
        description = 'CentOS Linux {} x86_64 HVM EBS {} {}'.format(
                self.data['CentOS Version'],
                self.data['Revision'],
                datetime.datetime.utcnow().strftime('%Y-%m-%d-%H%M%S'))

        ec2 = session.client('ec2', region_name=self.source_region)
        response = ec2.import_image(
            Architecture='x86_64',
            Description=description,
            DiskContainers=[
                {
                    'Description': description,
                    'DeviceName': '/dev/sda1',
                    'Format': 'VMDK',
                    'Url': 's3://{}/{}'.format(
                        bucketname, self.filename)
                }
            ],
            Hypervisor='xen',
            LicenseType='AWS',
            Platform='Linux'
        )
        temporary_ami = response['ImageId']

        amis_created = {}
        for region in self.destination_regions:
            ec2 = session.client('ec2', region_name=region)
            amis_created[region] = ec2.copy_image(
                Description=description,
                Name=description,
                SourceImageId=temporary_ami,
                SourceRegion=self.source_region)

        logging.info(str(
            "Deregistering temporary AMI {}".format(temporary_ami))
        ec2 = session.client('ec2', region_name=self.source_region)
        ec2.deregister_image(ImageId=temporary_ami)


def make_opt_parser():
    """Parse the options from command line"""
    parser = argparse.ArgumentParser(description='Import virtualbox vagrant box as AWS AMI')
    parser.add_argument('--region', default='cn-north-1')
    parser.add_argument('--s3bucket', help='s3bucket', default=None)
    parser.add_argument('--version',
                        required=False,
                        help='The CentOS version that you want to use',
                        default=7)
    parser.add_argument('--revision',
                        required=False,
                        help='The CentOS revision you want to use',
                        default='1803_01')
    parser.add_argument('--tempdir',
                        default='./tmpdir',
                        help="Temporary dir WARNING: "
                        "it will be cleaned up before and after operation",
                       )
    parser.add_argument('--verbose',
                        required=False,
                        help='Display status and progress',
                        action='store_true')
    parser.add_argument('--debug',
                        required=False,
                        action='store_true')
    return parser

def cleanup_temp_dir(parser):
    """Clean up the temporary directory"""
    if not os.path.isdir(parser.tempdir):
        os.mkdir(parser.tempdir)
        return
    for tfile in os.listdir(parser.tempdir):
        os.remove("{}/{}".format(parser.tempdir, tfile))

def main(opts):
    """Main function"""
    if opts.verbose:
        logging.basicConfig(level=logging.INFO)
    cleanup_temp_dir(opts)
    box = CentOSVagrantBox(
        centos_version=opts.version,
        revision=opts.revision,
        tmpdir=opts.tempdir)
    box.download()
    sys.exit(0)
    cleanup_temp_dir(opts)


if __name__ == '__main__':
    main(make_opt_parser().parse_args(sys.argv[1:]))
