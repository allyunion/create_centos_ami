#!/usr/bin/env python

"""This program helps create an AMI in AWS China regions"""

# pylint ignores
# pylint: disable=fixme

# Python standard libraries
import argparse
from hashlib import sha256
import json
import logging
import os
import re
import subprocess
import sys
import time

# Custom Libraries

# boto libraries
#import boto3
#from boto3.s3.key import Key
#from boto3 import ec2

# Downloader library
from pySmartDL import SmartDL

SHA256SUM = ('http://cloud.centos.org/centos/{centos_version}/vagrant/'
             'x86_64/images/sha256sum.txt')
__BASE_URL = ('http://cloud.centos.org/centos/{centos_version}/vagrant/'
              'x86_64/images/CentOS-{centos_version}-x86_64-Vagrant-{revision}'
              '.VirtualBox.box')
__BASE_FILENAME = ('CentOS-{centos_version}-x86_64-Vagrant-{revision}'
                   '.VirtualBox.box')

def make_opt_parser():
    """Parse the options from command line"""
    parser = argparse.ArgumentParser(description='Import virtualbox vagrant box as AWS AMI')
    parser.add_argument('--region', default='cn-north-1')
    parser.add_argument('--s3bucket', help='s3bucket', default=None)
    parser.add_argument('--s3key',
                        help='s3key e.g. centos-6-hvm-20160125111111'
                        'if ommited your vboxfile must look like e.g. centos6.7-20160101111111')
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

def download_vagrant_file(parser):
    """Download the Vagrant CentOS vagrant file from CentOS"""

    sha256sum_url = SHA256SUM.format(centos_version=parser.version)
    shadl = SmartDL(sha256sum_url, parser.tempdir)
    shadl.start()

    sha256sum_filename = os.path.join(parser.tempdir, 'sha256sum.txt')

    vagrant_filename = __BASE_FILENAME.format(centos_version=parser.version,
                                              revision=parser.revision)

    sha256_crc = None
    with open(sha256sum_filename) as fopen:
        for line in fopen.readlines():
            if vagrant_filename in line:
                sha256_crc = line.split(' ')[0]

    #sys.exit(0)

    url = __BASE_URL.format(centos_version=parser.version,
                            revision=parser.revision)
    downloader = SmartDL(url, parser.tempdir)
    downloader.start()

    fullpath = os.path.join(
        parser.tempdir,
        vagrant_filename)

    with open(fullpath, 'rb') as fread:
        check_sha256 = sha256(fread.read()).hexdigest()
        print(check_sha256 == sha256_crc)

    sys.exit(0)

def cleanup_temp_dir(parser):
    """Clean up the temporary directory"""
    if not os.path.isdir(parser.tempdir):
        os.mkdir(parser.tempdir)
        return
    for tfile in os.listdir(parser.tempdir):
        os.remove("{}/{}".format(parser.tempdir, tfile))


def vbox_to_vmdk(parser):
    """
    Extract vbox and convert to OVA, required for AWS import
    """
    vmdkfile = None
    fullpath = os.path.join(parser.tempdir,
                            __BASE_FILENAME.format(
                                centos_version=parser.version,
                                revision=parser.revision))
    try:
        # split basename/dirname; use regexp as basename may contain dot for version
        parsed_vbox_filename = re.search(r'(.+)\.([A-Za-z]+)', fullpath)
        vboxprefix, vboxsuffix = parsed_vbox_filename.group(1), parsed_vbox_filename.group(2)
        subprocess.check_call(
            ["gunzip",
             "-S",
             "."+vboxsuffix,
             os.path.basename(fullpath)
            ], cwd=parser.tempdir)
        subprocess.check_call(
            ["tar",
             "xf",
             os.path.basename(vboxprefix)
            ], cwd=parser.tempdir)

        vmdkfile = [
            file for file in os.listdir(parser.tempdir) if '.vmdk' in file][0]

    except subprocess.CalledProcessError as error:
        print("Error while extracting supplied vbox file: {}".format(parser.vboxfile))
        print("Reported error is: {}".format(error))
        sys.exit(1)
    except IndexError:
        print("Found more than one .vmdk files after extracting {}".format(parser.vboxfile))
        sys.exit(1)

    return "{}/{}".format(parser.tempdir, vmdkfile)


def upload_vmdk_to_s3(parser, vmdkfile):
    """Upload the extracted vmdk file to S3"""
    #def percent_cb(completed, total):
    #    """Internal function for progress meter"""
    #    if not parser.verbose:
    #        return
    #    sys.stdout.write("\r{}%".format(0 if completed == 0 else completed*100/total))
    #    sys.stdout.flush()
    logging.info(str("Uploading {} to s3".format(vmdkfile)))
    # boto2 doesn't have import-image yet; use aws cli command until we switch to boto3
    if not parser.s3key:
        (osname, osver, creationdate) = parse_vbox_name(os.path.basename(parser.vboxfile))
        s3file = "temp-hvm-{}-{}-{}".format(osname, osver, creationdate)
        parser.s3key = s3file
    else:
        s3file = parser.s3key
    #aws_access_key = os.environ.get('AWS_ACCESS_KEY_ID')
    #aws_secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY_ID')

#    s3conn = boto3.connect_s3(aws_access_key,
#                              aws_secret_key)

    # see https://github.com/boto/boto/issues/2741
#    bucket = s3conn.get_bucket(parser.s3bucket, validate=False)
#    bucket_location = bucket.get_location()
#    if bucket_location:
#        conn = boto3.s3.connect_to_region(bucket_location)
#        parser.region = bucket_location
#        bucket = conn.get_bucket(parser.s3bucket)
    # TODO check if key exists in bucket
#    s3key = Key(bucket)
#    s3key.key = s3file
#    s3key.set_contents_from_filename(vmdkfile, cb=percent_cb, num_cb=10)


def delete_s3key(parser):
    """Delete the s3 key"""
    #aws_access_key = os.environ.get('AWS_ACCESS_KEY_ID')
    #aws_secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY_ID')

    #s3conn = boto3.connect_s3(aws_access_key,
    #                          aws_secret_key)

    # see https://github.com/boto/boto/issues/2741
    #bucket = s3conn.get_bucket(parser.s3bucket, validate=False)
    #bucket_location = bucket.get_location()
    #if bucket_location:
    #    conn = boto3.s3.connect_to_region(bucket_location)
    #    parser.region = bucket_location
    #    bucket = conn.get_bucket(parser.s3bucket)
#    s3key = Key(bucket)
#    s3key.key = parser.s3key
    #logging.info(str("Deleting updateded s3 file s3://{}/{}".format(
    #    parser.s3bucket,
    #    parser.s3key)))
#    bucket.delete_key(s3key)
    print(parser)

def import_s3key_to_ami(parser):
    """Import s3 key to ami"""
    try:
        aws_disk_container = {'Description': parser.s3key,
                              'DiskContainers': [{
                                  'Description': parser.s3key,
                                  'UserBucket': {
                                      'S3Bucket': parser.s3bucket,
                                      'S3Key': parser.s3key}
                                  }]}
        aws_import_command = [
            'aws',
            '--region', parser.region,
            'ec2', 'import-image',
            '--cli-input-json', json.dumps(aws_disk_container)]
        logging.info(str(
            "Running: {}".format(' '.join(aws_import_command))))
        importcmd_resp = subprocess.check_output(aws_import_command)
    except subprocess.CalledProcessError:
        logging.error("An error occured while execuring"
                      " ".join(aws_import_command))

    logging.debug(json.loads(importcmd_resp))
    import_task_id = json.loads(importcmd_resp)['ImportTaskId']
    logging.info("AWS is now importing vdmk to AMI.")

    while True:
        aws_import_status_cmd = [
            'aws',
            '--region', parser.region,
            'ec2', 'describe-import-image-tasks',
            '--import-task-ids', import_task_id]
        import_progress_resp = json.loads(
            subprocess.check_output(
                aws_import_status_cmd))['ImportImageTasks'][0]
        if 'Progress' not in import_progress_resp.keys() \
                and 'ImageId' in import_progress_resp.keys():
            temporary_ami = import_progress_resp['ImageId']
            logging.info(str(
                "Done, ami-id is {}".format(temporary_ami)))
            break
        else:
            import_progress = import_progress_resp['Progress']
            sys.stdout.write("\r%s%%" % import_progress)
            sys.stdout.flush()
        time.sleep(5)
    logging.info(str(
        "Successfully created temporary AMI {}".format(temporary_ami)))

    # import-image created random name and description. Those can't be modified.
    # Create copies for all regions with the right metadata instead.
#    amis_created = {}
#    for region in ['cn-north-1', 'cn-northeast-1']:
#        ec2conn = ec2.connect_to_region(region)
#        amis_created[region] = ec2conn.copy_image(
#            parser.region,
#            temporary_ami,
#            name=parser.s3key,
#            description=parser.s3key)
#        print("Created {} in region {}".format(
#            amis_created[region].image_id,
#            region))

    logging.info(str(
        "Deregistering temporary AMI {}".format(temporary_ami)))
    #ec2conn = ec2.connect_to_region(parser.region)
    #ec2conn.deregister_image(temporary_ami)


def parse_vbox_name(vboxname):
    """Parse the box name"""
    vbox_tokens = vboxname.split('-')
    osname = re.search('^[a-zA-Z]+', vbox_tokens[0]).group(0)
    osver = re.search(r'[0-9\.]+', vbox_tokens[0]).group(0)

    if osname == 'ubuntu':
        osver = osver
    elif osname == 'debian':
        osver = osver.split('.')[0]
    elif osname == 'opensuse' or osname == 'sles' or osname == 'oel':
        osver = osver.split('.')[0]
    else:
        osver = osname

    # isodate in UTC
    creationdate = time.strftime("%Y%m%d%H%M%S", time.gmtime())

    return (osname, osver, creationdate)


def main(opts):
    """Main function"""
    if opts.verbose:
        logging.basicConfig(level=logging.INFO)
    cleanup_temp_dir(opts)
    download_vagrant_file(opts)
    sys.exit(0)
    vmdkfile = vbox_to_vmdk(opts)
    upload_vmdk_to_s3(opts, vmdkfile)
    import_s3key_to_ami(opts)
    delete_s3key(opts)
    cleanup_temp_dir(opts)

if __name__ == '__main__':
    main(make_opt_parser().parse_args(sys.argv[1:]))
