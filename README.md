## create_centos_ami_aws_china -- A tool to help import CentOS 7 Cloud vagrant box files as AWS ec2 images in AWS China

Based on: https://github.com/dliappis/amiimporter
With this tool you can convert your vagrant box file to an AWS AMI (i.e. an ec2 image).
Pulls CentOS Vagrant images from: http://cloud.centos.org/centos/${CentOS-version}/vagrant/x86_64/images/

Using an S3 bucket of your choice (or it will automatically create one) it will import the box and produce AMIs in 'cn-north-1', 'cn-northwest-1'


### Prerequisites and limitations

- The produced AMIs are suitable for [HVM virtualization](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/virtualization_types.html). pv requires more steps such as installing a pv enabled kernel.

- Creates a temporary S3 bucket in cn-north-1 
  This will be used to upload the images for conversion to AMI.

- Define roles and policies in AWS. In particular:
  - a `vmimport` service role and a policy attached to it, precisely as explained [in this AWS doc.](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/VMImportPrerequisites.html).

  - if you are an IAM AWS user (as opposed to root user) you **also** need to attach the following inline policy. Replace `<youraccountid>` [with your own](http://docs.aws.amazon.com/general/latest/gr/acct-identifiers.html).

    ```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "380",
            "Effect": "Allow",
            "Action": [
                "iam:CreateRole",
                "iam:PutRolePolicy"
            ],
            "Resource": [
                "arn:aws:iam::<youraccountid>:role/vmimport"
            ]
        }
    ]
}
    ```
- Fast upstream bandwidth as you will be uploading the image to s3!

### The required parameters are:

- `--centos-version`
  Version of CentOS that you want to use

- `--revision`
  Revision number you want to use, example "1803_01"

- `--s3bucket`
  `[--s3key]`

  The s3bucket and the (temporary) key used for uploading the VM.  If not specified, IAM permissions to create an S3 bucket are required.
  `s3key` is optional but if you omit it, `vboxfile` expect a certain naming convention like `osdistroVER-othermetadata.box`
  For example ./oel7.1-x86_64-virtualbox.box is a valid name.

- `--verbose`

  Displays progress statistics. Very useful if the script is not run from another program.

By default it will created copies of the temporary AMI that AWS import-image creates in three regions -- us-east-1, us-west-2, eu-central-1.
It easy to add or remove destination regions in [this list](https://github.com/dliappis/amiimporter/blob/master/amiimporter.py#L173)

#### Example


``` shell
$ ./amiimporter.py --s3bucket mybucket --vboxfile ./oel7.1-x86_64-virtualbox.box --verbose
INFO:root:Uploading ./tmpdir/packer-virtualbox-iso-1453910880-disk1.vmdk to s3
99%
INFO:root:Running: aws --region eu-west-1 ec2 import-image --cli-input-json {"Description": "temp-hvm-oel-7-20160129134521", "DiskContainers": [{"UserBucket": {"S3Bucket": "mybucket", "S3Key": "temp-hvm-oel-7-20160129134521"}, "Description": "temp-hvm-oel-7-20160129134521"}]}
INFO:root:AWS is now importing vdmk to AMI.
98%
INFO:root:Done, amiid is ami-TTTTTTTT
INFO:root:Successfully created temporary AMI ami-TTTTTTTT
Created ami-XXXXXXXX in region eu-central-1
Created ami-YYYYYYYY in region us-west-2
Created ami-ZZZZZZZZ in region us-east-1
INFO:root:Deregistering temporary AMI ami-TTTTTTTT
INFO:root:Deleting updateded s3 file s3://mybucket/temp-hvm-oel-7-20160129134521

```
