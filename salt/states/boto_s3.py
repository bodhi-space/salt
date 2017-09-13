# -*- coding: utf-8 -*-
'''
Manage S3 Resources
=================

.. versionadded:: 2016.3.0

Manage S3 resources.  Be aware that this interacts with Amazon's services, and so may incur charges.

This module uses ``boto3``, which can be installed via package, or pip.

This module accepts explicit AWS credentials but can also utilize IAM roles assigned to the instance
through Instance Profiles.  Dynamic credentials are then automatically obtained from AWS API and no
further configuration is necessary. More information available `here
<http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html>`_.

If IAM roles are not used you need to specify them either in a pillar file or in the minion's config
file:

.. code-block:: yaml

    s3.keyid: GKTADJGHEIQSXMKKRBJ08H
    s3.key: askdjghsdfjkghWupUjasdflkdfklgjsdfjajkghs

It's also possible to specify ``key``, ``keyid`` and ``region`` via a profile, either passed in as
a dict, or as a string to pull from pillars or minion config:

.. code-block:: yaml

    myprofile:
        keyid: GKTADJGHEIQSXMKKRBJ08H
        key: askdjghsdfjkghWupUjasdflkdfklgjsdfjajkghs
        region: us-east-1

.. code-block:: yaml

    Ensure s3 object exists:
        boto_s3.object_present:
            - Bucket: a_s3_bucket
            - Key: path/to/a/file/in/the/bucket
            - FileName: /path/to/local/file
            - profile: my-profile

:depends: boto3
'''

# Import Python Libs
from __future__ import absolute_import
import copy
import difflib
import logging
import hashlib
import yaml

# Import Salt libs
import salt.ext.six as six
import salt.utils

log = logging.getLogger(__name__)


def __virtual__():
    '''
    Only load if boto is available.
    '''
    if 'boto_s3.get_object_metadata' not in __salt__:
        return False
    return 'boto_s3'


def object_present(name, region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Ensure a file exists in S3 with the exact contents desired.

    NOTE THAT due to the extraordinarily byzantine history and logic of the ACL/AccessControl/Grant
    system within S3 and the AWS API infterface thereto, it is a monummental task to support them
    in an idempotent way.  Thus, at the moment, this state will ACCEPT these arguments, and SET them
    on the objects as passed, but because we can't verify their current state against the desired,
    this will lead to re-application at every state run.  This is undesireable in almost all cases,
    so for the moment it's advised that use of these options be avoided.  Such parameters will be
    flagged below as "non-idempotent".

    name
        The name of the state definition.  If either Bucket or Key is not provided explicitly,
        this will be used to determine the location of the object in S3, by splitting on the first
        slash and using the first part as the Bucket name and the remainder as the S3 Key.

    Bucket
        Name of the bucket to which the PUT operation was initiated.

    Key
        Object key for which the PUT operation was initiated.

    FileName
        Absolute path (that is, starting with a `/`) to a file on the local minion filesystem which
        is to be put to the S3 bucket.

        Mutually exclusive with `Body`.

    Body
        Object data.  Note that this can be either a `file`-like object, e.g. something with a
        `read()` method, OR a sequence of bytes, in which case it will be treated as a blob of bytes
        (as in b'\\Xnn\\Xnn...') to be written literally to the S3 object.  In practice, the
        FileName param (above) is easier to use in most scenarios.  This option IS very powerful,
        however; as it can, with some effort, read from sockets, streams, or anything else providing
        a `file`-like interface in python.

        Mutually exclusive with `FileName`.

    ACL
        The canned ACL to apply to the object.  NON-IDEMPOTENT
        Valid values:
            private
            public-read
            public-read-write
            authenticated-read
            aws-exec-read
            bucket-owner-read
            bucket-owner-full-control

    CacheControl
        Specifies caching behavior along the request/reply chain.

    ContentDisposition
        Specifies presentational information for the object.

    ContentEncoding
        Specifies what content encodings have been applied to the object and thus what decoding
        mechanisms must be applied to obtain the media-type referenced by the Content-Type header
        field.

    ContentLanguage
        The language the content is in.

    ContentLength
        Size of the body in bytes. This parameter is useful when the size of the body cannot be
        determined automatically.

    ContentMD5
        The base64-encoded 128-bit MD5 digest of the part data.

    ContentType
        A standard MIME type describing the format of the object data.

    Expires
        The date and time at which the object is no longer cacheable.

    GrantFullControl
        Gives the grantee READ, READ_ACP, and WRITE_ACP permissions on the object.  NON-IDEMPOTENT

    GrantRead
        Allows grantee to read the object data and its metadata.  NON-IDEMPOTENT

    GrantReadACP
        Allows grantee to read the object ACL.  NON-IDEMPOTENT

    GrantWriteACP
        Allows grantee to write the ACL for the applicable object.  NON-IDEMPOTENT

    Metadata
        A dict of metadata to store with the object in S3.

    ServerSideEncryption
        The Server-side encryption algorithm used when storing this object in S3 (e.g., AES256,
        aws:kms).

    StorageClass
        The type of storage to use for the object.  Defaults to 'STANDARD'.
        Valid values:
            STANDARD
            REDUCED_REDUNDANCY
            STANDARD_IA

    WebsiteRedirectLocation
        If the bucket is configured as a website, redirects requests for this object to another
        object in the same bucket or to an external URL.  Amazon S3 stores the value of this header
        in the object metadata.

    SSECustomerAlgorithm
        Specifies the algorithm to use to when encrypting the object (e.g., AES256).

    SSECustomerKey
        Specifies the customer-provided encryption key for Amazon S3 to use in encrypting data.
        This value is used to store the object and then it is discarded; Amazon does not store the
        encryption key. The key must be appropriate for use with the algorithm specified in
        SSECustomerAlgorithm.

    SSECustomerKeyMD5
        Specifies the 128-bit MD5 digest of the encryption key according to RFC 1321. Amazon S3
        uses this header for a message integrity check to ensure the encryption key was transmitted
        without error.  Please note that this parameter is automatically populated if it is not
        provided, so including this parameter is not required.

    SSEKMSKeyId
        Specifies the AWS KMS key ID to use for object encryption.  All GET and PUT requests for an
        object protected by AWS KMS will fail if not made via SSL or using SigV4.  Documentation on
        configuring any of the officially supported AWS SDKs and CLI can be found at
        http://docs.aws.amazon.com/AmazonS3/latest/dev/UsingAWSSDK.html#specify-signature-version

    RequestPayer
        Confirms that the requester knows that she or he will be charged for the request.  Bucket
        owners need not specify this parameter in their requests.  Documentation on downloading
        objects from requester pays buckets can be found at
        http://docs.aws.amazon.com/AmazonS3/latest/dev/ObjectsinRequesterPaysBuckets.html

    Tagging
        The tag-set for the object.  The tag-set may be a dictionary of AWS tags in the standard
        AWS "list of dicts" format, a simple dict of {<tag>: <value>, ...} pairs, or a string.
        NOTE THAT if it is passed as a string, the tagset MUST be encoded as URL Query Parameters
        by the caller before passing to this function.  The `canonical_to_tagstring()` function
        below is a convenient way to achieve this encoding.

    region
        Region to connect to.

    key
        Secret key to be used.

    keyid
        Access key to be used.

    profile
        A dict with region, key and keyid, or a pillar key (string) which contains a dict with
        region, key and keyid.
    '''
    ret = {'name': name, 'result': True, 'comment': '', 'changes': {}}
    kwargs = {k: v for k, v in kwargs.items() if not k.startswith('_')}

    # Special munging - extract Bucket and Key from name if they're not passed
    bucket, _, s3_key = name.partition('/')
    kwargs['Bucket'] = kwargs.get('Bucket', bucket)
    kwargs['Key'] = kwargs.get('Key', s3_key)

    # Dupes check in exec module function, but makes logic below easier
    if 'FileName' in kwargs and 'Body' in kwargs:
        ret['result'] = False
        msg = '`Body` and `FileName` are mutually exclusive parameters.'
        ret['comment'] = msg
        log.error(msg)
        return ret

    # Honor an explicit ContentMD5 if passed in.  We must assume you know
    # what you are about :)
    if 'ContentMD5' not in kwargs:
        if 'Body' in kwargs and isinstance(kwargs['Body'], file):
            # Not safe to auto-calculate size of a `file` object - if we read to EOF it might well
            # bork whatever is pushing the data from the other side...
            log.warning("Can't auto-determine the ContentMD5 of a `file` object - please set "
                        "ContentND5 explicitly in the state definition.")
        md5 = hashlib.md5()
        try:
            if 'FileName' in kwargs:
                with open(kwargs['FileName']) as f:
                    for hunk in iter(lambda: f.read(4096), ''):
                        md5.update(hunk)
                kwargs['ContentMD5'] = md5.digest().encode('base64').strip()
            elif 'Body' in kwargs:
                if isinstance(kwargs['Body'], six.string_types):
                    md5.update(kwargs['Body'])
                    kwargs['ContentMD5'] = md5.digest().encode('base64').strip()
        except IOError as e:
            ret['result'] = False
            msg = "Could not read local file {0}: {1}".format(kwargs['FileName'], e)
            ret['comment'] = msg
            log.error(msg)
            return ret

    # Clean up our args for head_object()
    HEAD_ARGS = ['Bucket', 'IfMatch', 'IfModifiedSince', 'IfNoneMatch', 'IfUnmodifiedSince', 'Key',
                 'PartNumber', 'Range', 'RequestPayer', 'SSECustomerAlgorithm', 'SSECustomerKey',
                 'SSECustomerKeyMD5', 'VersionId']
    desc = {k: v for k, v in six.iteritems(kwargs) if k in HEAD_ARGS}
    r = __salt__['boto_s3.head_object'](region=region, key=key, keyid=keyid, profile=profile,
                                        **desc)
    if 'error' in r and r['error'].get('Code') != '404':  # 404 == 'Not Found'
        ret['result'] = False
        msg = 'Error when checking if S3 object exists: {0}.'.format(r['error'])
        ret['comment'] = msg
        log.error(msg)
        return ret

    # Note that S3 semantics are such that "metadata" changes ABOUT an object ALSO create a new
    # version in the bucket (if versioned) or overwrite the old object (if not).  Therefore ANY
    # change is a "push" by definition.
    push = False
    current = r.get('result', {})
    if not current:
        push = True
    else:
        if 'ContentMD5' not in current:
            # Oops, nothing to compare with, so all we can do is push...
            log.debug('{0}/{1} exists but ContentMD5 not set.  Will push a new revision of the '
                      'file.'.format(kwargs['Bucket'], kwargs['Key']))
            push = True
        else:
            if kwargs.get('ContentMD5', '') != current['ContentMD5']:
                push = True

    for k, v in kwargs.items():
        if k in current:
            if current[k] != v:
                push = True

    if not push:
        msg = 'S3 object {0} is present and in the desired state.'.format(name)
        log.info(msg)
        ret['comment'] = msg
        return ret

    # OK, looks like we have some changes to apply
    changes_diff = ''.join(difflib.unified_diff(
        _yaml_safe_dump(current).splitlines(True),
        _yaml_safe_dump(kwargs).splitlines(True),
    ))

    if __opts__['test']:
        ret['result'] = None
        ret['comment'] = 'S3 object {0} would be {1}d.'.format(name, action)
        ret['pchanges'] = {'diff': changes_diff}
        return ret

    r = __salt__['boto_s3.upload_file'](
        name,
        source,
        extra_args=combined_extra_args,
        region=region,
        key=key,
        keyid=keyid,
        profile=profile,
    )

    if 'error' in r:
        ret['result'] = False
        ret['comment'] = 'Failed to {0} S3 object: {1}.'.format(
            action,
            r['error'],
        )
        return ret

    ret['result'] = True
    ret['comment'] = 'S3 object {0} {1}d.'.format(name, action)
    ret['comment'] += '\nChanges:\n{0}'.format(changes_diff)
    ret['changes'] = {'diff': changes_diff}
    return ret


def _yaml_safe_dump(attrs):
    '''Safely dump YAML using a readable flow style'''
    dumper = __utils__['yamldumper.get_dumper']('IndentedSafeOrderedDumper')
    return yaml.dump(attrs, default_flow_style=False, Dumper=dumper)
