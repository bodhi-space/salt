# -*- coding: utf-8 -*-
'''
Connection module for Amazon S3 using boto3

.. versionadded:: develop

:configuration: This module accepts explicit AWS credentials but can also
    utilize IAM roles assigned to the instance through Instance Profiles or
    it can read them from the ~/.aws/credentials file or from these
    environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY.
    Dynamic credentials are then automatically obtained from AWS API and no
    further configuration is necessary.  More information available at:

    .. code-block:: text

        http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/
            iam-roles-for-amazon-ec2.html

        http://boto3.readthedocs.io/en/latest/guide/
            configuration.html#guide-configuration

    If IAM roles are not used you need to specify them either in a pillar or
    in the minion's config file:

    .. code-block:: yaml

        s3.keyid: GKTADJGHEIQSXMKKRBJ08H
        s3.key: askdjghsdfjkghWupUjasdflkdfklgjsdfjajkghs

    A region may also be specified in the configuration:

    .. code-block:: yaml

        s3.region: us-east-1

    If a region is not specified, the default is us-east-1.

    It's also possible to specify key, keyid and region via a profile, either
    as a passed in dict, or as a string to pull from pillars or minion config:

    .. code-block:: yaml

        myprofile:
            keyid: GKTADJGHEIQSXMKKRBJ08H
            key: askdjghsdfjkghWupUjasdflkdfklgjsdfjajkghs
            region: us-east-1

:depends: boto3
'''
# keep lint from choking on _get_conn and _cache_id
# pylint: disable=E0602

# Import Python libs
from __future__ import absolute_import
import logging
import json
import difflib

# Import Salt libs
from salt.utils.versions import LooseVersion as _LooseVersion
from salt.ext import six
from salt.ext.six.moves.urllib.parse import urlencode, parse_qs
import boto3.utils

log = logging.getLogger(__name__)

# pylint: disable=import-error
try:
    # pylint: disable=unused-import
    import boto3
    # pylint: enable=unused-import
    import botocore
    logging.getLogger('boto3').setLevel(logging.CRITICAL)
    HAS_BOTO = True
except ImportError:
    HAS_BOTO = False
# pylint: enable=import-error


def __virtual__():
    '''
    Only load if boto libraries exist and if boto libraries are greater than
    a given version.
    '''
    needed_boto3_version = '1.2.1'
    msg = 'The boto_s3 module cannot be loaded: {0}.'
    if not HAS_BOTO:
        return (False, msg.format('boto3 libraries not found'))
    if _LooseVersion(boto3.__version__) < _LooseVersion(needed_boto3_version):
        submsg = 'boto3 library version {0} is required'.format(needed_boto3_version)
        return (False, msg.format(submsg))
    return True


def __init__(opts):  # pylint: disable=unused-argument
    if HAS_BOTO:
        __utils__['boto3.assign_funcs'](__name__, 's3')


def _strerror(e):
    ret = getattr(e, 'response', {}).get('Error', {}).get('Message')
    ret = ret if ret else '{0}'.format(e.args[0]) if hasattr(e, 'args') and len(e.args) else None
    ret = ret if ret else getattr(e, 'message', '')
    log.error(ret)
    return ret


def delete_object(region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Note that the semantics of "deleting" objects from S3 is almost NOTHING like what you might
    expect from experience with a filesystem.  AWS makes every effort to never delete data from S3,
    and extra hoops must be jumped through if you really want it to happen.  The terminology used
    ('delete markers' and 'null versions') is equally strange.

    A good overview of how S3 treats objects, object versions, and delete requests WRT these is
    .. _`Object Versioning`: http://docs.aws.amazon.com/AmazonS3/latest/dev/ObjectVersioning.html
    and
    .. _`Deleting Object Versions`: http://docs.aws.amazon.com/AmazonS3/latest/dev/DeletingObjectVersions.html

    On an unversioned bucket, all objects are null versions, so just delete the requested object.

    On a versioned bucket, and without providing a VersionId, insert a delete marker and make it
    the current version of the object.

    On a versioned bucket, with a provided VersionId, delete that version from the bucket without
    adding a delete marker.  Only the bucket owner can delete a specified object version.

    On a versioned bucket, and without providing a VersionId, remove the null version (if there is
    one) of the object and insert a delete marker in its place, which becomes the current null
    version of the object.  If there isn't a null version, delete nothing and just insert a delete
    marker, which becomes the current null version.

    On a version-suspended bucket, with a provided VersionId, delete that version from the bucket
    without adding a delete marker.  Only the bucket owner can delete a specified object version.

    See also:
    .. _`AWS API Documentation`: https://docs.aws.amazon.com/goto/WebAPI/s3-2006-03-01/DeleteObject

    Bucket
        The S3 bucket within which to look for the given Key (file).

    Key
        The path within the Bucket (without leading `/`) to the file being managed.

    MFA
        The concatenation of the authentication device's serial number, a space, and the value that
        is displayed on your authentication device.

    VersionId
        VersionId used to reference a specific version of the object.

    RequestPayer
        Confirms that the requester knows they will be charged for the request.  Bucket owners need
        not specify this parameter in their requests.  Info on requester pays buckets can be found at
        http://docs.aws.amazon.com/AmazonS3/latest/dev/ObjectsinRequesterPaysBuckets.html

    CLI Example:

    .. code-block:: bash

        salt myminion boto_s3.delete_object Bucket=my_bucket Key=path/to/an/object profile=profile
    '''
    kwargs = {k: v for k, v in kwargs.items() if not k.startswith('_')}
    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)

    try:
        ret = conn.delete_object(**kwargs)
        ret.pop('ResponseMetadata', None)
    except (botocore.exceptions.ClientError, botocore.exceptions.ParamValidationError) as e:
        return {'error': _strerror(e)}

    return {'result': ret}


def delete_object_tagging(region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Removes the tag-set from an existing object.  Note that this is all-or-nothing - there is not
    provision in the underlying AWS call to delete only certain tags and leave others.

    Bucket
        The S3 bucket within which to look for the given Key (file).

    Key
        The path within the Bucket (without leading `/`) to the file being managed.

    VersionId
        VersionId used to reference a specific version of the object.

    CLI Example:

    .. code-block:: bash

        salt myminion boto_s3.delete_object_tagging Bucket=my_bucket Key=an/object profile=profile
    '''
    kwargs = {k: v for k, v in kwargs.items() if not k.startswith('_')}
    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)

    try:
        ret = conn.delete_object_tagging(**kwargs)
        ret.pop('ResponseMetadata', None)
    except (botocore.exceptions.ClientError, botocore.exceptions.ParamValidationError) as e:
        return {'error': _strerror(e)}

    return {'result': ret}


def delete_objects(region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Delete multiple objects from a bucket using a single request.  One may specify up to 1000 keys.
    Note that some deletions may generate errors without preventing the deletion of any other
    objects.  Thus a separate "Errors" structure is returned along with the Deleted list detailing
    successful deletions.

    Bucket
        The S3 bucket within which to look for the given Key(s) (file(s)).

    Delete
        A dict defining which objects in the given bucket to delete, of the form:
        .. code-block:: python
            {
                'Objects': [
                    {
                        'Key': 'string',
                        'VersionId': 'string'
                    },
                    ...
                ]
            }
        Note:  To ensure sane behavior, the (very poorly documented) Quiet flag to the Delete
        parameter is explicitly not supported.

    MFA
        The concatenation of the authentication device's serial number, a space, and the value that
        is displayed on your authentication device.

    RequestPayer
        Confirms that the requester knows they will be charged for the request.  Bucket owners need
        not specify this parameter in their requests.  Info on requester pays buckets can be found at
        http://docs.aws.amazon.com/AmazonS3/latest/dev/ObjectsinRequesterPaysBuckets.html

    CLI Example:

    .. code-block:: bash

        salt myminion boto_s3.delete_objects Bucket=my_bucket profile=profile \
                        Delete='{Objects:[{Key:object1}, {Key:path/to/object2}]}'
    '''
    kwargs = {k: v for k, v in kwargs.items() if not k.startswith('_')}
    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)

    try:
        ret = conn.delete_objects(**kwargs)
        ret.pop('ResponseMetadata', None)
    except (botocore.exceptions.ClientError, botocore.exceptions.ParamValidationError) as e:
        return {'error': _strerror(e)}

    return {'result': ret}



def describe_object(region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Gather and return all available info about an S3 object.

    Bucket
        The S3 bucket within which to look for the given Key (file).

    Key
        The path within the Bucket (without leading `/`) to the file being managed.

    IfMatch
        Return the object only if its entity tag (ETag) is the same as the one specified, otherwise
        return a 412 (precondition failed).

    IfModifiedSince
        Return the object only if it has been modified since the specified time, otherwise return
        a 304 (not modified).

    IfNoneMatch
        Return the object only if its entity tag (ETag) is different from the one specified,
        otherwise return a 304 (not modified).

    IfUnmodifiedSince
        Return the object only if it has not been modified since the specified time, otherwise
        return a 412 (precondition failed).

    Range
        Downloads the specified range bytes of an object.  For more information about the HTTP
        Range header, go to http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.35.

    VersionId
        VersionId used to reference a specific version of the object.

    SSECustomerAlgorithm
        Specifies the algorithm to use to when encrypting the object (e.g., AES256).

    SSECustomerKey
        Specifies the customer-provided encryption key for Amazon S3 to use in encrypting data.
        This value is used to store the object and then it is discarded; Amazon does not store the
        encryption key.  The key must be appropriate for use with the algorithm specified in the
        value of SSECustomerAlgorithm.

    SSECustomerKeyMD5
        Specifies the 128-bit MD5 digest of the encryption key according to RFC 1321.  Amazon S3
        uses this header for a message integrity check to ensure the encryption key was transmitted
        without error.  Please note that this parameter not manditory - it is automatically
        populated not provided.

    RequestPayer
        Confirms that the requester knows they will be charged for the request.  Bucket owners need
        not specify this parameter in their requests.  Info on requester pays buckets can be found at
        http://docs.aws.amazon.com/AmazonS3/latest/dev/ObjectsinRequesterPaysBuckets.html

    PartNumber
        Part number of the object being read.  This is a positive integer between 1 and 10,000.
        Effectively performs a 'ranged' HEAD request for the part specified.  Useful querying about
        the size of the part and the number of parts in this object.

    CLI Example:

    .. code-block:: bash

        salt myminion boto_s3.describe_object Bucket=my_bucket Key=path/to/an/object profile=profile
    '''
    kwargs = {k: v for k, v in kwargs.items() if not k.startswith('_')}
    r = head_object(region=region, key=key, keyid=keyid, profile=profile, **kwargs)
    if 'error' in r:
        log.error(r['error'])
        return r
    ret = r.get('result', None)
    if ret is None:
        return {'result': ret}
    get_acl_args = {'Bucket', 'Key', 'VersionId', 'RequestPayer'}
    acl_args = {arg: kwargs[arg] for arg in get_acl_args if arg in kwargs}
    r = get_object_acl(region=region, key=key, keyid=keyid, profile=profile, **acl_args)
    ret.update({'ACL': r['result']}) if r.get('result') is not None else None
    get_tagging_args = {'Bucket', 'Key', 'VersionId'}
    tag_args = {arg: kwargs[arg] for arg in get_tagging_args if arg in kwargs}
    r = get_object_tagging(region=region, key=key, keyid=keyid, profile=profile, **tag_args)
    ret.update(r['result']) if r['result'].get('TagSet') else None
    return {'result': ret}


def get_object_acl(region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Get ACL data for an S3 object.

    Bucket
        The S3 bucket within which to look for the given Key (file).

    Key
        The path within the Bucket (without leading `/`) to the file being managed.

    VersionId
        VersionId used to reference a specific version of the object.

    RequestPayer
        Confirms that the requester knows they will be charged for the request.  Bucket owners need
        not specify this parameter in their requests.  Info on requester pays buckets can be found at
        http://docs.aws.amazon.com/AmazonS3/latest/dev/ObjectsinRequesterPaysBuckets.html

    CLI Example:

    .. code-block:: bash

        salt myminion boto_s3.get_object_acl Bucket=my_bucket Key=path/to/an/object profile=profile
    '''
    kwargs = {k: v for k, v in kwargs.items() if not k.startswith('_')}
    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)

    try:
        ret = conn.get_object_acl(**kwargs)
        ret.pop('ResponseMetadata', None)
    except (botocore.exceptions.ClientError, botocore.exceptions.ParamValidationError) as e:
        return {'error': _strerror(e)}

    return {'result': ret}


def get_object_tagging(region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Get Tagging data for an S3 object.

    Bucket
        The S3 bucket within which to look for the given Key (file).

    Key
        The path within the Bucket (without leading `/`) to the file being managed.

    VersionId
        VersionId used to reference a specific version of the object.

    CLI Example:

    .. code-block:: bash

        salt myminion boto_s3.get_object_tagging Bucket=my_bucket Key=path/to/an/object profile=profile
    '''
    kwargs = {k: v for k, v in kwargs.items() if not k.startswith('_')}
    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)

    try:
        ret = conn.get_object_tagging(**kwargs)
        ret.pop('ResponseMetadata', None)
    except (botocore.exceptions.ClientError, botocore.exceptions.ParamValidationError) as e:
        return {'error': _strerror(e)}

    return {'result': ret}


def head_object(region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Get Metadata about an S3 object.

    Bucket
        The S3 bucket within which to look for the given Key (file).

    Key
        The path within the Bucket (without leading `/`) to the file being managed.

    IfMatch
        Return the object only if its entity tag (ETag) is the same as the one specified,
        otherwise return a 412 (precondition failed).

    IfModifiedSince
        Return the object only if it has been modified since the specified time, otherwise
        return a 304 (not modified).

    IfNoneMatch
        Return the object only if its entity tag (ETag) is different from the one specified,
        otherwise return a 304 (not modified).

    IfUnmodifiedSince
        Return the object only if it has not been modified since the specified time, otherwise
        return a 412 (precondition failed).

    Range
        Downloads the specified range bytes of an object.  For more information about the HTTP Range
        header, go to http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.35.

    VersionId
        VersionId used to reference a specific version of the object.

    SSECustomerAlgorithm
        Specifies the algorithm to use to when encrypting the object (e.g., AES256).

    SSECustomerKey
        Specifies the customer-provided encryption key for Amazon S3 to use in encrypting data.
        This value is used to store the object and then it is discarded; Amazon does not store the
        encryption key.  The key must be appropriate for use with the algorithm specified in the
        value of SSECustomerAlgorithm.

    SSECustomerKeyMD5
        Specifies the 128-bit MD5 digest of the encryption key according to RFC 1321.  Amazon S3
        uses this header for a message integrity check to ensure the encryption key was transmitted
        without error.  Please note that this parameter not manditory - it is automatically
        populated not provided.

    RequestPayer
        Confirms that the requester knows they will be charged for the request.  Bucket owners need
        not specify this parameter in their requests.  Info on requester pays buckets can be found
        at http://docs.aws.amazon.com/AmazonS3/latest/dev/ObjectsinRequesterPaysBuckets.html

    PartNumber
        Part number of the object being read.  This is a positive integer between 1 and 10,000.
        Effectively performs a 'ranged' HEAD request for the part specified.  Useful querying about
        the size of the part and the number of parts in this object.

    CLI Example:

    .. code-block:: bash

        salt myminion boto_s3.head_object Bucket=my_bucket Key=path/to/an/object profile=profile
    '''
    kwargs = {k: v for k, v in kwargs.items() if not k.startswith('_')}
    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)

    try:
        ret = conn.head_object(**kwargs)
        ret.pop('ResponseMetadata', None)
    except (botocore.exceptions.ClientError, botocore.exceptions.ParamValidationError) as e:
        return {'error': _strerror(e)}

    return {'result': ret}


def put_object(region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Put an object to an S3 bucket.

    Bucket
        Name of the bucket to which the PUT operation was initiated.

    Key
        Object key for which the PUT operation was initiated.

    FileName
        Absolute path (that is, starting with a `/`) to a file on the local minion filesystem
        which is to be put to the S3 bucket.

        Note:  Mutually exclusive with `Body`.

    Body
        Object data to send.  Note that this can be either a `file`-like object, e.g. something
        with a `read()` method, OR a sequence of bytes, in which case it will be treated as a blob
        of bytes (binary data, as in b'\\Xnn\\Xnn...') to be written literally to the S3 object.
        In practice, the FileName param (above) is easier to use in most scenarios.  This option IS
        very powerful, however; as it can, with some effort, read from sockets, streams, or
        anything else providing a `file`-like interface in python.

        Note:  Mutually exclusive with `FileName`.

    ACL
        The canned ACL to apply to the object.
        Valid values:
            'private',
            'public-read',
            'public-read-write',
            'authenticated-read',
            'aws-exec-read',
            'bucket-owner-read',
            'bucket-owner-full-control'

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
        Size of the body in bytes.  This parameter is useful when the size of the body cannot be
        determined automatically.

    ContentMD5
        The base64-encoded 128-bit MD5 digest of the part data.

    ContentType
        A standard MIME type describing the format of the object data.

    Expires
        The date and time at which the object is no longer cacheable.

    GrantFullControl
        Gives the grantee READ, READ_ACP, and WRITE_ACP permissions on the object.

    GrantRead
        Allows grantee to read the object data and its metadata.

    GrantReadACP
        Allows grantee to read the object ACL.

    GrantWriteACP
        Allows grantee to write the ACL for the applicable object.

    Metadata
        A dict of metadata to store with the object in S3.

    ServerSideEncryption
        The Server-side encryption algorithm used when storing this object in S3 (e.g., AES256,
        aws:kms).

    StorageClass
        The type of storage to use for the object.  Defaults to 'STANDARD'.
        Valid values:
            'STANDARD'|'REDUCED_REDUNDANCY'|'STANDARD_IA'

    WebsiteRedirectLocation
        If the bucket is configured as a website, redirects requests for this object to another
        object in the same bucket or to an external URL.  Amazon S3 stores the value of this header
        in the object metadata.

    SSECustomerAlgorithm
        Specifies the algorithm to use to when encrypting the object (e.g., AES256).

    SSECustomerKey
        Specifies the customer-provided encryption key for Amazon S3 to use in encrypting data.
        This value is used to store the object and then it is discarded; Amazon does not store the
        encryption key.  The key must be appropriate for use with the algorithm specified in
        SSECustomerAlgorithm

    SSECustomerKeyMD5
        Specifies the 128-bit MD5 digest of the encryption key according to RFC 1321.  Amazon S3
        uses this header for a message integrity check to ensure the encryption key was transmitted
        without error.  Please note that this parameter is automatically populated if it is not
        provided, so including this parameter is not required.

    SSEKMSKeyId
        Specifies the AWS KMS key ID to use for object encryption.  All GET and PUT requests for
        an object protected by AWS KMS will fail if not made via SSL or using SigV4.  Documentation
        on configuring any of the officially supported AWS SDKs and CLI can be found at
        http://docs.aws.amazon.com/AmazonS3/latest/dev/UsingAWSSDK.html#specify-signature-version

    RequestPayer
        Confirms that the requester knows they will be charged for the request.  Bucket owners need
        not specify this parameter in their requests.  Info on requester pays buckets can be found at
        http://docs.aws.amazon.com/AmazonS3/latest/dev/ObjectsinRequesterPaysBuckets.html

    Tagging
        The tag-set for the object.  The tag-set may be a dictionary of AWS tags in the standard
        AWS "list of dicts" format, a simple dict of <tag>: <value> pairs, or a string.
        NOTE THAT if it is passed as a string, the tagset MUST be encoded as URL Query Parameters
        by the caller before passing to this function.  The `canonical_to_tagstring()` function
        below is a convenient way to achieve this encoding.

    CLI Example:

    .. code-block:: bash

        salt myminion boto_s3.put_object Bucket=my_bucket Key=path/to/an/object \
                          FileName=/a/file/to/put/in/the/bucket Tagging='{Name: my_file}' \
                          profile=profile
    '''
    kwargs = {k: v for k, v in kwargs.items() if not k.startswith('_')}

    # Special-cased args that need munging.
    if 'Tagging' in kwargs:
        tags = tags_to_canonical(kwargs['Tagging'])
        kwargs['Tagging'] = canonical_to_tagstring(tags) if tags is not False else False
        if kwargs['Tagging'] is False:
            msg = "Couldn't parse requested Tagging argument."
            log.error(msg)
            return {'error': msg}

    if 'FileName' in kwargs:
        if 'Body' in kwargs:
            return {'error': '`Body` and `FileName` are mutually exclusive parameters.'}
        try:
            kwargs['Body'] = open(kwargs.pop('FileName'))
        except IOError as e:
            msg = 'Error opening {0}: {1}'.format(kwargs['FileName'], e)
            log.error(msg)
            return {'error': msg}

    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
    try:
        ret = conn.put_object(**kwargs)
        ret.pop('ResponseMetadata', None)
    except (botocore.exceptions.ClientError, botocore.exceptions.ParamValidationError) as e:
        return {'error': _strerror(e)}

    return {'result': ret}


def put_object_acl(region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Set (replace) the Access Control List (ACL) permissions for an existing object in a bucket.

    Bucket
        The S3 bucket within which to look for the given Key (file).

    Key
        The path within the Bucket (without leading `/`) to the file being managed.

    ACL
        A canned ACL to apply to the object.
        Available values:
            private
            public-read
            public-read-write
            authenticated-read
            aws-exec-read
            bucket-owner-read
            bucket-owner-full-control
        Note that the ACL and AccessControlPolicy parameters are mutually exclusive.

    AccessControlPolicy
        A (JSON, or data structure which can be converted to JSON) policy describing the
        desired Access Control Policy for the object.  For more details see the
        .. _`AWS ACL docs`: https://docs.aws.amazon.com/goto/WebAPI/s3-2006-03-01/PutObjectAcl
        Should be in the form:
        .. code-block:: json
            {
                'Grants': [
                    {
                        'Grantee': {
                            'DisplayName': 'string',
                            'EmailAddress': 'string',
                            'ID': 'string',
                            'Type': 'CanonicalUser'|'AmazonCustomerByEmail'|'Group',
                            'URI': 'string'
                        },
                        'Permission': 'FULL_CONTROL'|'WRITE'|'WRITE_ACP'|'READ'|'READ_ACP'
                    },
                    ...
                ],
                'Owner': {
                    'DisplayName': 'string',
                    'ID': 'string'
                }
            }

        Note that the ACL and AccessControlPolicy parameters are mutually exclusive.
        Also note that AWS does not permit passing any of the Grant* options in the same call as
        one including an AccessControlPolicy.

        BE AWARE that you cannot use an email address to specify a grantee for any AWS Region
        that was created after 12/8/2014.  The following Regions were created after 12/8/2014:
            US East (Ohio)
            Canada (Central)
            Asia Pacific (Mumbai)
            Asia Pacific (Seoul)
            EU (Frankfurt)
            EU (London)
            China (Beijing)
            China (Ningxia)
            AWS GovCloud (US)
        It is strongly recommended that you simply avoid using `AmazonCustomerByEmail` entirely to
        prevent issues.

    GrantFullControl
        Allows grantee the read, write, read ACP, and write ACP permissions on the bucket.
        Note that internally this maps to the equivalent AccessControlPolicy.
        Also note that AWS does not permit passing any of the Grant* options in the same call as
        one including an AccessControlPolicy.

    GrantRead
        Allows grantee to list the objects in the bucket.
        Note that internally this maps to the equivalent AccessControlPolicy.
        Also note that AWS does not permit passing any of the Grant* options in the same call as
        one including an AccessControlPolicy.

    GrantReadACP
        Allows grantee to read the bucket ACL.
        Note that internally this maps to the equivalent AccessControlPolicy.
        Also note that AWS does not permit passing any of the Grant* options in the same call as
        one including an AccessControlPolicy.

    GrantWrite
        Allows grantee to create, overwrite, and delete any object in the bucket.
        Note that internally this maps to the equivalent AccessControlPolicy.
        Also note that AWS does not permit passing any of the Grant* options in the same call as
        one including an AccessControlPolicy.

    GrantWriteACP
        Allows grantee to write the ACL for the applicable bucket.
        Note that internally this maps to the equivalent AccessControlPolicy.
        Also note that AWS does not permit passing any of the Grant* options in the same call as
        one including an AccessControlPolicy.

    RequestPayer
        Confirms that the requester knows they will be charged for the request.  Bucket owners need
        not specify this parameter in their requests.  Info on requester pays buckets can be found at
        http://docs.aws.amazon.com/AmazonS3/latest/dev/ObjectsinRequesterPaysBuckets.html

    VersionId
        VersionId used to reference a specific version of the object.

    CLI Example:

    .. code-block:: bash

        salt myminion boto_s3.put_object_acl Bucket=my_bucket Key=an/object ACL=public-read \
                          profile=profile
    '''
    kwargs = {k: v for k, v in kwargs.items() if not k.startswith('_')}
    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)

    if isinstance(kwargs.get('AccessControlPolicy'), six.string_types):
        try:
            kwargs['AccessControlPolicy'] = json.loads(kwargs['AccessControlPolicy'])
        except ValueError as e:
            msg = "Couldn't parse AccessControlPolicy as JSON: {0}".format(str(e))
            log.error(msg)
            return {'error': msg}
    try:
        ret = conn.put_object_acl(**kwargs)
        log.info(ret)
        ret.pop('ResponseMetadata', None)
    except (botocore.exceptions.ClientError, botocore.exceptions.ParamValidationError) as e:
        return {'error': _strerror(e)}

    return {'result': ret}


def put_object_tagging(region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Sets (replaces) the supplied TagSet on an existing object in a bucket.

    Bucket
        The S3 bucket within which to look for the given Key (file).

    Key
        The path within the Bucket (without leading `/`) to the file being managed.

    VersionId
        VersionId used to reference a specific version of the object.

    ContentMD5
        The base64-encoded 128-bit MD5 digest of the part data.

    Tagging
        The TagSet to apply to the object.  Should be in formatted as follows:
        .. code-block:: python
            {
                'TagSet': [
                    {
                        'Key': 'string',
                        'Value': 'string'
                    },
                    ...
                ]
            }

    CLI Example:

    .. code-block:: bash

        salt myminion boto_s3.put_object_acl Bucket=my_bucket Key=an/object ACL=public-read \
                          profile=profile
    '''
    kwargs = {k: v for k, v in kwargs.items() if not k.startswith('_')}
    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)

    try:
        ret = conn.put_object_tagging(**kwargs)
        log.info(ret)
        ret.pop('ResponseMetadata', None)
    except (botocore.exceptions.ClientError, botocore.exceptions.ParamValidationError) as e:
        return {'error': _strerror(e)}

    return {'result': ret}


def tags_to_canonical(tags):
    '''
    Convert various AWS TagSet structures (in various forms) to a dict, which is directly
    comparable to another dict and is thus usable as a safe, `canonical`, form for TagSet data.
    '''
    try:
        if isinstance(tags, dict):
            # Dict is not a valid form for AWS tags, assume already canonicalized.
            return tags
        if isinstance(tags, six.string_types):
            t = parse_qs(qs=tagstring, keep_blank_values=True, strict_parsing=True)
            return {k: (v if v is not '' else None) for k, v in t.items()}
        if isinstance(tags, list):
            return {t['Key']: t.get('Value') for t in tags}
    except (ValueError, KeyError) as e:
        log.error('Malformed tagset passed: {0}: {1}'.format(tags, e))
        return False


def canonical_to_tagstring(tags):
    '''
    Convert a dict to a URL Query String suitable for passing to functions, such as put_object(),
    which require them.
    '''
    try:
        return urlencode(tags)
    except TypeError as e:
        log.error('Malformed tagset passed: {0}: {1}'.format(tags, e))
        return False


def canonical_to_tagset(tags):
    '''
    Convert a dict to an AWS "list of dicts" style TagSet.
    '''
    try:
        return [{'Key': k, 'Value': v} for k, v in tags.items()]
    except AttributeError as e:
        log.error('Malformed tagset passed: {0}: {1}'.format(tags, e))
        return False


def data_to_ordered_yaml(one):
    '''
    Dump a data structure to YAML using an ordered output style.  Useful for comparing data
    structures.
    '''
    dumper = __utils__['yamldumper.get_dumper']('IndentedSafeOrderedDumper')
    return yaml.dump(one, default_flow_style=False, Dumper=dumper)


def compare_datastructures(one, two):
    '''
    Compare two arbitrary data structures (for example, AccessControlPolicy documents).  These can
    be passed as either python data structures or JSON.  Returns a diff-style string describing what
    changed between the first and the second, or an empty string if they are identical.
    '''
    try:
        if isinstance(one, six.string_types):
            log.debug('Converting first value from JSON: {0}'.format(one))
            one = json.loads(one)
        if isinstance(two, six.string_types):
            log.debug('Converting second value from JSON: {0}'.format(two))
            two = json.loads(two)
    except ValueError as e:
        msg = "Couldn't parse string as JSON: {0}".format(str(e))
        log.error(msg)
        return {'error': msg}

    one = data_to_ordered_yaml(one).splitlines()
    two = data_to_ordered_yaml(two).splitlines()
    return '\n'.join(difflib.unified_diff(one, two, lineterm=''))
