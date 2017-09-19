# -*- coding: utf-8 -*-
'''
Connection module for Amazon RDS

:configuration: This module accepts explicit rds credentials but can also
    utilize IAM roles assigned to the instance through Instance Profiles.
    Dynamic credentials are then automatically obtained from AWS API and no
    further configuration is necessary.  More Information available at:

    .. code-block:: text

        http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html

    If IAM roles are not used you need to specify them either in a pillar or
    in the minion's config file:

    .. code-block:: yaml

        rds.keyid: GKTADJGHEIQSXMKKRBJ08H
        rds.key: askdjghsdfjkghWupUjasdflkdfklgjsdfjajkghs

    A region may also be specified in the configuration:

    .. code-block:: yaml

        rds.region: us-east-1

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
#pylint: disable=E0602
# pylint whinging about perfectly valid code
#pylint: disable=W0106


# Import Python libs
from __future__ import absolute_import
import sys
import logging
import time
from datetime import datetime, timedelta
import json
import jmespath as JMESPath
from copy import deepcopy
import locale

# Import Salt libs
import salt.utils.boto3
import salt.utils.compat
import salt.utils.odict as odict
import salt.utils
from salt.exceptions import SaltInvocationError, CommandExecutionError
from salt.utils.versions import LooseVersion as _LooseVersion
import salt.ext.six as six

log = logging.getLogger(__name__)

# pylint: disable=import-error
try:
    #pylint: disable=unused-import
    import boto
    import boto3
    #pylint: enable=unused-import
    from botocore.exceptions import ClientError, ParamValidationError
    logging.getLogger('boto').setLevel(logging.CRITICAL)
    logging.getLogger('boto3').setLevel(logging.CRITICAL)
    HAS_BOTO = True
except ImportError:
    HAS_BOTO = False
# pylint: enable=import-error

bad_db_instance_stati = ('deleting', 'failed', 'inaccessible-encryption-credentials',
                         'incompatible-credentials', 'incompatible-network',
                         'incompatible-option-group', 'incompatible-parameters',
                         'incompatible-restore', 'restore-error', 'storage-full', None)


def __virtual__():
    '''
    Only load if boto libraries exist and if boto libraries are greater than
    a given version.
    '''
    required_boto3_version = '1.3.1'
    if not HAS_BOTO:
        return (False, 'The boto3_rds module could not be loaded: '
                'boto libraries not found')
    elif _LooseVersion(boto3.__version__) < _LooseVersion(required_boto3_version):
        return (False, 'The boto3_rds module could not be loaded: '
                'boto version {0} or later must be installed.'.format(required_boto3_version))
    else:
        return True


def __init__(opts):
    salt.utils.compat.pack_dunder(__name__)
    if HAS_BOTO:
        __utils__['boto3.assign_funcs'](__name__, 'rds')


def add_tags_to_resource(ResourceName, Tags, region=None, key=None, keyid=None, profile=None):
    '''
    Add tags to an arbitrary AWS resource.

    CLI example to description of parameters::

        salt myminion boto3_rds.add_tags_to_resource aResourceARN '{Key: myTag, Value: Ilovefuzzykittens}'
    '''
    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
    try:
        conn.add_tags_to_resource(ResourceName=ResourceName, Tags=Tags)
        return True
    except ClientError as e:
        log.error('Failed to add tags to resource {0}.'.format(ResourceName))
        return False


def list_tags_for_resource(ResourceName, Filters=None, region=None, key=None, keyid=None,
                           profile=None):
    '''
    List the tags current set on an arbitrary AWS resource.  Note that the Filters argument is
    currently unimplemented at the AWS API layer, but is a placeholder for planned functionality.

    CLI example to description of parameters::

        salt myminion boto3_rds.list_tags_for_resource aResourceARN
    '''
    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
    args = {'ResourceName': ResourceName}
    arg.update({'Filters': Filters}) if Filters else None
    try:
        r = conn.list_tags_for_resource(**args)
        return  r.get('TagList')
    except ClientError as e:
        log.error('Failed to list tags for resource {0}.'.format(ResourceName))
        return []


def remove_tags_from_resource(ResourceName, TagKeys, region=None, key=None, keyid=None,
                              profile=None):
    '''
    Add tags to an arbitrary AWS resource.

    CLI example to description of parameters::

        salt myminion boto3_rds.remove_tags_from_resource aResourceARN '[myTag]'
    '''
    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
    try:
        conn.remove_tags_from_resource(ResourceName=ResourceName, TagKeys=list(TagKeys))
        return True
    except ClientError as e:
        log.error('Failed to remove tags from resource {0}.'.format(ResourceName))
        return False


def ensure_tags(ResourceName, Tags, commit=True, region=None, key=None, keyid=None,
                profile=None):
    '''
    Ensure tags on a resource are exactly those provided - no more, no less.

    CLI example to description of parameters::

        salt myminion boto3_rds.ensure_tags aResourceARN '{Key: myTag, Value: Ilovefuzzykittens}'
    '''
    ret = {'name': ResourceName, 'result': True, 'comment': '', 'changes': {}}
    current = list_tags_for_resource(ResourceName=ResourceName, region=region, key=key,
                                     keyid=keyid, profile=profile)

    # We convert all AWS TagList structures to simple dicts internally for ease of processing.
    current = dict([(tag['Key'], tag.get('Value')) for tag in current])
    # They MAY already be a dict, since other functions in the module use that format...
    desired = dict([(tag['Key'], tag.get('Value')) for tag in Tags]) if isinstance(Tags, list) else Tags

    if current == desired:
        msg = 'Tags already set on resource {0}.'.format(ResourceName)
        return _log_and_set_ret(ret, True, msg)

    if not commit:
        msg = 'Tags would be updated on resource {0}'.format(ResourceName)
        changes = {'old': {'Tags': [{'Key': k, 'Value': current[k]} for k in current]},
                   'new': {'Tags': [{'Key': k, 'Value': desired[k]} for k in desired]}}
        return _log_and_set_ret(ret, None, msg, changes=changes)

    # Calculate changes needed...
    current_keys = set(current.keys())
    desired_keys = set(desired.keys())
    shared = current_keys & desired_keys
    remove = current_keys - desired_keys
    add = desired_keys - current_keys
    add |= set([k for k in shared if current[k] != desired[k]])
    add_tags = [{'Key': k, 'Value': desired[k]} for k in add]

    if remove:
        if not remove_tags_from_resource(ResourceName=ResourceName, TagKeys=remove, region=region,
                                         key=key, keyid=keyid, profile=profile):
            msg = 'Failure while removing tags from resource {0}.'.format(ResourceName)
            return _log_and_set_ret(ret, False, msg, 'error')
    if add:
        if not add_tags_to_resource(ResourceName=ResourceName, Tags=add_tags, region=region,
                                    key=key, keyid=keyid, profile=profile):
            msg = 'Failure while adding tags to resource {0}.'.format(ResourceName)
            return _log_and_set_ret(ret, False, msg, 'error')
    if add or remove:
        new = list_tags_for_resource(ResourceName=ResourceName, region=region, key=key,
                                     keyid=keyid, profile=profile)
        msg = 'Tags updated on resource {0}.'.format(ResourceName)
        changes = {'old': {'Tags': [{'Key': k, 'Value': current[k]} for k in current]},
                   'new': {'Tags': new}}
        return _log_and_set_ret(ret, True, msg, changes=changes)
    # Should be unreachable, but WTH.
    return _log_and_set_ret(ret, True, msg)


def describe_account_attributes(jmespath=None, region=None, key=None, keyid=None, profile=None):
    '''
    Return a detailed listing of all, or just some, Account Quotes visible in the
    current scope.  Arbitrary subelements or subsections of the returned dataset
    can be selected by passing in a valid JMSEPath filter as well.

    CLI example::

        salt myminion boto3_rds.describe_account_attributes
    '''
    return _describe(func=sys._getframe().f_code.co_name, error_code_name=None, jmespath=jmespath,
                     jmesflatten='AccountQuotas', identifier='AccountQuota', region=region, key=key,
                     keyid=keyid, profile=profile)


def describe_db_instances(jmespath=None, region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Return a detailed listing of all, or just some, DB Instances visible in the current scope.
    Arbitrary subelements or subsections of the returned dataset can be selected by passing in a
    valid JMSEPath filter as well.

    DBInstanceIdentifier
        A user-supplied instance identifier.  If this parameter is specified, information from only
        the specific DB instance is returned.  This parameter isn't case-sensitive.
        Constraints:
            Must contain from 1 to 63 alphanumeric characters or hyphens
            First character must be a letter
            Cannot end with a hyphen or contain two consecutive hyphens

    Filters
        A list of filters to limit the DB Instances to describe.
        Supported filters:
            db-cluster-id
                Accepts DB cluster identifiers and DB cluster Amazon Resource Names (ARNs).  The
                results list will only include information about the DB instances associated with
                the DB Clusters identified by these ARNs.
            db-instance-id
                Accepts DB instance identifiers and DB instance Amazon Resource Names (ARNs).  The
                results list will only include information about the DB instances identified by
                these ARNs.

    CLI example::

        salt myminion boto3_rds.describe_db_instances jmespath='DBInstances[*].DBInstanceIdentifier'
    '''
    kwargs = dict([(k, v) for k, v in kwargs.items() if not k.startswith('_')])
    return  _describe(func=sys._getframe().f_code.co_name, error_code_name='DBInstanceNotFound',
                      jmespath=jmespath, jmesflatten='DBInstances', identifier='DBInstanceIdentifier',
                      region=region, key=key, keyid=keyid, profile=profile, **kwargs)


def create_db_instance(DBInstanceIdentifier, wait=0, commit=True,
                       region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Create a new RDS DB Instance

    DBInstanceIdentifier
        REQUIRED
        The DB instance identifier.  This parameter is stored as a lowercase string.
        Constraints:
            Must contain from 1 to 63 alphanumeric characters or hyphens (1 to 15 for SQL Server).
            First character must be a letter.
            Cannot end with a hyphen or contain two consecutive hyphens.

    DBInstanceClass
        REQUIRED
        The instance class providing the compute and memory capacity desired for the DB instance.
        Note that not all instance classes are available in all regions for all DB engines.
        Currently available instance sizes (and the relative pricing thereof) can be found at
        https://aws.amazon.com/rds/details/

    Engine
        REQUIRED
        The name of the database engine to be used for this instance.
        Not every database engine is available for every AWS region.  See the link under
        DBInstanceClass for availability details.
        Valid Values:
            postgres | aurora | mysql | mariadb | oracle-se1 | oracle-se2 | oracle-se | oracle-ee |
                sqlserver-ee | sqlserver-se | sqlserver-ex | sqlserver-web

    DBName
        The meaning of this parameter differs according to the database engine you use.
        PostgreSQL
            The name of the database to create when the DB instance is created.  If this parameter
            is not specified, the default "postgres" database is created in the DB instance.
            Constraints:
                Must contain 1 to 63 alphanumeric characters
                Must begin with a letter or an underscore.
                Subsequent characters can be letters, underscores, or digits (0-9).
        MariaDB / MySQL
            The name of the database to create when the DB instance is created.  If this parameter
            is not specified, no database is created in the DB instance.
            Constraints:
                Must contain 1 to 64 alphanumeric characters
                Cannot be a word reserved by the specified database engine
                Cannot be a word reserved by the specified database engine
        Oracle
            The Oracle System ID (SID) of the created DB instance.
            Default: ORCL
            Constraints:
                Cannot be longer than 8 characters
        SQL Server
            Not applicable.  Must be null.
        Amazon Aurora
            The name of the database to create when the primary instance of the DB cluster is
            created.  If this parameter is not specified, no database is created in the DB instance.
            Constraints:
                Must contain 1 to 64 alphanumeric characters
                Cannot be a word reserved by the specified database engine

    AllocatedStorage
        REQUIRED for all except Amazon Aurora.
        The amount of storage (in gigabytes) to be initially allocated for the database instance.
        PostgreSQL / MariaDB / MySQL
            Constraints: Must be an integer from 5 to 6144.
        Oracle
            Constraints: Must be an integer from 10 to 6144.
        SQL Server
            Constraints: Must be an integer from 200 to 4096 (Standard Edition and Enterprise
            Edition) or from 20 to 4096 (Express Edition and Web Edition)
        Amazon Aurora
            Not applicable.  Aurora cluster volumes automatically grow as the amount of data in
            your database increases, though you are only charged for the space that you use in an
            Aurora cluster volume.

    MasterUsername
        The name for the master database user.
        PostgreSQL
            Constraints:
                Must be 1 to 63 alphanumeric characters.
                First character must be a letter.
                Cannot be a reserved word for the chosen database engine.
        MariaDB
            Constraints:
                Must be 1 to 16 alphanumeric characters.
                Cannot be a reserved word for the chosen database engine.
        MySQL
            Constraints:
                Must be 1 to 16 alphanumeric characters.
                First character must be a letter.
                Cannot be a reserved word for the chosen database engine.
        Oracle
            Constraints:
                Must be 1 to 30 alphanumeric characters.
                First character must be a letter.
                Cannot be a reserved word for the chosen database engine.
        Microsoft SQL Server
            Constraints:
                Must be 1 to 128 alphanumeric characters.
                First character must be a letter.
                Cannot be a reserved word for the chosen database engine.
        Amazon Aurora
            Not applicable.  You specify the name for the master database user when you create your
            DB cluster.

    MasterUserPassword
        The password for the master database user.  Can contain any printable ASCII character except
        "/", """, or "@".
        PostgreSQL / Microsoft SQL Server
            Constraints: Must contain from 8 to 128 characters.
        MariaDB / MySQL
            Constraints: Must contain from 8 to 41 characters.
        Oracle
            Constraints: Must contain from 8 to 30 characters.
        Amazon Aurora
            Not applicable.  You specify the password for the master database user when you create
            your DB cluster.

    DBSecurityGroups
        A list of DB security groups to associate with this DB instance.
        Default: The default DB security group for the database engine.

    VpcSecurityGroupIds
        A list of EC2 VPC security groups to associate with this DB instance.
        Default: The default EC2 VPC security group for the DB subnet group's VPC.

    AvailabilityZone
        The EC2 Availability Zone that the database instance will be created in.
        Default: A random, system-chosen Availability Zone in the endpoint's region.
        Constraints:
            The AvailabilityZone parameter cannot be specified if the MultiAZ param is set to true.
            The specified Availability Zone must be in the same region as the current endpoint.

    DBSubnetGroupName
        A DB subnet group to associate with this DB instance.
        If there is no DB subnet group, then it is a non-VPC DB instance.

    PreferredMaintenanceWindow
        The weekly time range during which system maintenance can occur, in UTC.
        Format: ddd:hh24:mi-ddd:hh24:mi
        Valid Days: mon | tue | wed | thu | fri | sat | sun
        Default: A 30-minute window selected at random from an 8-hour block of time per region,
        occurring on a random day of the week.
        Constraints: Window must be at least 30 minutes in length.

    DBParameterGroupName
        The name of the DB parameter group to associate with this DB instance.  If this argument is
        omitted, the default DBParameterGroup for the specified engine will be used.
        Constraints:
            Must be 1 to 255 alphanumeric characters
            First character must be a letter
            Cannot end with a hyphen or contain two consecutive hyphens

    BackupRetentionPeriod
        The number of days for which automated backups are retained.  Setting this parameter to a
        positive number enables backups.  Setting this parameter to 0 disables automated backups.
        Default: 1
        Constraints:
            Must be a value from 0 to 35
            Cannot be set to 0 if the DB instance is a source to Read Replicas

    PreferredBackupWindow
        The daily time range during which automated backups are created if automated backups are
        enabled, using the BackupRetentionPeriod parameter.
        Default: A 30-minute window selected at random from an 8-hour block of time per region.
        Constraints:
            Must be in the format hh24:mi-hh24:mi.
            Times should be in Universal Coordinated Time (UTC).
            Must not conflict with the preferred maintenance window.
            Must be at least 30 minutes.

    Port
        The port number on which the database accepts connections.
        PostgreSQL
            Default: 5432
            Valid Values: 1150-65535
        MariaDB / MySQL / Amazon Aurora
            Default: 3306
            Valid Values: 1150-65535
        Oracle
            Default: 1521
            Valid Values: 1150-65535
        SQL Server
            Default: 1433
            Valid Values: 1150-65535 except for 1434, 3389, 47001, 49152, and 49152 through 49156.

    MultiAZ
        Specifies if the DB instance is a Multi-AZ deployment.  Mutually exclusive with the
        AvailabilityZone parameter.

    EngineVersion
        The version number of the database engine to use.
        Not every database engine (and/or major and minor version thereof) is available for every
        AWS region.  See the link under DBInstanceClass for availability details.

    AutoMinorVersionUpgrade
        Indicates that minor engine upgrades will be applied automatically to the DB instance
        during the maintenance window.
        Default: true

    LicenseModel
        License model information for this DB instance.
        Valid values: license-included | bring-your-own-license | general-public-license
        Default: Varies depending on the Engine chosen.

    Iops
        The amount of Provisioned IOPS (input/output operations per second) to be initially
        allocated for the DB instance.
        Constraints:
            Must be a multiple between 3 and 10 of the storage amount for the DB instance.
            Must also be an integer multiple of 1000.
            For example, if the size of your DB instance is 500 GB, then your Iops value can be
             2000, 3000, 4000, or 5000.

    OptionGroupName
        Indicates that the DB instance should be associated with the specified option group.
        Permanent options, such as the TDE option for Oracle Advanced Security TDE, cannot be
        removed from an option group, and that option group cannot be removed from a DB instance
        once it is associated with a DB instance

    CharacterSetName
        For supported engines, indicates that the DB instance should be associated with the
        specified CharacterSet.

    PubliclyAccessible
        Specifies the accessibility options for the DB instance.  A value of true specifies an
        Internet-facing instance with a publicly resolvable DNS name, which resolves to a public
        IP address.  A value of false specifies an internal instance with a DNS name that resolves
        to a private IP address.
        Default: The default behavior varies depending on whether a VPC has been requested or not.
        The following list shows the default behavior in each case.
            Default VPC: true
            VPC: false
        If no DB subnet group has been specified as part of the request and the PubliclyAccessible
        value has not been set, the DB instance will be publicly accessible.  If a specific DB
        subnet group has been specified as part of the request and the PubliclyAccessible value has
        not been set, the DB instance will be private.

    Tags
        A list of tag dicts, each in the standard AWS {'Key': <key>, 'Value': <value>} format
        Constraints:
            A key is the (required) name of the tag.  The string value can be from 1 to 128 Unicode
            characters in length and cannot be prefixed with "aws:" or "rds:".  The string can only
            contain only the set of Unicode letters, digits, white-space, '_', '.', '/', '=', '+',
            and '-'.
            A value is the (optional) value of the tag.  The string value can be from 1 to 256
            Unicode characters in length and cannot be prefixed with "aws:" or "rds:".  The string
            can only contain only the set of Unicode letters, digits, white-space, '_', '.', '/',
            '=', '+', and '-'.

    DBClusterIdentifier
        The identifier of the DB cluster that the instance will belong to.

    StorageType
        Specifies the storage type to be associated with the DB instance.
        Valid values: standard | gp2 | io1
        Constraint: If you specify io1, you must also include a value for the Iops parameter.
        Default: io1 if the Iops parameter is specified; otherwise standard

    TdeCredentialArn
        The ARN from the Key Store with which to associate the instance for TDE encryption.

    TdeCredentialPassword
        The password for the given ARN from the Key Store in order to access the device.

    StorageEncrypted
        Specifies whether the DB instance is encrypted.
        Default: false

    KmsKeyId
        The KMS key identifier for an encrypted DB instance.
        The KMS key identifier is the Amazon Resource Name (ARN) for the KMS encryption key.  If
        you are creating a DB instance with the same AWS account that owns the KMS encryption key
        used to encrypt the new DB instance, then you can use the KMS key alias instead of the ARN
        for the KM encryption key.
        If the StorageEncrypted parameter is true, and you do not specify a value for the KmsKeyId
        parameter, then Amazon RDS will use your default encryption key.  AWS KMS creates the
        default encryption key for your AWS account.  Your AWS account has a different default
        encryption key for each AWS region.

    Domain
        Specify the Active Directory Domain to create the instance in.

    CopyTagsToSnapshot
        Set to True to copy all tags from the DB instance to snapshots of the DB instance;
        otherwise false.
        Default: false

    MonitoringInterval
        The interval, in seconds, between points when Enhanced Monitoring metrics are collected for
        the DB instance.  To disable collecting Enhanced Monitoring metrics, specify 0.  You must
        set MonitoringInterval to a non-zero value if MonitoringRoleArn is specified.
        Default: 0
        Valid Values: 0, 1, 5, 10, 15, 30, 60

    MonitoringRoleArn
        The ARN for the IAM role that permits RDS to send enhanced monitoring metrics to CloudWatch
        Logs.  For example, arn:aws:iam:123456789012:role/emaccess.
        If MonitoringInterval is set to a non-zero value, you must supply a MonitoringRoleArn value.

    DomainIAMRoleName
        Specify the name of the IAM role to be used when making API calls to the Directory Service.

    PromotionTier
        A value that specifies the order in which an Aurora Replica is promoted to the primary
        instance after a failure of the existing primary instance.
        Default: 1
        Valid Values: 0 - 15

    Timezone
        The time zone of the DB instance.  The time zone parameter is currently supported only for
        Microsoft SQL Server.

    EnableIAMDatabaseAuthentication
        True to enable mapping of AWS Identity and Access Management (IAM) accounts to database
        accounts; otherwise false.  Not every database engine (and/or major and minor version
        thereof) supports this.  See the link under DBInstanceClass for availability details.
        Default: false

    wait
        Int value (default: 0) requesting salt to wait 'wait' seconds for the specified actions
        to apply, and the DB instance to become available.  SOME changes can take a SIGNIFICANT
        amount of time to complete and thus will fail a state run given any sensible finite wait
        time.  Until you become familiar with which options most strongly affect your state run
        times, it's recommended to leave the default of 'wait=0' and simply check periodically to
        see if the updates have completed.

    commit
        Boolean (default: True) declaring whether to actually apply any changes or simply report
        them back as "what would happen if"...

    region
        Region to connect to.

    key
        AWS secret key to be used.

    keyid
        AWS access key to be used.

    profile
        A dict with region, key and keyid, or a pillar key (string) that contains a dict with
        region, key and keyid.

    '''
    # XXX TODO re-implement via _create()
    ret = {'name': DBInstanceIdentifier, 'result': True, 'comment': '', 'changes': {}}
    current = describe_db_instances(DBInstanceIdentifier=DBInstanceIdentifier, region=region,
                                    key=key, keyid=keyid, profile=profile)
    if len(current):
        msg = "DB Instance {0} already exists.".format(DBInstanceIdentifier)
        return _log_and_set_ret(ret, False, msg, 'error', None)

    # These are all only meaningful for modify_db_instance(), but we might be called from
    # db_instance_exists() so we just accept and ignore them for the sake of simplicity.
    modify_only_params = [
        'AllowMajorVersionUpgrade',
        'ApplyImmediately',
        'NewDBInstanceIdentifier'
    ]
    # These are 'modify' things that we have to massage to use within a create call
    modify_only_that_we_munge = {
        'DBPortNumber': 'Port',
        # This cannot be set at creation, but only with an explicity, separate modify afterward....
        'CACertificateIdentifier': None
    }
    fixed = {'DBInstanceIdentifier': DBInstanceIdentifier}
    modify_after_create = {}
    kwargs = dict([(k, v) for k, v in kwargs.items() if not k.startswith('_')])
    for param, newparam in modify_only_that_we_munge.items():
        if kwargs.get(param) is not None:
            if param == 'CACertificateIdentifier':
                modify_after_create.update({param: kwargs[param]})
            elif newparam not in kwargs:    # Don't clobber explicit values
                kwargs[newparam] = kwargs[param]
            del kwargs[param]
    for param, newval in kwargs.items():
        if param in modify_only_params or param.startswith('_') or newval is None:
            log.debug('ignoring param {0}'.format(param))
            continue
        fixed[param] = newval

    if not commit:
        fixed.update(modify_after_create)
        msg = 'DB Instance {0} would be created.'.format(DBInstanceIdentifier)
        return _log_and_set_ret(ret, None, msg, changes={'old': None, 'new': fixed})

    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
    try:
        r = conn.create_db_instance(**fixed)
        if not r or 'DBInstance' not in r:
            msg = 'Failed to create DB Instance {0}:  unkonwn error'.format(
                    DBInstanceIdentifier)
            return _log_and_set_ret(ret, False, msg, 'error', None)
        r = r['DBInstance']
        # create_db_idstance() sets Tags, but neither its own returned data strucutre NOR
        # describe_db_instance() lists them back!  Annoying or WHAT?
        r['Tags'] = list_tags_for_resource(ResourceName=r['DBInstanceArn'], region=region,
                key=key, keyid=keyid, profile=profile)
    except ClientError as e:
        msg = 'Failed to create DB Instance {0}: {1}'.format(DBInstanceIdentifier, e)
        return _log_and_set_ret(ret, False, msg, 'error', None)
    except ParamValidationError as e:
        msg = '  '.join('{0}'.format(e).split('\n'))
        return _log_and_set_ret(ret, False, msg, 'error', None)

    if not wait:
        msg = 'DB Instance {0} modification requested.'.format(DBInstanceIdentifier)
        return _log_and_set_ret(ret, True, msg, changes={'old': None, 'new': r})

    log.info('Waiting up to {0} seconds for DB Instance {1} to become available.'.format(wait,
             DBInstanceIdentifier))
    o_wait = wait
    succeeded = False
    while wait > 0:
        r = describe_db_instances(DBInstanceIdentifier=DBInstanceIdentifier, region=region, key=key,
                                  keyid=keyid, profile=profile)
        if not r:
            msg = 'DB Instance {0} should exist but was not found.'.format(DBInstanceIdentifier)
            return _log_and_set_ret(ret, False, msg, 'error', None)
        r = r[0]
        status = r['DBInstanceStatus']
        if status in bad_db_instance_stati:
            msg = 'Error while creating DB Instance {0}: DBInstanceStatus returned `{1}`'.format(
                    DBInstanceIdentifier, status)
            return _log_and_set_ret(ret, False, msg, 'error', {'old': None, 'new': r})
        if status == 'available':
            msg = 'DB Instance {0} created.'.format(DBInstanceIdentifier)
            if not modify_after_create:
                return _log_and_set_ret(ret, True, msg, changes={'old': None, 'new': r})
            succeeded = True
            break
        sleep = wait if wait % 60 == wait else 60
        log.info('Sleeping {0} seconds for DB Instance {1} to become available.'.format(sleep,
                 DBInstanceIdentifier))
        time.sleep(sleep)
        wait -= sleep
    if not succeeded:
        msg = 'DB Instance {0} not available after {1} seconds!'.format(DBInstanceIdentifier, o_wait)
        return _log_and_set_ret(ret, False, msg, 'error', {'old': None, 'new': r})

    # modify_after_create == True
    args = {'DBInstanceIdentifier': DBInstanceIdentifer, 'wait': wait, 'commit': commit,
            'region': region, 'key': key, 'keyid': keyid, 'profile': profile}
    args.update(modify_after_create)
    r = modify_db_instance(**args).get('DBInstance')
    ret.update({'result': r['result'],
                'comment': '{0}  {1}'.format(ret['comment'], r['comment']),
                'changes': {'old': None, 'new': r}})
    return ret


def modify_db_instance(DBInstanceIdentifier, wait=0, commit=True,
                       region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Update settings for an existing RDS DB Instance

    Annoyingly, there are 5 separate classes of parameters, along with various corner-case
    permutations.  The first is applied asyncronously by by AWS as soon as the request is made,
    regardless of the value of ApplyImmediately.  The second are `safe` in the sense that they
    risk no downtime (either service or instance) but DO honor the value of ApplyImmediately.  The
    third are `unsafe` - that is, they run the risk of service or instance downtime, but also honor
    ApplyImmediately.  The fourth do NOT honor AppyImmediately, but do require an explicit instance
    reboot to be applied - in some cases a failure reboot will also work, but not in all.  Lastly is
    the fifth type, which - if passed - can cause an immediate system reboot to occur, REGARDLESS of
    the value of ApplyImmediately.  Worst of all is that some params are USUALLY category 1 or 2,
    but under certain conditions can instead be 3, 4, or even 5; all apparently depending on the
    mood of the AWS API developer that day...

    We try our best to categorize the parameters below as to where they fit in this scheme, but
    strongly recommend referring to the AWS docs at `Modifying an Amazon RDS DB Instance and Using
    the Apply Immediately Parameter`__ before attempting to modify any production systems.
    .. __: http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.DBInstance.Modifying.html

    Setting `ApplyImmediately` to True will cause any changed settings, whether `safe` or `unsafe`
    -- as well as any pending changes scheduled for the next maintenance window -- to be applied
    immedidately.  This INCLUDES those which can cause downtime (that is, category 3 above).  Each
    param below is tagged per this table
        IMMED - category one, the change will be applied more-or-less immediately at AWS's whim.
        SAFE - category two, the change will be applied if `ApplyImmdiately` is True (defaults to
            False).  Applying these will not, in and of themselves, cause any downtime.
        UNSAFE - category three, the change will be applied if `ApplyImmdiately` is True (defaults
            to False).  This can imply simple DB downtime, or an actual instance reboot.
        REBOOT - category four, change will only be applied upon an explicit (e.g. manual) instance
            reboot.
        STUPID - category five, change will be applied immediately REGARDLESS of the setting of
            ApplyImmediately, potentially resulting in an instant INSTANCE REBOOT.

    Also note that SOME of these changes can take a SIGNIFICANT time to complete (days in one case)
    and thus can hang a state run for that long if run with wait != 0.  When making changes which
    run the risk of long application times, it's recommended to set wait=0 and simply check
    periodically to see if the updates have completed.

    DBInstanceIdentifier
        The DB instance identifier.  This value is stored as a lowercase string.
        Constraints:
            Must be the identifier for an existing DB instance
            Must contain from 1 to 63 alphanumeric characters or hyphens
            First character must be a letter
            Cannot end with a hyphen or contain two consecutive hyphens

    AllocatedStorage
        SAFE
        A new storage capacity of the RDS instance.
        MariaDB / MySQL / PostgreSQL
            Valid Values: 5-6144
            Constraints: Value supplied must be at least 10% greater than the current value.  Values
                that are not at least 10% greater than the existing value are rounded up so that
                they are 10% greater than the current value.
        Oracle
            Valid Values: 10-6144
            Constraints: Value supplied must be at least 10% greater than the current value.  Values
                that are not at least 10% greater than the existing value are rounded up so that
                they are 10% greater than the current value.
        SQL Server
            Cannot be modified.

    DBInstanceClass
        UNSAFE
        A new DB instance class.  To determine the instance classes that are available for a
        particular DB engine, see https://aws.amazon.com/rds/details/.  Not all instance classes are
        available in all regions for all DB engines.

    DBSubnetGroupName
        UNSAFE
        A new DB subnet group for the DB instance.  You can use this parameter to move your DB
        instance to a different VPC.  If your DB instance is not in a VPC, you can use this to move
        your instance into a VPC.

    DBSecurityGroups
        IMMED
        A list of DB security groups to authorize on this DB instance.

    VpcSecurityGroupIds
        IMMED
        A list of EC2 VPC security groups to authorize on this DB instance.

    MasterUserPassword
        IMMED
        The new password for the DB instance master user.
        Note that between the time of the request and its completion, the MasterUserPassword element
        exists in the PendingModifiedValues element of the operation response.
        Constraints:
            Must be 8 to 41 alphanumeric characters (MySQL, MariaDB, and Amazon Aurora), 8 to 30
            alphanumeric characters (Oracle), or 8 to 128 alphanumeric characters (SQL Server).
            Can be any printable ASCII character except "/", """, or "@".

    DBParameterGroupName
        IMMED / REBOOT
        The name of the DB parameter group to apply to the DB instance.  Changing this setting does
        not result in an outage.  The parameter group name itself is changed immediately, but the
        actual parameter changes are not applied until you reboot the instance without failover.
        The DB instance will NOT be rebooted automatically and the parameter changes will NOT be
        applied during the next maintenance window.
        Constraints:
            The DB parameter group must be in the same parameter group family as this DB instance.

    BackupRetentionPeriod
        SAFE / UNSAFE
        The number of days to retain automated backups.  Setting this parameter to a positive
        number enables backups.  Setting it to 0 disables automated backups.
        Only UNSAFE if the change is from 0 to a non-zero value or vice-versa, SAFE otherwise.
        Constraints:
            Must be a value from 0 to 35
            Only valid for a MySQL Read Replica if the source is running MySQL 5.6
            Only valid for a PostgreSQL Read Replica if the source is running PostgreSQL 9.3.5
            Cannot be set to 0 if the DB instance is a source to Read Replicas

    PreferredBackupWindow
        IMMED
        The daily time range during which automated backups are created if automated backups are
        enabled, as determined by the BackupRetentionPeriod parameter.
        Format:
            hh24:mi-hh24:mi
        Constraints:
            Times must be in Universal Time Coordinated (UTC)
            Must not conflict with the PreferredMaintenanceWindow
            Must be at least 30 minutes

    PreferredMaintenanceWindow
        STUPID
        The weekly time range (in UTC) during which system maintenance can occur, which can result
        in an outage.  Changing this parameter is IMMED, except in the following UNSAFE scenario:
        If there are pending actions that cause a reboot, and the maintenance window is changed to
        include the current time, a reboot will occur to apply the changes.  Thus, if moving this
        window to the current time, there must be at least 30 minutes between the current time and
        end of the window to ensure pending changes can be applied.
        Format:
            ddd:hh24:mi-ddd:hh24:mi
        Valid Days:
            mon | tue | wed | thu | fri | sat | sun
        Constraints:
            Must be at least 30 minutes

    MultiAZ
        SAFE
        Specifies if the DB instance is a Multi-AZ deployment.
        Constraints:
            Cannot be specified if the DB instance is a Read Replica.

    EngineVersion
        UNSAFE
        The version number of the database engine to upgrade to.
        Note:  For major version upgrades, if a non-default DB parameter group is currently in use,
        a new DB parameter group in the DB parameter group family for the new engine version MUST be
        supplied.

    AllowMajorVersionUpgrade
        IMMED
        Indicates that major version upgrades are allowed.
        Constraints:
            This parameter must be set to true when specifying a value for the EngineVersion
            parameter that is a different major version than the DB instance's current version.

    AutoMinorVersionUpgrade
        IMMED / UNSAFE
        Indicates that minor version upgrades may be applied automatically to the DB instance during
        the maintenance window.  Changing this parameter is IMMED except in the following UNSAFE
        scenario:  An outage will result if this parameter is set to True during the maintenance
        window, and a newer minor version is available, and RDS has enabled auto patching for that
        engine version.

    LicenseModel
        UNSAFE
        The license model for the DB instance.
        Valid values:
            license-included
            bring-your-own-license
            general-public-license

    Iops
        SAFE / UNSAFE
        The new Provisioned IOPS value for the RDS instance.
        Note:  Setting the IOPS value for the SQL Server database engine is not supported.
        Constraints:
            Value supplied must be at least 10% greater than the current value.  Values that are not
            at least 10% greater than the existing value are rounded up so that they are 10% greater
            than the current value.  If you are migrating from Provisioned IOPS to standard storage,
            set this value to 0.

    OptionGroupName
        SAFE / UNSAFE
        Indicates that the DB instance should be associated with the specified option group.
        SAFE except in the following UNSAFE case:  If the parameter change results in an option
        group that enables OEM, this change can cause a brief (sub-second) period during which new
        connections are rejected but existing connections are not interrupted.
        Note:  Permanent options, such as the TDE option for Oracle Advanced Security TDE, cannot be
        removed from an option group, and that option group cannot be removed from a DB instance
        once it is associated with a DB instance.

    NewDBInstanceIdentifier
        UNSAFE
        A new DB instance identifier for the DB instance, when renaming a DB instance.  This value
        is stored as a lowercase string.
        Constraints:
            Must contain from 1 to 63 alphanumeric characters or hyphens
            First character must be a letter
            Cannot end with a hyphen or contain two consecutive hyphens

    StorageType
        UNSAFE
        Specifies the storage type to be associated with the DB instance.
        Valid values:
            standard
            gp2
            io1
        Default:  io1 if the Iops parameter is specified; otherwise standard.
        Notes:
            If you specify io1, you MUST provide a value for the Iops parameter.
            You cannot modify an existing SQL Server DB instance to change storage type or modify
            storage allocation.
            In some cases an immediate outage occurs when you convert from one storage type to
            another.  If you change from standard to gp2 or io1, a short outage occurs.  Also, if
            you change from io1 or gp2 to standard, a short outage occurs.  For instances in a
            single Availability Zone, the DB instance might be unavailable for a few minutes when
            the conversion is initiated.  For multi-AZ deployments, the time the instance is
            unavailable is limited to the time it takes for a failover operation to complete, which
            typically takes less than two minutes.  Although the DB instance is available for reads
            and writes during the conversion, you might experience degraded performance until the
            conversion process is complete.  Whenever you change the storage type of a DB instance,
            the data for that DB instance is migrated to a new volume.  The duration of the
            migration depends on several factors such as database load, storage size, storage type,
            and amount of IOPS provisioned (if any).  Typical migration times are under 24 hours,
            but can take up to several days in some cases.  During the migration, the DB instance is
            available for use, but might experience performance degradation.  While the migration
            takes place, nightly backups are suspended and no other Amazon RDS operations can take
            place on the affected instance, including Modify, Reboot, Delete, Create Read Replica,
            and DB Snapshot.

    TdeCredentialArn
        IMMED
        The ARN from the Key Store with which to associate the instance for TDE encryption.

    TdeCredentialPassword
        IMMED
        The password for the given ARN from the Key Store in order to access the device.

    CACertificateIdentifier
        IMMED
        Indicates the certificate that needs to be associated with the instance.

    Domain
        IMMED
        An Active Directory Domain to move the instance to.  Specify the string `none` to remove the
        instance from its current domain.  The domain must be created prior to this operation.
        Currently only a Microsoft SQL Server instance can be created in a Active Directory Domain.

    DomainIAMRoleName
        IMMED
        The name of the IAM role to use when making API calls to the Directory Service.

    CopyTagsToSnapshot
        IMMED
        True to copy all tags from the DB instance to snapshots of the DB instance.
        Default:  False

    MonitoringInterval
        IMMED
        The interval, in seconds, between points when Enhanced Monitoring metrics are collected for
        the DB instance.  Set to 0 to disable collecting Enhanced Monitoring metrics.
        Default:  0
        Note:  If MonitoringRoleArn is set, then MonitoringInterval nust set to a non-zero value.
        Valid Values:  0, 1, 5, 10, 15, 30, 60

    MonitoringRoleArn
        IMMED
        The ARN for the IAM role that permits RDS to send Enhanced Monitoring metrics to CloudWatch
        Logs.

    DBPortNumber
        STUPID
        WARNING!!!  YOUR DATABASE WILL RESTART when you change the DBPortNumber value REGARDLESS of
        the value of the ApplyImmediately parameter.  Act accordingly...
        The port number on which the database accepts connections.  The value must not match any of
        the port values specified for options in the option group for the DB instance.
            Amazon Aurora / MariaDB / MySQL
                Default: 3306
                Valid Values: 1150-65535
            PostgreSQL
                Default: 5432
                Valid Values: 1150-65535
            Oracle
                Default: 1521
                Valid Values: 1150-65535
            SQL Server
                Default: 1433
                Valid Values: 1150-65535 except for 1434, 3389, 47001, 49152, and 49152-49156.

    PubliclyAccessible
        IMMED
        Boolean value that indicates if the DB instance has a publicly resolvable DNS name.  Set to
        True to make the DB instance Internet-facing with a publicly resolvable DNS name, which
        resolves to a public IP address.  Set to False to make the DB instance internal with a DNS
        name that resolves to a private IP address.
        Note:
            PubliclyAccessible only applies to DB instances in a VPC.  The DB instance must be part
            of a public subnet and PubliclyAccessible must be true in order for it to be publicly
            accessible.
        Default: False

    PromotionTier
        IMMED
        A value that specifies the order in which an Aurora Replica is promoted to the primary
        instance after a failure of the existing primary instance.  For more information, see
        http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Aurora.Managing.html#Aurora.Managing.FaultTolerance
        Default: 1
        Valid Values: 0 - 15

    ApplyImmediately
        If True, specifies that the updates in this request, and any other pending changes,
        be asynchronously applied as soon as possible.  If False (the default), changes to the
        instance are applied during the next maintenance window (viz. PreferredMaintenanceWindow).
        Some parameter changes can cause an outage and will be applied on the next instance reboot.
        See http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.DBInstance.Modifying.html
        for details of the impact that setting ApplyImmediately to True or False has for each
        parameter and to determine when the changes will be applied.

    wait
        Int value (default: 0) requesting salt to wait 'wait' seconds for the specified updates
        to apply, and the DB instance to return to an available state.  SOME changes can take a
        SIGNIFICANT time to complete (days in one scenario) and thus will fail a state run given any
        sensible finite wait time.  When making changes which run the risk of long application
        times, it's recommended to leave the default of 'wait=0' and simply check periodically to
        see if the updates have completed.

    commit
        Boolean (default: True) declaring whether to actually apply any changes or simply report
        them back as "what would happen if"...

    CLI example to modify an RDS DB Instance::

        salt myminion boto3_rds.modify_db_instance anRDSinstance PromotionTier=3 wait=False

    '''
    if not isinstance(wait, int):
        raise SaltInvocationError("Bad value ('{0}') passed for 'wait' param - must be an "
                                  "int.".format(wait))

    ret = {'name': DBInstanceIdentifier, 'result': True, 'comment': '', 'changes': {}}
    current = describe_db_instances(DBInstanceIdentifier=DBInstanceIdentifier, region=region,
                                    key=key, keyid=keyid, profile=profile)
    if not len(current):
        msg = "RDS DB Instance {0} not found, can't modify.".format(DBInstanceIdentifier)
        return _log_and_set_ret(ret, False, msg, 'error', None)

    current = current[0]
    pending = set(current.get('PendingModifiedValues', {}).keys())
    cat1 = set(['DBSecurityGroups', 'VpcSecurityGroupIds', 'VpcSecurityGroups', 'MasterUserPassword',
            'DBParameterGroupName', 'PreferredBackupWindow', 'AllowMajorVersionUpgrade',
            'AutoMinorVersionUpgrade', 'TdeCredentialArn', 'TdeCredentialPassword',
            'CACertificateIdentifier', 'Domain', 'DomainIAMRoleName', 'CopyTagsToSnapshot',
            'MonitoringInterval', 'PubliclyAccessible', 'MonitoringRoleArn', 'PromotionTier'])
    # We split out 2 from 3 so we can later determine if downtime might be expected...
    cat2 = set(['AllocatedStorage', 'BackupRetentionPeriod', 'MultiAZ', 'Iops', 'OptionGroupName'])
    cat3 = set(['DBInstanceClass', 'DBSubnetGroupName', 'BackupRetentionPeriod', 'EngineVersion',
            'LicenseModel', 'OptionGroupName', 'NewDBInstanceIdentifier', 'Iops', 'StorageType'])
    cat4 = set(['DBParameterGroupName'])
    cat5 = set(['AutoMinorVersionUpgrade', 'DBPortNumber', 'PreferredMaintenanceWindow'])

    # Allows us to mix and match params from create_db_instance() and modify_db_instance(), e.g.
    # in the state definition...
    create_only_params = set([
        'AvailabilityZone',
        'CharacterSetName',
        'DBClusterIdentifier',
        'DBName',
        'Engine',
        'KmsKeyId',
        'StorageEncrypted',
        'Timezone',
        'MasterUsername'
    ])
    create_only_that_we_munge = {
        'Port': 'DBPortNumber',
        'Tags': None
    }

    modify_params = cat1 | cat2 | cat3 | cat4 | cat5
    special_cases = {
            'ApplyImmediately': (None, None),
            # There is no "current value" for this - it's simply something that must be passed, and
            # set to True, if EngineVersion is changed.  Thus we'll let AWS catch any calling error.
            'AllowMajorVersionUpgrade': (None, None),
            # Literally NO way to verify passwords since AWS will NOT return them once set.
            # So basically DON'T set this on a state def unless you want it to apply at every run.
            # Probably the best you can do is set it once, run, then comment it out.  Then only
            # uncomment when you need to change it again....   Argh!
            'MasterUserPassword': (None, 'MasterUserPassword'),
            'TdeCredentialPassword': (None, None),
            'DBSubnetGroupName': ('DBSubnetGroup.DBSubnetGroupName', 'DBSubnetGroupName'),
            'VpcSecurityGroupIds': ('VPCSecurityGroups[*].VPCSecurityGroupId', 'VpcSecurityGroupIds'),
            'DBSecurityGroups': ('DBSecurityGroups[*].DBSecurityGroupName', 'DBSecurityGroups'),
            'OptionGroupName': ('OptionGroupMemberships[*].OptionGroupName', 'OptionGroupName'),
            'NewDBInstanceIdentifier': ('DBInstanceIdentifier', 'DBInstanceIdentifier'),
            'Domain': ('DomainMemberships[*].Domain', 'Domain'),
            'DomainIAMRoleName': ('DomainMemberships[*].IAMRoleName', 'DomainIAMRoleName'),
            'DBPortNumber': ('Endpoint.Port', None),
            'DBParameterGroupName': ('DBParameterGroups[*].DBParameterGroupName', None)
    }

    # The purpose of this is to determine whether we're currently inside the maintenance window,
    # or WILL be in it after any changes have been applied.  This matters in that if either of
    # these is true, ApplyImmediately is for all intents and purposes force-enabled, for hopefully
    # obvious reasons...  Note that all datetime objects utilized herein are naive by intent.
    save_locale = locale.getlocale(locale.LC_TIME)  # Locale diffs can blow it all up, so save....
    locale.setlocale(locale.LC_TIME, 'C')
    now = datetime.utcnow()
    current_week = now.strftime('%W')
    kwargs = dict([(k, v) for k, v in kwargs.items() if not k.startswith('_')])
    if 'PreferredMaintenanceWindow' in kwargs:
        # AWS always returns this as lowercase, so for comparing later we do the same.
        kwargs['PreferredMaintenanceWindow'] = kwargs['PreferredMaintenanceWindow'].lower()
    maintenance_window = kwargs['PreferredMaintenanceWindow'] \
            if 'PreferredMaintenanceWindow' in kwargs else current['PreferredMaintenanceWindow']
    try:
        # Format: ddd:hh24:mi-ddd:hh24:mi
        # Valid Days: mon | tue | wed | thu | fri | sat | sun
        # Constraints: Must be at least 30 minutes
        start, stop = maintenance_window.split('-')
        # Insert current year and week-of-year so the day-of-week value has context...
        maintenance_start = datetime.strptime('{0}:{1}:{2}'.format(now.year, current_week, start),
                                              '%Y:%W:%a:%H:%M')
        maintenance_stop = datetime.strptime('{0}:{1}:{2}'.format(now.year, current_week, stop),
                                             '%Y:%W:%a:%H:%M')
        if (maintenance_stop - maintenance_start) < timedelta(minutes=30):
            raise ValueError('Maintenance window must be at least 30 minutes.')
        if maintenance_start <= now < maintenance_stop:
            log.info('Current time is within scheduled maintenance window, setting ApplyImmediately to True')
            kwargs['ApplyImmediately'] = True
    except ValueError:
        msg = 'Malformed value for PreferredMaintenanceWindow: {0}'.format(maintenance_window)
        return _log_and_set_ret(ret, False, msg, 'error', None)
    finally:
        locale.setlocale(locale.LC_TIME, save_locale)   # ...and reset.

    fixed = {}
    from_pending = []
    Tags = []
    ApplyImmediately = kwargs.get('ApplyImmediately', False)
    for param, newparam in create_only_that_we_munge.items():
        # Have to do these first because they mutate kwargs :-/
        if param in kwargs:
            if param == 'Tags':
                Tags = kwargs[param]        # Save them off for later application
                current_tags = list_tags_for_resource(ResourceName=current['DBInstanceArn'], region=region,
                                                      key=key, keyid=keyid, profile=profile)
            elif param == 'Port':
                if newparam not in kwargs:  # Don't clobber an explicit value
                    kwargs[newparam] = kwargs[param]
            del kwargs[param]
    for param, newval in kwargs.items():
        if param in create_only_params or param.startswith('_') or newval is None:
            log.debug('ignoring param {0}'.format(param))
            continue
        elif param not in modify_params and param not in special_cases:
            log.warning('Unknown option `{0}` seen - passing it along but AWS may barf'
                        ' on it later.'.format(param))
        if param in special_cases:
            # ApplyImmediately is a meta-param and shouldn't appear in changes output
            if param == 'ApplyImmediately':
                fixed[param] = newval
                continue
            oldval = []
            path_in_current, path_in_pending = special_cases[param]
            if path_in_current:
                oldval = JMESPath.search(path_in_current, current)
            if ApplyImmediately and path_in_pending and path_in_pending in pending:
                oldval = JMESPath.search(path, pending)
                from_pending += [param]
            # Some searches return singletons, some lists; some params take singletons but
            # return lists; some params take lists and return lists; etc., etc.  Normalize!
            oldval_list = [oldval] if oldval and not isinstance(oldval, list) else oldval
            newval_list = [newval] if newval and not isinstance(newval, list) else newval
            if not oldval_list or not __utils__['boto3.json_objs_equal'](oldval_list, newval_list,
                                                                         try_json=True):
                fixed[param] = newval
                # EXTRA-special case...
                if param == 'DBParameterGroupName':
                    log.warning("You're changing the DB Parameter Group.  The parameter group "
                            "change occurs immediately.  However, parameter changes only occur "
                            "when you reboot the DB instance manually without failover.")
        else:
            oldval = JMESPath.search(param, current)
            if ApplyImmediately and param in pending:
                oldval = JMESPath.search(param, pending)
                from_pending += [param]
            if newval != oldval:
                fixed[param] = newval

    now = set([l for l in cat1 if fixed.get(l) is not None])
    later = set()
    risky = set([l for l in cat5 if fixed.get(l) is not None])
    side_effects = set()
    if ApplyImmediately:
        now |= set([l for l in cat2 if fixed.get(l) is not None])
        now |= set([l for l in cat3 if fixed.get(l) is not None])
        # Unsafe things which will get applied as a SIDE-EFFECT of ApplyImmediately because they
        # are currently pending application.  Technically, `pending` can contain options outside of
        # sets 2 and 3 if they happen to be in the process of being applied at the time we run, but
        # as they'll happen regardless of anything we might do, it's safe to ignore them...
        side_effects |= set([l for l in cat3 if fixed.get(l) and l in from_pending])
        risky |= set([l for l in cat3 if fixed.get(l) is not None])
    else:
        later |= set([l for l in cat2 if fixed.get(l) is not None])
        later |= set([l for l in cat3 if fixed.get(l) is not None])

    expect_downtime = False
    if any(risky) or any(side_effects):
        expect_downtime = True

    need_update = False
    need_update_tags = False
    if fixed:
        need_update = True
    if Tags:
        t = ensure_tags(ResourceName=current['DBInstanceArn'], Tags=Tags, commit=False,
                region=region, key=key, keyid=keyid, profile=profile)
        if t['result'] == None:
            need_update_tags = True

    if not need_update and not need_update_tags:
        msg = 'DB Instance {0} is in the desired state.'.format(DBInstanceIdentifier)
        return _log_and_set_ret(ret, True, msg)

    log.debug('kwargs: {0}'.format(kwargs))
    log.debug('fixed: {0}'.format(fixed))
    if not commit:    # Generally means we're running with test=True, so pander to that assumption.
        msg = 'DB Instance {0} would be updated.'.format(DBInstanceIdentifier)
        desired = deepcopy(current).update(fixed)
        if Tags:
            desired.update({'Tags': Tags})
        return _log_and_set_ret(ret, None, msg, changes={'old': current, 'new': desired})

    if need_update:
        try:
            fixed.update({'DBInstanceIdentifier': DBInstanceIdentifier})
            conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
            r = conn.modify_db_instance(**fixed).get('DBInstance')
        except ClientError as e:
            msg = 'Failed to modify DB Instance {0}: {1}'.format(DBInstanceIdentifier, e)
            return _log_and_set_ret(ret, False, msg, 'error', None)
    else:
        r = describe_db_instances(DBInstanceIdentifier=DBInstanceIdentifier, region=region, key=key,
                                  keyid=keyid, profile=profile)
        if not r:
            msg = 'Failure while modifying DB Instance {0}: unknown error'.format(
                    DBInstanceIdentifier)
            return _log_and_set_ret(ret, False, msg, 'error', None)
        r = r[0]
    if need_update_tags:
        t = ensure_tags(ResourceName=current['DBInstanceArn'], Tags=Tags, region=region, key=key,
                keyid=keyid, profile=profile)
        ret['comment'] = '{0}  {1}'.format(ret['comment'], t['comment'])
    r['Tags'] = list_tags_for_resource(ResourceName=current['DBInstanceArn'], region=region,
            key=key, keyid=keyid, profile=profile)

    if not wait:
        msg = 'DB Instance {0} modification requested.'.format(DBInstanceIdentifier)
        return _log_and_set_ret(ret, True, msg, changes={'old': current, 'new': r})

    log.info('Waiting up to {0} seconds for DB Instance {1} to become available.'.format(wait,
             DBInstanceIdentifier))
    o_wait = wait
    while wait > 0:
        r = describe_db_instances(DBInstanceIdentifier=DBInstanceIdentifier, region=region, key=key,
                                  keyid=keyid, profile=profile)
        if not r:
            msg = 'Failure while modifying DB Instance {0}: unknown error'.format(
                    DBInstanceIdentifier)
            return _log_and_set_ret(ret, False, msg, 'error', None)
        r = r[0]
        if r.get('DBInstanceStatus') in bad_db_instance_stati:
            msg = 'Error while modifying DB Instance {0}: DBInstanceStatus returned `{1}`'.format(
                    DBInstanceIdentifier, r[0].get('DBInstanceStatus'))
            return _log_and_set_ret(ret, False, msg, 'error', {'old': current, 'new': r})
        if r['DBInstanceStatus'] == 'available':
            msg = 'DB Instance {0} updated.'.format(DBInstanceIdentifier)
            return _log_and_set_ret(ret, True, msg, changes={'old': current, 'new': r})
        sleep = wait if wait % 60 == wait else 60
        log.info('Sleeping {0} seconds for DB Instance {1} to become available.'.format(sleep,
                 DBInstanceIdentifier))
        time.sleep(sleep)
        wait -= sleep
    msg = 'DB Instance {0} not available after {1} seconds!'.format(DBInstanceIdentifier, o_wait)
    return _log_and_set_ret(ret, False, msg, 'error', {'old': current, 'new': r})


def create_db_instance_read_replica(DBInstanceIdentifier, SourceDBInstanceIdentifier, wait=0,
                                    region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Create an RDS DB Instance Read Replica

    DBInstanceIdentifier
        The DB Instance identifier of the Read Replica to be creeated.

    SourceDBInstanceIdentifier
        The identifier of the DB instance that will act as the source for the Read Replica.  Each DB
        instance can have up to five Read Replicas.
        Constraints:
            Must be the identifier of an existing MySQL, MariaDB, or PostgreSQL DB instance.
            Can specify a DB instance that is a MySQL Read Replica only if the source is running
            MySQL 5.6.
            Can specify a DB instance that is a PostgreSQL DB instance only if the source is running
            PostgreSQL 9.3.5 or later.
            The specified DB instance must have automatic backups enabled, its backup retention
            period must be greater than 0.
            If the source DB instance is in the same region as the Read Replica, specify a valid DB
            instance identifier.
            If the source DB instance is in a different region than the Read Replica, specify a
            valid DB instance ARN.

    DBInstanceClass
        The instance type providing the desired compute and memory capacity of the Read Replica.
        Note:
            Not all instance classes are available in all regions for all DB engines.
            Currently available instance sizes (and the relative pricing thereof) can be found at
            https://aws.amazon.com/rds/details/

    AvailabilityZone
        The Amazon EC2 Availability Zone that the Read Replica will be created in.
        Default:  A random, system-chosen Availability Zone in the endpoint's region.

    Port
        The port number that the DB instance uses for connections.
        Default:  Inherits from the source DB instance
        Valid Values:  1150-65535

    AutoMinorVersionUpgrade
        Indicates that minor engine upgrades will be applied automatically to the Read Replica
        during the maintenance window.
        Default:  Inherits from the source DB instance

    Iops
        The amount of Provisioned IOPS to be initially allocated for the DB instance.

    OptionGroupName
        The Option Group to associate the DB instance with.  If omitted, the default Option Group
        for the engine specified will be used.

    PubliclyAccessible
        Specifies the accessibility options for the DB instance.  A value of True specifies an
        Internet-facing instance with a publicly resolvable DNS name, which resolves to a public IP
        address.  A value of false specifies an internal instance with a DNS name that resolves to
        a private IP address.
        Default:
            The default behavior varies depending on whether a VPC has been requested or not.  The
            following list shows the default behavior in each case.
                Default VPC: true
                VPC: false
        If no DB subnet group has been specified as part of the request and the PubliclyAccessible
        value has not been set, the DB instance will be publicly accessible.  If a specific DB
        subnet group has been specified as part of the request and the PubliclyAccessible value has
        not been set, the DB instance will be private.

    Tags
      A list of tag dicts, each in the standard AWS {'Key': <key>, 'Value': <value>} format
      Constraints:
          A key is the (required) name of the tag.  The string value can be from 1 to 128 Unicode
          characters in length and cannot be prefixed with "aws:" or "rds:".  The string can only
          contain only the set of Unicode letters, digits, white-space, '_', '.', '/', '=', '+',
          and '-'.
          A value is the (optional) value of the tag.  The string value can be from 1 to 256
          Unicode characters in length and cannot be prefixed with "aws:" or "rds:".  The string
          can only contain only the set of Unicode letters, digits, white-space, '_', '.', '/',
          '=', '+', and '-'.

    DBSubnetGroupName
        Specifies a DB subnet group for the DB instance.  The new DB instance will be created in the
        VPC associated with the DB subnet group.  If no DB subnet group is specified, then the new DB
        instance is not created in a VPC.
        Constraints:
            Must contain no more than 255 alphanumeric characters, periods, underscores, spaces, or
            hyphens.
            Must not be the string 'default'.
            Can only be specified if the Source DB Instance is in another region.
            The DB subnet group must be in the same region in which the operation is running.
            All Read Replicas in one region and created from the same Source DB Instance must either:
              - Specify DB Subnet Groups from the same VPC.  All these Read Replicas will be created
                in the same VPC.
              - Not specify a DB subnet group.  All these Read Replicas will be created outside of
                any VPC.

    StorageType
        Specifies the storage type to be associated with the Read Replica.
        If you specify io1, you must also include a value for the Iops parameter.
        Valid values:  standard | gp2 | io1
        Default:  io1 if the Iops parameter is specified; otherwise standard.

    CopyTagsToSnapshot
        True to copy all tags from the Read Replica to snapshots of the Read Replica; otherwise
        False.
        Default:  False

    MonitoringInterval
        The interval, in seconds, between points when Enhanced Monitoring metrics are collected for
        the Read Replica.  To disable collecting Enhanced Monitoring metrics, specify 0.  If
        MonitoringRoleArn is specified, then you must also set MonitoringInterval to a value other
        than 0.
        Default:  0
        Valid Values: 0, 1, 5, 10, 15, 30, 60

    MonitoringRoleArn
        The ARN for the IAM role that permits RDS to send enhanced monitoring metrics to CloudWatch
        Logs.  If MonitoringInterval is set to a value other than 0, then you must supply a
        MonitoringRoleArn value.

    KmsKeyId
        The AWS KMS key ID for an encrypted Read Replica.  The KMS key ID is either the ARN, the KMS
        key identifier, or the KMS key alias for the KMS encryption key.
        If you create an unencrypted Read Replica and specify a value for the KmsKeyId parameter,
        Amazon RDS encrypts the target Read Replica using the specified KMS encryption key.
        If you create an encrypted Read Replica from your AWS account, you can specify a value for
        KmsKeyId to encrypt the Read Replica with a new KMS encryption key.  If you don't specify a
        value for KmsKeyId, then the Read Replica is encrypted with the same KMS key as the source
        DB instance.  If you create an encrypted Read Replica in a different AWS region, then you
        must specify a KMS key for the destination AWS region.  KMS encryption keys are specific to
        the region that they are created in, and you cannot use encryption keys from one region in
        another region.

    PreSignedUrl
        The URL that contains a Signature Version 4 signed request for the
        CreateDBInstanceReadReplica API action in the AWS region that contains the source DB
        instance.  The PreSignedUrl parameter must be used when encrypting a Read Replica from
        another AWS region.  The presigned URL must be a valid request for the
        CreateDBInstanceReadReplica API action that can be executed in the source region that
        contains the encrypted DB instance.  The presigned URL request must contain the following
        parameter values:
            DestinationRegion
                The AWS Region that the Read Replica is created in.  This region is the same one
                where the CreateDBInstanceReadReplica action is called that contains this presigned
                URL.  For example, if you create an encrypted Read Replica in the us-east-1 region,
                and the source DB instance is in the west-2 region, then you call the
                CreateDBInstanceReadReplica action in the us-east-1 region and provide a presigned
                URL that contains a call to the CreateDBInstanceReadReplica action in the us-west-2
                region.  For this example, the DestinationRegion in the presigned URL must be set to
                the us-east-1 region.
            KmsKeyId
                The KMS key identifier for the key to use to encrypt the Read Replica in the
                destination region.  This is the same identifier for both the
                CreateDBInstanceReadReplica action that is called in the destination region, and the
                action contained in the presigned URL.
            SourceDBInstanceIdentifier
                The DB instance identifier for the encrypted Read Replica to be created.  This
                identifier must be in the ARN format for the source region.  For example, if you
                create an encrypted Read Replica from a DB instance in the us-west-2 region, then
                your SourceDBInstanceIdentifier would look like this example:
                    arn:aws:rds:us-west-2:123456789012:instance:mysql-instance1-instance-20161115

    EnableIAMDatabaseAuthentication
        True to enable mapping of AWS Identity and Access Management (IAM) accounts to database
        accounts; otherwise False.
        You can enable IAM database authentication for the following database engines
            For MySQL 5.6, minor version 5.6.34 or higher
            For MySQL 5.7, minor version 5.7.16 or higher
            Aurora 5.6 or higher.
        Default:  False

    SourceRegion
        The ID of the region that contains the source for the read replica.

    CLI example to create an RDS DB Instance Read Replica::

        salt myminion boto3_rds.create_read_replica replicaname source_name
    '''
    # XXX TODO re-implement via _create()
    required = ('DBInstanceIdentifier', 'SourceDBInstanceIdentifier')
    kwargs = dict([(k, v) for k, v in kwargs.items() if not k.startswith('_')])
    for r in required:
        if r not in kwargs:
            raise SaltInvocationError('{0} is a required paramaeter'.format(r))
    ret = {'name': kwargs['DBInstanceIdentifier'], 'result': True, 'comment': '', 'changes': {}}
    r = describe_db_instances(DBInstanceIdentifier=kwargs['DBInstanceIdentifier'], region=region,
                              key=key, keyid=keyid, profile=profile)
    if len(r):
        msg = 'DB Read Replica {0} exists.'.format(kwargs['DBInstanceIdentifier'])
        return _log_and_set_ret(ret, False, msg, 'error', None)
    s = describe_db_instances(DBInstanceIdentifier=kwargs['SourceDBInstanceIdentifier'],
                              region=region, key=key, keyid=keyid, profile=profile)
    if not len(s):
        msg = 'DB Replication source instance {0} not found.'.format(
                kwargs['SourceDBInstanceIdentifier'])
        log.error(msg)
        return _log_and_set_ret(ret, False, msg, 'error', None)
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.create_db_instance_read_replica(**kwargs).get('DBInstance')
        r['Tags'] = list_tags_for_resource(ResourceName=current['DBInstanceArn'], region=region,
                key=key, keyid=keyid, profile=profile)
    except ClientError as e:
        msg = 'Failed to create DB Read Replica {0}: {1}'.format(kwargs['DBInstanceIdentifier'], e)
        return _log_and_set_ret(ret, False, msg, 'error', None)

    if not wait:
        msg = 'DB Read Replica {0} requested.'.format(kwargs['DBInstanceIdentifier'])
        return _log_and_set_ret(ret, True, msg, changes={'old': None, 'new': r})

    log.info('Waiting up to {0} seconds for DB Read Replica {1} to become available.'.format(wait,
             DBInstanceIdentifier))
    o_wait = wait
    while wait > 0:
        r = describe_db_instances(DBInstanceIdentifier=DBInstanceIdentifier, region=region, key=key,
                                  keyid=keyid, profile=profile)
        if not r:
            msg = 'Error while creating DB Read Replica {0}: unknown error'.format(
                    DBInstanceIdentifier)
            return _log_and_set_ret(ret, False, msg, 'error', None)
        r = r[0]
        if r['DBInstanceStatus'] in bad_db_instance_stati:
            msg = 'Error while creating DB Read Replica {0}: DBInstanceStatus returned `{1}`'.format(
                    DBInstanceIdentifier, r['DBInstanceStatus'])
            return _log_and_set_ret(ret, False, msg, 'error', None)
        elif r['DBInstanceStatus'] == 'available':
            msg = 'DB Read Replica {0} created.'.format(DBInstanceIdentifier)
            return _log_and_set_ret(ret, True, msg, changes={'old': None, 'new': r})
        sleep = wait if wait % 60 == wait else 60
        log.info('Sleeping {0} seconds for DB Read Replica {1} to become available.'.format(sleep,
                 DBInstanceIdentifier))
        time.sleep(sleep)
        wait -= sleep
    msg = 'DB Read Replica {0} not available after {1} seconds!'.format(DBInstanceIdentifier, o_wait)
    return _log_and_set_ret(ret, False, msg, 'error', {'old': None, 'new': r})


def delete_db_instance(wait=0, region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Delete an RDS DB Instance.

    DBInstanceIdentifier
        The DB instance identifier for the DB instance to be deleted.  This parameter is not
        case-sensitive.
        Constraints:
            Must contain from 1 to 63 alphanumeric characters or hyphens
            First character must be a letter
            Cannot end with a hyphen or contain two consecutive hyphens

    SkipFinalSnapshot
        Determines whether a final DB snapshot is created before the DB instance is deleted.
        If True, no DB snapshot is created.  If False, a DB snapshot is created before the DB
        instance is deleted.
        Notes:
            Specify true when deleting a Read Replica.
            The FinalDBSnapshotIdentifier parameter must be specified if SkipFinalSnapshot is False.
            When a DB instance is in a failure state and has a status of 'incompatible-restore',
            'failed', or 'incompatible-network', it can only be deleted if SkipFinalSnapshot is True.
        Default: False

    FinalDBSnapshotIdentifier
        The DBSnapshotIdentifier of the new DBSnapshot created when SkipFinalSnapshot is false.
        Notes:
            Specifying this parameter while SkipFinalShapshot is true results in an error.
        Constraints:
            Must be 1 to 255 alphanumeric characters
            First character must be a letter
            Cannot end with a hyphen or contain two consecutive hyphens
            Cannot be specified when deleting a Read Replica.

    wait
        Int value (default: 0) requesting salt to wait 'wait' seconds for the specified updates
        to apply, and the DB instance to be considered "absent" by AWS.

    CLI example::

        salt myminion boto3_rds.delete myrds skip_final_snapshot=True \
                region=us-east-1
    '''
    func = 'db_instance'
    identifier = 'DBInstanceIdentifier'
    desc = 'DB Instance'
    required = None
    wait = wait
    kwargs = dict([(k, v) for k, v in kwargs.items() if not k.startswith('_')])
    return _delete(func=func, identifier=identifier, desc=desc, required=required, wait=wait,
                   region=region, key=key, keyid=keyid, profile=profile, **kwargs)


def describe_option_groups(jmespath=None,
                           region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Return a detailed listing of all, or just some, Option Groups visible in the
    current scope.  Arbitrary subelements or subsections of the returned dataset
    can be selected by passing in a valid JMSEPath filter as well.

    OptionGroupName
        The name of the option group to describe.  Cannot be supplied together with EngineName or
        MajorEngineVersion.

    Filters
        This parameter is a placeholder - it is not currently implemented within the AWS API.

    EngineName
        Filters the list of option groups to only include groups associated with a specific
        database engine.

    MajorEngineVersion
        Filters the list of option groups to only include groups associated with a specific
        database engine version.  If specified, then EngineName must also be specified.

    CLI example::

        salt myminion boto3_rds.describe_option_groups OptionGroupName='my-option-group'

    '''
    kwargs = dict([(k, v) for k, v in kwargs.items() if not k.startswith('_')])
    return _describe(func=sys._getframe().f_code.co_name, error_code_name='OptionGroupNotFoundFault',
                     jmespath=jmespath, jmesflatten='OptionGroupsList', identifier='OptionGroupName',
                     region=region, key=key, keyid=keyid, profile=profile, **kwargs)


def create_option_group(region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Create an RDS Option Group

    OptionGroupName
        Specifies the name of the option group to be created.
        Constraints:
            Must be 1 to 255 alphanumeric characters or hyphens
            First character must be a letter
            Cannot end with a hyphen or contain two consecutive hyphens

    EngineName
        Specifies the name of the engine that this option group should be associated with.

    MajorEngineVersion
        Specifies the major version of the engine that this option group should be associated with.

    OptionGroupDescription
        The description of the option group.

    Tags
        A list of tag dicts, each in the standard AWS {'Key': <key>, 'Value': <value>} format
        Constraints:
            A key is the (required) name of the tag.  The string value can be from 1 to 128 Unicode
            characters in length and cannot be prefixed with "aws:" or "rds:".  The string can only
            contain only the set of Unicode letters, digits, white-space, '_', '.', '/', '=', '+',
            and '-'.
            A value is the (optional) value of the tag.  The string value can be from 1 to 256
            Unicode characters in length and cannot be prefixed with "aws:" or "rds:".  The string
            can only contain only the set of Unicode letters, digits, white-space, '_', '.', '/',
            '=', '+', and '-'.

    commit
        Boolean (default: True) declaring whether to actually apply any changes or simply report
        them back as "what would happen if"...

    CLI example to create an RDS Option Group::

        salt myminion boto3_rds.create_option_group my-opt-group mysql 5.6 "group description"
    '''
    func = 'option_group'
    identifier = 'OptionGroupName'
    path = 'OptionGroup'
    desc = 'Option Group'
    required = ('EngineName', 'MajorEngineVersion', 'OptionGroupDescription')
    wait = 0
    kwargs = dict([(k, v) for k, v in kwargs.items() if not k.startswith('_')])
    return _create(func=func, identifier=identifier, path=path, desc=desc, required=required,
                   region=region, key=key, keyid=keyid, profile=profile, **kwargs)


def delete_option_group(wait=0, region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Delete an RDS Option Group.

    OptionGropuName
        The name of an RDS Option Group to delete

    CLI example::

        salt myminion boto3_rds.delete_option_group my-opt-group region=us-east-1
    '''
    func = 'option_group'
    identifier = 'OptionGroupName'
    desc = 'Option Group'
    required = None
    wait = 0
    kwargs = dict([(k, v) for k, v in kwargs.items() if not k.startswith('_')])
    return _delete(func=func, identifier=identifier, desc=desc, required=required, wait=wait,
                   region=region, key=key, keyid=keyid, profile=profile, **kwargs)


def describe_db_parameter_groups(jmespath=None,
                                 region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Return a detailed listing of all, or just some, DB Parameter Groups visible in the
    current scope.  Arbitrary subelements or subsections of the returned dataset
    can be selected by passing in a valid JMSEPath filter as well.

    DBParameterGroupName
        The name of a specific DB parameter group to return details for.
        Constraints:
            Must be 1 to 255 alphanumeric characters
            First character must be a letter
            Cannot end with a hyphen or contain two consecutive hyphens
    Filters
        This parameter is a placeholder - it is not currently implemented within the AWS API.

    CLI example::

        salt myminion boto3_rds.describe_db_parameter_groups DBParameterGroupName=bobDobbs

    '''
    kwargs = dict([(k, v) for k, v in kwargs.items() if not k.startswith('_')])
    return _describe(func=sys._getframe().f_code.co_name, error_code_name='DBParameterGroupNotFound',
                     jmespath=jmespath, jmesflatten='DBParameterGroups',
                     identifier='DBParameterGroup', region=region, key=key, keyid=keyid,
                     profile=profile, **kwargs)


def create_db_parameter_group(region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Create an RDS DB Parameter Group.  Note that this call DOES NOT TAKE a `Parameters` option.
    ALL parameter groups are created with a default set of params and values, and must be customized
    afterward with a call to modify_db_parameter_group() - this is an AWS limitation, and has
    nothing to do with boto or salt.

    DBParameterGroupName
        The name of the DB parameter group.
        Constraints:
            Must be 1 to 255 alphanumeric characters
            First character must be a letter
            Cannot end with a hyphen or contain two consecutive hyphens
        Notes:
            This value is stored as a lowercase string.

    DBParameterGroupFamily
        The DB parameter group family name.  A DB parameter group can be associated with one and
        only one DB parameter group family, and can be applied only to a DB instance running a
        database engine and engine version compatible with that DB parameter group family.

    Description
        The description for the DB parameter group.

    Tags
        A list of tag dicts, each in the standard AWS {'Key': <key>, 'Value': <value>} format
        Constraints:
            A key is the (required) name of the tag.  The string value can be from 1 to 128 Unicode
            characters in length and cannot be prefixed with "aws:" or "rds:".  The string can only
            contain only the set of Unicode letters, digits, white-space, '_', '.', '/', '=', '+',
            and '-'.
            A value is the (optional) value of the tag.  The string value can be from 1 to 256
            Unicode characters in length and cannot be prefixed with "aws:" or "rds:".  The string
            can only contain only the set of Unicode letters, digits, white-space, '_', '.', '/',
            '=', '+', and '-'.

    commit
        Boolean (default: True) declaring whether to actually apply any changes or simply report
        them back as "what would happen if"...

    CLI example to create an RDS DB Parameter Group::

        salt myminion boto3_rds.create_db_parameter_group my-param-group mysql5.6 \
                "group description"
    '''
    func = 'db_parameter_group'
    identifier = 'DBParameterGroupName'
    path = 'DBParameterGroup'
    desc = 'DB Parameter Group'
    required = ('DBParameterGroupFamily', 'Description')
    wait = 0
    kwargs = dict([(k, v) for k, v in kwargs.items() if not k.startswith('_')])
    return _create(func=func, identifier=identifier, path=path, desc=desc, required=required,
                   region=region, key=key, keyid=keyid, profile=profile, **kwargs)


def modify_db_parameter_group(region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Modifies the parameters of a DB Parameter Group.

    Note: Changes to dynamic parameters are applied immediately.  Changes to static parameters
    require a reboot without failover to the DB instance associated with the parameter group
    before the change can take effect.
    Warning: After you modify a DB parameter group, you should wait at least 5 minutes before
    creating your first DB instance that uses that DB parameter group as the default parameter
    group.  This allows Amazon RDS to fully complete the modify action before the parameter group
    is used as the default for a new DB instance.  This is especially important for parameters that
    are critical when creating the default database for a DB instance, such as the character set
    for the default database defined by the character_set_database parameter.  You can use the
    Parameter Groups option of the Amazon RDS console or the DescribeDBParameters command to verify
    that your DB parameter group has been created or modified.

    DBParameterGroupName
        The name of the DB parameter group.
        Constraints:
            Must be the name of an existing DB parameter group
            Must be 1 to 255 alphanumeric characters
            First character must be a letter
            Cannot end with a hyphen or contain two consecutive hyphens

    Parameters
        A list of parameter dicts, each consisting of a parameter names, value, and the apply
        method for the parameter update.  Each dict can include the following keys:
            ParameterName
                Specifies the name of the parameter.  Required.
            ParameterValue
                Specifies the value of the parameter.  Required.
            ApplyMethod
                Indicates when to apply parameter updates.  Required.
                Valid Values:  immediate | pending-reboot
            Description
                Provides a description of the parameter.
            Source
                Indicates the source of the parameter value.
            ApplyType
                Specifies the engine specific parameters type.
            DataType
                Specifies the valid data type for the parameter.
            AllowedValues
                Specifies the valid range of values for the parameter.
            IsModifiable
                Boolean indicating whether the parameter can be modified.  Some parameters have
                security or operational implications that prevent them from being changed.
            MinimumEngineVersion
                The earliest engine version to which the parameter can apply.
        Note:
            You can use the immediate value with dynamic parameters only.  You can use the
            pending-reboot value for both dynamic and static parameters, whereby changes are
            applied when you reboot the DB instance without failover.

    Tags
        A list of tag dicts, each in the standard AWS {'Key': <key>, 'Value': <value>} format
        Constraints:
            A key is the (required) name of the tag.  The string value can be from 1 to 128 Unicode
            characters in length and cannot be prefixed with "aws:" or "rds:".  The string can only
            contain only the set of Unicode letters, digits, white-space, '_', '.', '/', '=', '+',
            and '-'.
            A value is the (optional) value of the tag.  The string value can be from 1 to 256
            Unicode characters in length and cannot be prefixed with "aws:" or "rds:".  The string
            can only contain only the set of Unicode letters, digits, white-space, '_', '.', '/',
            '=', '+', and '-'.

    commit
        Boolean (default: True) declaring whether to actually apply any changes or simply report
        them back as "what would happen if"...

    CLI example::

        salt myminion boto3_rds.modify_db_parameter_group DBParameterGroupName=My-Param-Group \
                Parameters='{"back_log":1, "binlog_cache_size":4096}' XXX FIXME
    '''
    ### A lot of hoops have to be jumped to present half-way sane semantics for this call, because:
    #   1)  create_db_parameter_group() does not take a Parameters arg, and returns no Parameters,
    #       and takes a Tags arg, but returns no Tags.
    #   2)  describe_db_parameter_groups() does not return Parameters, or Tags
    #   3)  modify_db_parameter_group() takes a Parameters arg, but not a Tags arg, and returns
    #       Parameters but not Tags
    #   4)  describe_db_parameters() returns Parameters but not Tags
    #   5)  list_tags_for_resource() returns Tags but nothing else
    #   6)  add_tags_to_resource() is used to both add and modify Tags if the resource already exists
    #   7)  remove_tags_from_resource() is used to remove Tags
    #   8)  at most, 20 params can be modifed in a single call to modify_db_parameter_group()
    # Fortunately, I worked around #2, at least for Tags, via _describe()...

    kwargs = dict([(k, v) for k, v in kwargs.items() if not k.startswith('_')])
    required = ('DBParameterGroupName', 'Parameters')
    for r in required:
        if r not in kwargs:
            raise SaltInvocationError('{0} is a required paramaeter'.format(r))
    ret = {'name': kwargs['DBParameterGroupName'], 'result': True, 'comment': '', 'changes': {}}
    Tags = kwargs.pop('Tags', None)
    Parameters = kwargs.pop('Parameters', None)
    current = describe_db_parameter_groups(DBParameterGroupName=kwargs['DBParameterGroupName'],
                                           region=region, key=key, keyid=keyid, profile=profile)
    if not len(current):
        msg = 'DB Parameter Group {0} not found.'.format(kwargs['DBParameterGroupName'])
        return _log_and_set_ret(ret, False, msg, 'error')
    current = current[0]

    update = False
    if Parameters:
        curr_params = describe_db_parameters(DBParameterGroupName=kwargs['DBParameterGroupName'],
                region=region, key=key, keyid=keyid, profile=profile)
        update = _get_param_diffs(curr_params, Parameters)

    update_tags = False
    if Tags:
        r = ensure_tags(current['DBParameterGroupArn'], Tags, commit=False,
                region=region, key=key, keyid=keyid, profile=profile)
        if r['result'] == None:
            update_tags = True

    if not update and not update_tags:
        msg = 'DB Parameter Group {0} is already in the correct state.'.format(
                kwargs['DBParameterGroupName'])
        return _log_and_set_ret(ret, True, msg)

    if update_tags:
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.modify_db_parameter_group(**kwargs).get('DBParameterGroupName')
        new = describe_db_parameter_groups(DBParameterGroupName=kwargs['DBParameterGroupName'],
                                           region=region, key=key, keyid=keyid, profile=profile)
        msg = 'DB Parameter Group {0} modified.'.format(kwargs['DBParameterGroupName'])
        return _log_and_set_ret(ret, True, msg, changes={'old': None, 'new': new[0]})
    except ClientError as e:
        msg = 'Failed to modify DB Parameter Group {0}: {1}'.format(
                kwargs['DBParameterGroupName'], e)
        return _log_and_set_ret(ret, False, msg, 'error')


def delete_db_parameter_group(wait=0, region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Delete an RDS DB Parameter Group.

    DBParameterGroupName
        The name of the DB parameter group to delete.
        Constraints:
            Must be the name of an existing DB parameter group
            You cannot delete a default DB parameter group
            Cannot be associated with any DB instances

    CLI example::

        salt myminion boto3_rds.delete_parameter_group my-param-group \
                region=us-east-1
    '''
    func = 'db_parameter_group'
    identifier = 'OptionGroupName'
    desc = 'DB Parameter Group'
    required = None
    wait = 0
    kwargs = dict([(k, v) for k, v in kwargs.items() if not k.startswith('_')])
    return _delete(func=func, identifier=identifier, desc=desc, required=required, wait=wait,
                   region=region, key=key, keyid=keyid, profile=profile, **kwargs)


def describe_db_parameters(jmespath=None,
                           region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Returns a detailed description of the current parameters set on a given DB Parameter
    Group.

    DBParameterGroupName
        The name of a specific DB Parameter Group to return details for.
        Constraints:
            Must be 1 to 255 alphanumeric characters
            First character must be a letter
            Cannot end with a hyphen or contain two consecutive hyphens

    Source
        The parameter types to return.
        Default:  All parameter types returned
        Valid Values:  user | system | engine-default

    Filters
        This parameter is a placeholder - it is not currently implemented within the AWS API.

    CLI example to description of parameters::

        salt myminion boto3_rds.describe_parameters parametergroupname\
            region=us-east-1
    '''
    required = ('DBParameterGroupName',)
    kwargs = dict([(k, v) for k, v in kwargs.items() if not k.startswith('_')])
    for r in required:
        if r not in kwargs:
            raise SaltInvocationError('{0} is a required paramaeter'.format(r))
    r = describe_db_parameter_groups(DBParameterGroupName=kwargs['DBParameterGroupName'],
                                     region=region, key=key, keyid=keyid, profile=profile)
    if not len(r):
        msg = 'DB Parameter Group {0} not found.'.format(kwargs['DBParameterGroupName'])
        log.error(msg)
        ret.update({'result': False, 'comment': msg})
        return ret

    return _describe(func=sys._getframe().f_code.co_name,
                     error_code_name='DBParameterGroupNotFound', jmespath=jmespath,
                     jmesflatten='Parameters', region=region, key=key, keyid=keyid,
                     profile=profile, **kwargs)


def describe_db_subnet_groups(jmespath=None,
                              region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Return a detailed listing of all, or just some, DB Subnet Groups visible in the
    current scope.  Arbitrary subelements or subsections of the returned dataset
    can be selected by passing in a valid JMSEPath filter as well.

    DBSubnetGroupName
        The name of a DB subnet group to return details for.

    Filters
        This parameter is a placeholder - it is not currently implemented within the AWS API.

    CLI example::

        salt myminion boto3_rds.describe_db_subnet_groups DBSubnetGroupName=bobDobbs
        salt myminion boto3_rds.describe_db_subnet_groups jmespath='"[?DBSubnetGroupName==`bobDobbs`]"'
    '''
    kwargs = dict([(k, v) for k, v in kwargs.items() if not k.startswith('_')])
    return _describe(func=sys._getframe().f_code.co_name,
                     error_code_name='DBSubnetGroupNotFoundFault', jmespath=jmespath,
                     jmesflatten='DBSubnetGroups', identifier='DBSubnetGroupName', region=region,
                     key=key, keyid=keyid, profile=profile, **kwargs)


def create_db_subnet_group(region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Create an RDS DB Subnet Group

    DBSubnetGroupName
        The name for the DB subnet group.  This value is stored as a lowercase string.
        Constraints:
            Must contain no more than 255 alphanumeric characters, periods, underscores, spaces, or
            hyphens.
            Must not be the string 'default'.

    DBSubnetGroupDescription
        The description for the DB subnet group.

    SubnetIds
        A list of the EC2 Subnet IDs for the DB subnet group.

    Tags
        A list of tag dicts, each in the standard AWS {'Key': <key>, 'Value': <value>} format
        Constraints:
            A key is the (required) name of the tag.  The string value can be from 1 to 128 Unicode
            characters in length and cannot be prefixed with "aws:" or "rds:".  The string can only
            contain only the set of Unicode letters, digits, white-space, '_', '.', '/', '=', '+',
            and '-'.
            A value is the (optional) value of the tag.  The string value can be from 1 to 256
            Unicode characters in length and cannot be prefixed with "aws:" or "rds:".  The string
            can only contain only the set of Unicode letters, digits, white-space, '_', '.', '/',
            '=', '+', and '-'.

    commit
        Boolean (default: True) declaring whether to actually apply any changes or simply report
        them back as "what would happen if"...

    CLI example to create an RDS DB Subnet Group::

        salt myminion boto3_rds.create_db_subnet_group DBSubnetGroupName=my-subnet-group \
                DBSubnetGroupDescription="My Favorite Subnet Group EVAR!" \
                SubetIds='[subnet-1234abcd,subnet-abcd1234]'
    '''
    func = 'db_subnet_group'
    identifier = 'DBSubnetGroupName'
    path = 'DBSubnetGroup'
    desc = 'DB Subnet Group'
    required = ('DBSubnetGroupDescription', 'SubnetIds')
    wait = 0
    kwargs = dict([(k, v) for k, v in kwargs.items() if not k.startswith('_')])
    return _create(func=func, identifier=identifier, path=path, desc=desc, required=required,
                   region=region, key=key, keyid=keyid, profile=profile, **kwargs)


def modify_db_subnet_group(commit=True, region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Modify an existing RDS DB Subnet Group.

    DBSubnetGroupName
        The name for the DB subnet group.  This value is stored as a lowercase string.
        Constraints:
            Must contain no more than 255 alphanumeric characters, periods, underscores, spaces, or
            hyphens.
            Must not be the string 'default'.

    DBSubnetGroupDescription
        The description for the DB subnet group.

    SubnetIds
        A list of the EC2 Subnet IDs for the DB subnet group.

    Tags
        A list of tag dicts, each in the standard AWS {'Key': <key>, 'Value': <value>} format
        Constraints:
            A key is the (required) name of the tag.  The string value can be from 1 to 128 Unicode
            characters in length and cannot be prefixed with "aws:" or "rds:".  The string can only
            contain only the set of Unicode letters, digits, white-space, '_', '.', '/', '=', '+',
            and '-'.
            A value is the (optional) value of the tag.  The string value can be from 1 to 256
            Unicode characters in length and cannot be prefixed with "aws:" or "rds:".  The string
            can only contain only the set of Unicode letters, digits, white-space, '_', '.', '/',
            '=', '+', and '-'.

    commit
        Boolean (default: True) declaring whether to actually apply any changes or simply report
        them back as "what would happen if"...

    CLI example::

        salt myminion boto3_rds.modify_db_subnet_group DBSubnetGroupName=my-subnet-group \
                SubetIds='[subnet-1234abcd,subnet-abcd1234]'
    '''
    kwargs = dict([(k, v) for k, v in kwargs.items() if not k.startswith('_')])
    required = ('DBSubnetGroupName', 'SubnetIds')
    Tags = kwargs.pop('Tags', None)
    for r in required:
        if r not in kwargs:
            raise SaltInvocationError('{0} is a required paramaeter'.format(r))
    ret = {'name': kwargs['DBSubnetGroupName'], 'result': True, 'comment': '', 'changes': {}}
    current = describe_db_subnet_groups(DBSubnetGroupName=kwargs['DBSubnetGroupName'],
                                        region=region, key=key, keyid=keyid, profile=profile)
    if not len(current):
        msg = 'DB Subnet Group {0} not found.'.format(kwargs['DBSubnetGroupName'])
        return _log_and_set_ret(ret, False, msg, 'error')
    current = current[0]
    need_update = False
    if 'DBSubnetGroupDescription' in kwargs:
        if  current['DBSubnetGroupDescription'] != kwargs['DBSubnetGroupDescription']:
            need_update = True
    current_snids = [s['SubnetIdentifier'] for s in current.get('Subnets', [])]
    if set(kwargs['SubnetIds']) != set(current_snids):
        need_update = True
    r = ensure_tags(current['DBSubnetGroupArn'], Tags, commit=False,
            region=region, key=key, keyid=keyid, profile=profile)
    if r['result'] == None:
        need_update = True
    if not need_update:
        msg = 'DB Subnet Group {0} already in the correct state.'.format(kwargs['DBSubnetGroupName'])
        return _log_and_set_ret(ret, True, msg)
    if not commit:
        msg = 'DB Subnet Group {0} would be updated.'.format(kwargs['DBSubnetGroupName'])
        current['SubnetIds'] = current_snids
        kwargs['Tags'] = Tags
        return _log_and_set_ret(ret, None, msg, changes={'old': current, 'new': kwargs})

    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.modify_db_subnet_group(**kwargs).get('DBSubnetGroup')
        if Tags:
            t = ensure_tags(r['DBSubnetGroupArn'], Tags, region=region, key=key, keyid=keyid,
                    profile=profile)
            if t['result'] is False:
                msg = 'Error setting tags on DB Subnet Group {0}: {1}'.format(
                        kwargs['DBSubnetGroupName'], t['comment'])
                return _log_and_set_ret(ret, False, msg, 'error')
        new = describe_db_subnet_groups(DBSubnetGroupName=kwargs['DBSubnetGroupName'],
                                        region=region, key=key, keyid=keyid, profile=profile)
        if current != new[0]:
            msg = 'DB Subnet Group {0} modified.'.format(kwargs['DBSubnetGroupName'])
            return _log_and_set_ret(ret, True, msg, changes={'old': current, 'new': new[0]})
        return ret
    except ClientError as e:
        msg = 'Failed to modify DB Subnet Group {0}: {1}'.format( kwargs['DBSubnetGroupName'], e)
        return _log_and_set_ret(ret, False, msg, 'error')


def delete_db_subnet_group(wait=0, region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Delete an RDS DB Subnet Group.

    DBSubnetGroupName
        The name of the database subnet group to delete.
        Note:
            You cannot delete the default subnet group.
        Constraints:
            Must contain no more than 255 alphanumeric characters, periods, underscores, spaces,
            or hyphens.
            Must not be the string 'default'.

    wait
        Int value (default: 0) requesting salt to wait 'wait' seconds for the specified actions
        to apply, and the resource to be considered "absent" by AWS.

    CLI example::

        salt myminion boto3_rds.delete_subnet_group my-subnet-group \
                region=us-east-1
    '''
    func = 'db_subnet_group'
    identifier = 'DBSubnetGroupName'
    desc = 'DB Subnet Group'
    required = None
    wait = 0
    kwargs = dict([(k, v) for k, v in kwargs.items() if not k.startswith('_')])
    return _delete(func=func, identifier=identifier, desc=desc, required=required, wait=wait,
                   region=region, key=key, keyid=keyid, profile=profile, **kwargs)


def get_endpoint(DBInstanceIdentifier, region=None, key=None, keyid=None, profile=None):
    '''
    Return the endpoint of an RDS DB Instance.

    DBInstanceIdentifier
        The DB Instance Identifier for which the endpoint should be returned.

    CLI example::

        salt myminion boto3_rds.get_endpoint myrds

    '''
    r = describe_db_instances(DBInstanceIdentifier=DBInstanceIdentifier, region=region, key=key,
                              keyid=keyid, profile=profile)
    if not len(r):
        msg = 'DB Instance {0} not found.'.format(DBInstanceIdentifie)
        log.error(msg)
        return None
    return JMESPath.search('[0].Endpoint.Address', r)


def _log_and_set_ret(ret, result, comment=None, loglevel='info', changes=None):
    ret.update({'result': result})
    ret.update({'comment': comment}) if comment else None
    ret.update({'changes': changes}) if changes else None
    loggit = getattr(log, loglevel)
    loggit(comment)
    return ret


def _describe(func, error_code_name, jmespath=None, jmesflatten=None, identifier=None,
              region=None, key=None, keyid=None, profile=None, **kwargs):
    # Note that there is an issue with salt auto-parsing some commandline args (e.g. jmespath='[]')
    # into data structures which JMESPath expects to be literal strings.  I started to kluge in work
    # arounds for these corner cases but the code complexity quickly ballooned, for little effective
    # benefit, so instead I backed it all out and wrote this comment :)
    # TL;DR
    # If you find yourself with errors such as `Passed invalid arguments: unhashable type: 'list'.`
    # when experimenting with new jmespath values, try "inside quotes" to force salt to treat them
    # as strings from the commandline - e.g. for `jmespath='[]'`, instead use `jmespath='"[]"'`.
    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
    kwargs = dict([(k, v) for k, v in kwargs.items() if not k.startswith('_')]) if kwargs else {}
    try:
        if conn.can_paginate(func):
            pag = conn.get_paginator(func)
            pit = pag.paginate(**kwargs)
            # This flattens the return structure to the same format as would be returned by the else
            # clause below, which permits Tags to be added if needed, and jmespath to operate on a
            # level playing field.
            pit = pit.search(jmesflatten) if jmesflatten is not None else pit
            ret = [p for p in pit if p is not None]
            ret = ret if ret else []
        else:
            func = getattr(conn, func)
            ret = func(**kwargs)
            ret = JMESPath.search(jmesflatten, ret) if jmesflatten is not None else ret
    except ClientError as e:
        code = getattr(e, 'response', {}).get('Error', {}).get('Code')
        if code == error_code_name:
            # Return empty list if requested resource not found
            return []
        raise
    except ParamValidationError as e:
        msg = '  '.join('{0}'.format(e).split('\n'))
        raise CommandExecutionError(msg)
    except (KeyError, AttributeError) as e:
        raise CommandExecutionError('AWS RDS client API does not seem to have a function {0}'
                                    ''.format(func))
    arn_map = {
        'DBInstanceIdentifier': 'DBInstanceArn',
        'DBSubnetGroupName': 'DBSubnetGroupArn',
        'OptionGroupName': 'OptionGroupArn',
        'DBParameterGroupName': 'DBParameterGroupArn'
    }
    if identifier:
        arn_attr = arn_map.get(identifier)
        for r in ret:
            arn = r.get(arn_attr) if arn_attr else None
            if arn:
                r['Tags'] = list_tags_for_resource(ResourceName=arn, region=region,
                                                   key=key, keyid=keyid, profile=profile)
    # Have to do this after Tags are added in case we want to apply jmespath to them
    return JMESPath.search(jmespath, ret) if jmespath is not None else ret


def _create(func, identifier, path, desc, required=None, wait=0, commit=True, status_path=None,
            error_stati=None, avail_status='available', region=None, key=None, keyid=None,
            profile=None, **kwargs):
    required = [identifier] if not isinstance(required, list) else \
            (required + [identifier]) if identifier not in required else required
    kwargs = dict([(k, v) for k, v in kwargs.items() if not k.startswith('_')]) if kwargs else {}
    for r in required:
        if r not in kwargs:
            raise SaltInvocationError('{0} is a required paramaeter'.format(r))
    ret = {'name': kwargs[identifier], 'result': True, 'comment': '', 'changes': {}}

    describe_func = globals().get('describe_' + func + 's')
    if not describe_func:
        raise CommandExecutionError('boto3_rds module does not have a function `{0}`'
                                    ''.format('describe_' + func + 's'))
    args = {identifier: kwargs[identifier], 'region': region, 'key': key, 'keyid': keyid,
            'profile': profile}
    r = describe_func(**args)
    if len(r):
        msg = '{0} {1} already exists.'.format(desc, kwargs[identifier])
        return _log_and_set_ret(ret, False, msg, 'error', None)

    if not commit:
        msg = '{0} {1} would be created'.format(desc, kwargs[identifier])
        return _log_and_set_ret(ret, None, msg, changes={'old': None, 'new': kwargs})

    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
    try:
        create_func = getattr(conn, 'create_' + func)
    except (KeyError, AttributeError) as e:
        raise CommandExecutionError('RDS client API does not seem to have a function `{0}`'.format(
                                    'create_' + func))
    try:
        r = create_func(**kwargs)
        if not r or path not in r:    # I don't THINK this can happen, but....
            msg = 'Failed to create {0} {1}: unknown error'.format(desc, kwargs[identifier])
            return _log_and_set_ret(ret, False, msg, 'error', None)
    except ClientError as e:
        msg = 'Failed to create {0} {1}: {2}'.format(desc, kwargs[identifier], e)
        return _log_and_set_ret(ret, False, msg, 'error', None)
    except ParamValidationError as e:
        msg = '  '.join('{0}'.format(e).split('\n'))
        return _log_and_set_ret(ret, False, msg, 'error', None)

    if not wait:
        msg = '{0} {1} creation requested.'.format(desc, kwargs[identifier])
        r = describe_func(**args)
        return _log_and_set_ret(ret, True, msg, changes={'old': None, 'new': r[0]})

    log.info('Waiting up to {0} seconds for {1} {2} to become available.'.format(wait, desc,
              kwargs[identifier]))
    o_wait = wait
    while wait > 0:
        r = describe_func(**args)
        if not r:
            msg = '{0} {1} should exist but was not found.'.format(desc, kwargs[identifier])
            return _log_and_set_ret(ret, False, msg, 'error', None)
        r = r[0]
        if status_path:
            curr_status = JMESPath.search(status_path, r)
            curr_status = curr_status[0] if isinstance(curr_status, list) else curr_status
            if curr_status and curr_status == avail_status:
                msg = '{0} {1} created and {2}.'.format(desc, kwargs[identifier], avail_status)
                return _log_and_set_ret(ret, True, msg, changes={'old': None, 'new': r})
            if error_stati and curr_status in error_stati:
                msg = 'Error creating {0} {1}: resource status check returned {2}.'.format(desc,
                        kwargs[identifier], curr_status)
                return _log_and_set_ret(ret, False, msg, 'error', {'old': None, 'new': r})
        sleep = wait if wait % 60 == wait else 60
        log.info('Sleeping {0} seconds for {1} {2} to become {3}.'.format(sleep, desc,
                 kwargs[identifier], avail_status))
        time.sleep(sleep)
        wait -= sleep
    msg = '{0} {1} not {2} after {3} seconds!'.format(desc, DBInstanceIdentifier,
            avail_status, o_wait)
    return _log_and_set_ret(ret, False, msg, 'error', None)


def _delete(func, identifier, desc, required=None, wait=0,
            region=None, key=None, keyid=None, profile=None, **kwargs):
    required = [identifier] if not isinstance(required, list) else (required + [identifier]) if identifier not in required else required
    kwargs = dict([(k, v) for k, v in kwargs.items() if not k.startswith('_')]) if kwargs else {}
    for r in required:
        if r not in kwargs:
            raise SaltInvocationError('{0} is a required paramaeter'.format(r))
    ret = {'name': kwargs[identifier], 'result': True, 'comment': '', 'changes': {}}

    describe_func = globals().get('describe_' + func + 's')
    if not describe_func:
        raise CommandExecutionError('boto3_rds module does not have a function `{0}`'
                                    ''.format('describe_' + func + 's'))
    args = {identifier: kwargs[identifier], 'region': region, 'key': key, 'keyid': keyid,
            'profile': profile}
    old = describe_func(**args)
    if not len(old):
        msg = '{0} {1} not found.'.format(desc, kwargs[identifier])
        return _log_and_set_ret(ret, False, msg, 'error', None)
    old = old[0]
    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
    try:
        delete_func = getattr(conn, 'delete_' + func)
    except (KeyError, AttributeError) as e:
        raise CommandExecutionError('RDS client API does not seem to have a function `{0}`'.format(
                                    'delete_' + func))
    try:
        r = delete_func(**kwargs)
    except ClientError as e:
        msg = 'Failed to delete {0} {1}: {2}'.format(desc, kwargs[identifier], e)
        return _log_and_set_ret(ret, False, msg, 'error', None)
    except ParamValidationError as e:
        msg = '  '.join('{0}'.format(e).split('\n'))
        return _log_and_set_ret(ret, False, msg, 'error', None)

    if not wait:
        msg = '{0} {1} deletion requested.'.format(desc, kwargs[identifier])
        return _log_and_set_ret(ret, True, msg, changes={'old': old, 'new': None})

    log.info('Waiting up to {0} seconds for {1} {2} to disappear.'.format(wait, desc,
              kwargs[identifier]))
    o_wait = wait
    while wait > 0:
        r = describe_func(**args)
        if not r:
            msg = '{0} {1} deleted.'.format(desc, kwargs[identifier])
            return _log_and_set_ret(ret, True, msg, changes={'old': old, 'new': None})
        sleep = wait if wait % 60 == wait else 60
        log.info('Sleeping {0} seconds for {1} {2} to disappear.'.format(sleep, desc,
                 kwargs[identifier]))
        time.sleep(sleep)
        wait -= sleep
    msg = '{0} {1} not gone after {2} seconds!'.format(desc, DBInstanceIdentifier, o_wait)
    return _log_and_set_ret(ret, False, msg, 'error', None)
