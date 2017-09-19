# -*- coding: utf-8 -*-
'''
Manage RDSs
===========

.. versionadded:: 2015.8.0

Create and destroy RDS instances. Be aware that this interacts with Amazon's
services, and so may incur charges.

This module uses ``boto``, which can be installed via package, or pip.

This module accepts explicit rds credentials but can also utilize
IAM roles assigned to the instance through Instance Profiles. Dynamic
credentials are then automatically obtained from AWS API and no further
configuration is necessary. More information available `here
<http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html>`_.

If IAM roles are not used you need to specify them either in a pillar file or
in the minion's config file:

.. code-block:: yaml

    rds.keyid: GKTADJGHEIQSXMKKRBJ08H
    rds.key: askdjghsdfjkghWupUjasdflkdfklgjsdfjajkghs

It's also possible to specify ``key``, ``keyid`` and ``region`` via a profile,
either passed in as a dict, or as a string to pull from pillars or minion
config:

.. code-block:: yaml

    myprofile:
        keyid: GKTADJGHEIQSXMKKRBJ08H
        key: askdjghsdfjkghWupUjasdflkdfklgjsdfjajkghs
            region: us-east-1

.. code-block:: yaml
XXX FIXME
    Ensure myrds RDS exists:
      boto_rds.present:
        - name: myrds
        - allocated_storage: 5
        - storage_type: standard
        - db_instance_class: db.t2.micro
        - engine: MySQL
        - master_username: myuser
        - master_user_password: mypass
        - region: us-east-1
        - keyid: GKTADJGHEIQSXMKKRBJ08H
        - key: askdjghsdfjkghWupUjasdflkdfklgjsdfjajkghs
        - tags:
            key: value

.. code-block:: yaml
XXX FIXME
    Ensure parameter group exists:
        create-parameter-group:
          boto_rds.parameter_present:
            - name: myparametergroup
            - db_parameter_group_family: mysql5.6
            - description: "parameter group family"
            - parameters:
              - binlog_cache_size: 32768
              - binlog_checksum: CRC32
            - region: eu-west-1
.. note::

:depends: boto3

'''

# Import Python Libs
from __future__ import absolute_import
import logging
import os

# Import Salt Libs
from salt.exceptions import SaltInvocationError
import salt.utils

log = logging.getLogger(__name__)


def __virtual__():
    '''
    Only load if boto is available.
    '''
    check_fun = 'boto3_rds.add_tags_to_resource'
    if check_fun in __salt__:
        return 'boto3_rds'
    return (False, __salt__.missing_fun_string(check_fun))


def _log_and_set_ret(ret, result, comment=None, loglevel='info', changes=None):
    ret.update({'result': result})
    ret.update({'comment': comment}) if comment else None
    ret.update({'changes': changes}) if changes else None
    loggit = getattr(log, loglevel)
    loggit(comment)
    return ret


def db_instance_present(**kwargs):
    '''
    Ensure an AWS RDS Instance exists.

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
        Int value (default: 0) requesting salt to wait 'wait' seconds for the specified updates
        to apply, and the DB instance to return to an available state.  SOME changes can take a
        SIGNIFICANT time to complete (days in one scenario) and thus will fail a state run given any
        sensible finite wait time.  When making changes which run the risk of long application
        times, it's recommended to leave the default of 'wait=0' and simply check periodically to
        see if the updates have completed.

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
    kwargs['commit'] = False if __opts__['test'] else True
    current = __salt__['boto3_rds.describe_db_instances'](DBInstanceIdentifier, region=region,
                                                          key=key, keyid=keyid, profile=profile)
    if len(current) > 1:
        # I don't THINK this is possible but paranoia in coding is a virtue, right?
        msg = "Multiple DB Instances matching `{0}` found.".format(DBInstanceIdentifier)
        log.error(msg)
        return {'name': DBInstanceIdentifier, 'result': False, 'comment': msg, 'changes': {}}
    elif len(current):
        return __salt__['boto3_rds.modify_db_instance'](**kwargs)
    else:
        return __salt__['boto3_rds.create_db_instance'](**kwargs)


def db_instance_absent(**kwargs):
    '''
    Ensure an RDS DB Instance is absent.

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
        The DBSnapshotIdentifier of the new DBSnapshot created when SkipFinalSnapshot is set to false .
        Notes:
            Specifying this parameter while SkipFinalShapshot is true results in an error.
        Constraints:
            Must be 1 to 255 alphanumeric characters
            First character must be a letter
            Cannot end with a hyphen or contain two consecutive hyphens
            Cannot be specified when deleting a Read Replica.

    wait
        Int value (default: 0) requesting salt to wait 'wait' seconds for the specified actions
        to apply, and the resource to be considered "absent" by AWS.

    region
        Region to connect to.

    key
        Secret key to be used.

    keyid
        Access key to be used.

    profile
        A dict with region, key and keyid, or a pillar key (string) that
        contains a dict with region, key and keyid.
    '''
    required = ('DBInstanceIdentifier',)
    kwargs = dict([(k, v) for k, v in kwargs.items() if not k.startswith('_')])
    for r in required:
        if r not in kwargs:
            raise SaltInvocationError('{0} is a required paramaeter'.format(r))
    ret = {'name': kwargs['DBInstanceIdentifier'], 'result': True, 'comment': '', 'changes': {}}
    current = __salt__['boto3_rds.describe_db_instances'](
            DBInstanceIdentifier=kwargs['DBInstanceIdentifier'], region=region, key=key,
            keyid=keyid, profile=profile)
    if not len(current):
        msg = '{0} DB Instance already absent.'.format(kwargs['DBInstanceIdentifier'])
        return _log_and_set_ret(ret, True, msg)
    current = current[0]
    if __opts__['test']:
        msg = 'DB Instance {0} would be removed.'.format(kwargs['DBInstanceIdentifier'])
        return _log_and_set_ret(ret, None, msg, changes={'old': current, 'new': None})
    return __salt__['boto3_rds.delete_db_instance'](**kwargs)


def db_subnet_group_present(**kwargs):
    '''
    Ensure a DB subnet group exists, with the provided settings.

    DBSubnetGroupName
        The name for the DB subnet group. This value is stored as a lowercase string.
        Constraints:
            Must contain no more than 255 alphanumeric characters, periods, underscores,
            spaces, or hyphens.
            Must not be the string `default`.

    DBSubnetGroupDescription
        The description for the DB subnet group.

    Subnets
        A list of the EC2 Subnet IDs and/or Name Tags of Subnets to be attached to the
        DB subnet group.

    Tags
        A list of tag dicts, each in the standard AWS {'Key': <key>, 'Value': <value>} format.
        Constraints:
            A key is the (required) name of the tag.  The string value can be from 1 to 128 Unicode
            characters in length and cannot be prefixed with "aws:" or "rds:".  The string can only
            contain only the set of Unicode letters, digits, white-space, '_', '.', '/', '=', '+',
            and '-'.
            A value is the (optional) value of the tag.  The string value can be from 1 to 256
            Unicode characters in length and cannot be prefixed with "aws:" or "rds:".  The string
            can only contain only the set of Unicode letters, digits, white-space, '_', '.', '/',
            '=', '+', and '-'.

    region
        Region to connect to.

    key
        Secret key to be used.

    keyid
        Access key to be used.

    profile
        A dict with region, key and keyid, or a pillar key (string) that
        contains a dict with region, key and keyid.
    '''
    required = ('DBSubnetGroupName',)
    kwargs = dict([(k, v) for k, v in kwargs.items() if not k.startswith('_')])
    for r in required:
        if r not in kwargs:
            raise SaltInvocationError('{0} is a required paramaeter'.format(r))
    ret = {'name': kwargs['DBSubnetGroupName'], 'result': True, 'comment': '', 'changes': {}}
    kwargs['commit'] = False if __opts__['test'] else True
    # Convert 'Subnets' to 'SubnetIds' as needed.
    SubnetIds = set()
    kwargs['Subnets'] = kwargs['Subnets'] if kwargs.get('Subnets', None) else []
    for sn in kwargs.pop('Subnets', []):
        if sn.startswith('subnet-'):
            SubnetIds |= set([sn])
        else:
            r = __salt__['boto_vpc.get_resource_id']('subnet', name=sn, region=region, key=key,
                                                     keyid=keyid, profile=profile)
            if not r or not r.get('id'):
                msg = 'Could not resolve Subnet Name {0} to an ID.'.format(sn)
                return _log_and_set_ret(ret, False, msg, 'error')
            SubnetIds |= set([r['id']])
    kwargs['SubnetIds'] = list(SubnetIds)
    r = __salt__['boto3_rds.describe_db_subnet_groups'](DBSubnetGroupName=DBSubnetGroupName,
                                                       region=region, key=key, keyid=keyid,
                                                       profile=profile)
    if len(r):
        return __salt__['boto3_rds.modify_db_subnet_group'](**kwargs)
    else:
        return __salt__['boto3_rds.create_db_subnet_group'](**kwargs)


def db_subnet_group_absent(**kwargs):
    '''
    Ensure an RDS DB Subnet Group is absent.

    DBSubnetGroupName
        The name of the database subnet group to be removed.
        Note:
            You cannot delete the default subnet group.
        Constraints:
            Must contain no more than 255 alphanumeric characters, periods, underscores, spaces,
            or hyphens.
            Must not be the string 'default'.

    wait
        Int value (default: 0) requesting salt to wait 'wait' seconds for the specified actions
        to apply, and the resource to be considered "absent" by AWS.

    region
        Region to connect to.

    key
        Secret key to be used.

    keyid
        Access key to be used.

    profile
        A dict with region, key and keyid, or a pillar key (string) that
        contains a dict with region, key and keyid.
    '''
    required = ('DBSubnetGroupName',)
    kwargs = dict([(k, v) for k, v in kwargs.items() if not k.startswith('_')])
    for r in required:
        if r not in kwargs:
            raise SaltInvocationError('{0} is a required paramaeter'.format(r))
    ret = {'name': kwargs['DBSubnetGroupName'], 'result': True, 'comment': '', 'changes': {}}
    current = __salt__['boto3_rds.describe_db_subnet_groups'](
            DBSubnetGroupName=kwargs['DBSubnetGroupName'], region=region, key=key,
            keyid=keyid, profile=profile)
    if not len(current):
        msg = '{0} DB Subnet Group already absent.'.format(kwargs['DBSubnetGroupName'])
        return _log_and_set_ret(ret, True, msg)
    current = current[0]
    if __opts__['test']:
        msg = 'DB Subnet Group {0} would be removed.'.format(kwargs['DBSubnetGroupName'])
        return _log_and_set_ret(ret, None, msg, changes={'old': current, 'new': None})
    return __salt__['boto3_rds.delete_db_subnet_group'](**kwargs)


def db_parameter_group_present(**kwargs):
    '''
    Ensure an RDS DB Parameter Group exists with the given parameters.

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

    Parameters

    region
        Region to connect to.

    key
        Secret key to be used.

    keyid
        Access key to be used.

    profile
        A dict with region, key and keyid, or a pillar key (string) that
        contains a dict with region, key and keyid.
    '''
    required = ('DBParameterGroupName',)
    kwargs = dict([(k, v) for k, v in kwargs.items() if not k.startswith('_')])
    for r in required:
        if r not in kwargs:
            raise SaltInvocationError('{0} is a required paramaeter'.format(r))
    ret = {'name': kwargs['DBParameterGroupName'], 'result': True, 'comment': '', 'changes': {}}
    kwargs['commit'] = False if __opts__['test'] else True
    r = __salt__['boto3_rds.describe_db_parameter_groups'](DBParameterGroupName=DBParameterGroupName,
                                                           region=region, key=key, keyid=keyid,
                                                           profile=profile)
    if len(r):
        return __salt__['boto3_rds.modify_db_parameter_group'](**kwargs)
    else:
        return __salt__['boto3_rds.create_db_parameter_group'](**kwargs)
