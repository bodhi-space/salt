# -*- coding: utf-8 -*-
'''
Execution module for Amazon EMR using boto3
===========================================

.. versionadded:: Nitrogen

:configuration: This module accepts explicit emr credentials but can
    also utilize IAM roles assigned to the instance through Instance Profiles.
    Dynamic credentials are then automatically obtained from AWS API and no
    further configuration is necessary. More Information available at:

    .. code-block:: text

        http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html

    If IAM roles are not used you need to specify them either in a pillar or
    in the minion's config file:

    .. code-block:: yaml

        emr.keyid: GKTADJGHEIQSXMKKRBJ08H
        emr.key: askdjghsdfjkghWupUjasdflkdfklgjsdfjajkghs

    A region may also be specified in the configuration:

    .. code-block:: yaml

        emr.region: us-east-1

    If a region is not specified, the default is us-east-1.

    It's also possible to specify key, keyid and region via a profile, either
    as a passed in dict, or as a string to pull from pillars or minion config:

    .. code-block:: yaml

        myprofile:
            keyid: GKTADJGHEIQSXMKKRBJ08H
            key: askdjghsdfjkghWupUjasdflkdfklgjsdfjajkghs
            region: us-east-1

    One last method for passing in AWS credentials actually leverages boto's inbuilt
    support for `AWS profiles`__.
    .. __: http://boto3.readthedocs.io/en/latest/guide/configuration.html

    For example, assuming the minion managing AWS states is running salt as root, and
    further that you had created ~/root/.aws/credentials with the following:

    .. code-block:: ini

        [AWS_account1]
        aws_access_key_id = ABCDEFGHIJKLMNOPQRST
        aws_secret_access_key = somereallylongstring/AWS/generatedforyou

        [AnotherAccount]
        aws_access_key_id = ABC123DEF456GHI789J0
        aws_secret_access_key = anotherreallylongstringwhichAWSgenerated

    Then, rather than hardcoding keys and keyids in your pillar or state files (which are very
    likely going into some remote tracking SCM like git or subversion), you instead simply call
    any of the below functions with `aws_profile=AnotherAccount`.  Boto will pull the needed
    credentials from that profile on-the-fly.

    Any of the described config files will work, as this module achieves its goal by passing
    `profile_name=<aws_profile>` (if provided) to `boto3.Session()`, which thus uses the documented
    credential search order (as it is outlined in the link above).


:depends: boto3
'''

# keep lint from choking on _get_conn and _cache_id
#pylint: disable=E0602

# Import Python libs
from __future__ import absolute_import
import logging
import time
import sys

# Import Salt libs
import salt.utils.boto3
from salt.utils import exactly_one
from salt.utils.versions import LooseVersion
from salt.exceptions import SaltInvocationError, CommandExecutionError

log = logging.getLogger(__name__)

# Import third party libs
try:
    #pylint: disable=unused-import
    import botocore
    import boto3
    #pylint: enable=unused-import
    required_botocore_version = '1.5.0'
    required_boto3_version = '1.4.7'
    HAS_BOTO3 = True
    if LooseVersion(botocore.__version__) < LooseVersion(required_botocore_version):
        HAS_BOTO3 = False
    if LooseVersion(boto3.__version__) < LooseVersion(required_boto3_version):
        HAS_BOTO3 = False
    logging.getLogger('boto3').setLevel(logging.CRITICAL)
except ImportError:
    HAS_BOTO3 = False

# AWS API errors we consider "retry-able"...
# I've seen all of these in the wild, depending on my botocore version.
RETRY_ON = ('Throttling', 'ThrottlingException', 'RequestLimitExceeded',
            'Unavailable', 'ServiceUnavailable', 'InternalFailure', 'InternalError')
# AWS AWI states we consider "running" for our purposes...
RUNNING = ['STARTING', 'BOOTSTRAPPING', 'RUNNING', 'WAITING']

def __virtual__():
    '''
    Only load if boto libraries exist and if boto libraries are greater than
    a given version.
    '''
    if HAS_BOTO3:
        return True
    return (False, 'The boto3_emr module could not be loaded: boto3 libraries not found')


def __init__(opts):
    if HAS_BOTO3:
        __utils__['boto3.assign_funcs'](__name__, 'emr',
                  get_conn_funcname='_get_conn',
                  cache_id_funcname='_cache_id',
                  exactly_one_funcname=None)


def _collect_results(func, info_node, args, marker='Marker'):
    ret = []
    Marker = args[marker] if marker in args else ''
    args.pop(marker, None) if not args.get(marker) else None
    retries = 30
    while Marker is not None:
        try:
            r = func(**args)
            sub = r.get(info_node) if info_node else r
            if isinstance(sub, list):
                ret += sub
            else:
                ret = sub
            Marker = r.get(marker)
            args.update({marker: Marker})
        except botocore.exceptions.ParamValidationError as e:
            raise SaltInvocationError(str(e))
        except botocore.exceptions.ClientError as e:
            err = __utils__['boto3.get_error'](e)
            if err['code'] not in RETRY_ON:
                log.error('Error calling {0}({1}): {2}'.format(func.func_name, args, e))
                return None
            if retries:
                log.debug('Transient error ({0}) from API, will retry in 5 seconds'.format(err['code']))
                retries -= 1
                time.sleep(5)
                continue
            log.error('Too many API retries callig {0}({1}).'.format(func.func_name, args))
            return None
    return ret


def _list_resource(name=None, name_param=None, res_type=None, info_node=None,
                   conn=None, region=None, key=None, keyid=None, profile=None,
                   aws_session_token=None, botocore_session=None, aws_profile=None,
                   **args):
    if conn is None:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile,
                         aws_session_token=aws_session_token, botocore_session=botocore_session,
                         aws_profile=aws_profile, test_func='list_clusters')
    try:
        func = 'list_'+res_type
        f = getattr(conn, func)
    except (AttributeError, KeyError) as e:
        raise SaltInvocationError("No function '{0}()' found: {1}".format(func, str(e)))
    args.update({name_param: name}) if name and name_param and name_param not in args else args.update({'Marker': ''})
    args = {k: v for k, v in args.items() if not k.startswith('_')}
    return _collect_results(f, info_node, args)


def _describe_resource(name=None, name_param=None, res_type=None, info_node=None,
                       conn=None, region=None, key=None, keyid=None, profile=None,
                       aws_session_token=None, botocore_session=None, aws_profile=None,
                       **args):
    if conn is None:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile,
                         aws_session_token=aws_session_token, botocore_session=botocore_session,
                         aws_profile=aws_profile, test_func='list_clusters')
    try:
        func = 'describe_'+res_type
        f = getattr(conn, func)
    except (AttributeError, KeyError) as e:
        raise SaltInvocationError("No function '{0}()' found: {1}".format(func, str(e)))
    args.update({name_param: name}) if name and name_param and name_param not in args else args.update({'Marker': ''})
    args = {k: v for k, v in args.items() if not k.startswith('_')}
    return _collect_results(f, info_node, args)


def _delete_resource(name, name_param, desc, res_type, wait=0, status_param=None,
                     status_gone='deleted', region=None, key=None, keyid=None, profile=None,
                     aws_session_token=None, botocore_session=None, aws_profile=None,
                     **args):
    try:
        wait = int(wait)
    except:
        raise SaltInvocationError("Bad value ('{0}') passed for 'wait' param - must be an "
                                  "int or boolean.".format(wait))
    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile,
                     aws_session_token=aws_session_token, botocore_session=botocore_session,
                     aws_profile=aws_profile, test_func='list_clusters')
    if name_param in args:
        name = args[name_param]
    else:
        args[name_param] = name
    args = {k: v for k, v in args.items() if not k.startswith('_')}
    try:
        func = 'delete_'+res_type
        f = getattr(conn, func)
        if wait:
            func = 'describe_'+res_type
            s = globals()[func]
    except (AttributeError, KeyError) as e:
        raise SaltInvocationError("No function '{0}()' found: {1}".format(func, str(e)))
    try:
        f(**args)
        if not wait:
            log.info('{0} {1} deletion requested.'.format(desc.title(), name))
            return True
        log.info('Waiting up to {0} seconds for {1} {2} to be deleted.'.format(wait, desc, name))
        orig_wait = wait
        while wait > 0:
            r = s(name=name, conn=conn)
            if not r or not len(r) or r[0].get(status_param) == status_gone:
                log.info('{0} {1} deleted.'.format(desc.title(), name))
                return True
            sleep = wait if wait % 60 == wait else 60
            log.info('Sleeping {0} seconds for {1} {2} to be deleted.'.format(sleep, desc,
                                                                                  name))
            time.sleep(sleep)
            wait -= sleep
        log.error('{0} {1} not deleted after {2} seconds!'.format(desc.title(), name, orig_wait))
        return False
    except botocore.exceptions.ClientError as e:
        log.error('Failed to delete {0} {1}: {2}'.format(desc, name, e))
        return False


def _create_resource(name, name_param=None, desc=None, res_type=None, wait=0, status_param=None,
                     status_good='available', region=None, key=None, keyid=None, profile=None,
                     aws_session_token=None, botocore_session=None, aws_profile=None,
                     **args):
    try:
        wait = int(wait)
    except:
        raise SaltInvocationError("Bad value ('{0}') passed for 'wait' param - must be an "
                                  "int or boolean.".format(wait))
    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile,
                     aws_session_token=aws_session_token, botocore_session=botocore_session,
                     aws_profile=aws_profile, test_func='list_clusters')
    if name_param in args:
        name = args[name_param]
    else:
        args[name_param] = name
    args = {k: v for k, v in args.items() if not k.startswith('_')}
    try:
        func = 'create_'+res_type
        f = getattr(conn, func)
        if wait:
            func = 'describe_'+res_type+'s'
            s = globals()[func]
    except (AttributeError, KeyError) as e:
        raise SaltInvocationError("No function '{0}()' found: {1}".format(func, str(e)))
    try:
        f(**args)
        if not wait:
            log.info('{0} {1} created.'.format(desc.title(), name))
            return True
        log.info('Waiting up to {0} seconds for {1} {2} to be become available.'.format(wait, desc,
                                                                                        name))
        orig_wait = wait
        while wait > 0:
            r = s(name=name, conn=conn)
            if r and r[0].get(status_param) == status_good:
                log.info('{0} {1} created and available.'.format(desc.title(), name))
                return True
            sleep = wait if wait % 60 == wait else 60
            log.info('Sleeping {0} seconds for {1} {2} to become available.'.format(sleep, desc,
                                                                                    name))
            time.sleep(sleep)
            wait -= sleep
        log.error('{0} {1} not available after {2} seconds!'.format(desc.title(), name, orig_wait))
        return False
    except botocore.exceptions.ClientError as e:
        log.error('Failed to create {0} {1}: {2}'.format(desc, name, e))
        return False


def _modify_resource(name, name_param=None, desc=None, res_type=None, wait=0, status_param=None,
                     status_good='available', region=None, key=None, keyid=None, profile=None,
                     aws_session_token=None, botocore_session=None, aws_profile=None,
                     **args):
    try:
        wait = int(wait)
    except:
        raise SaltInvocationError("Bad value ('{0}') passed for 'wait' param - must be an "
                                  "int or boolean.".format(wait))
    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile,
                     aws_session_token=aws_session_token, botocore_session=botocore_session,
                     aws_profile=aws_profile, test_func='list_clusters')
    if name_param in args:
        name = args[name_param]
    else:
        args[name_param] = name
    args = {k: v for k, v in args.items() if not k.startswith('_')}
    try:
        func = 'modify_'+res_type
        f = getattr(conn, func)
        if wait:
            func = 'describe_'+res_type
            s = globals()[func]
    except (AttributeError, KeyError) as e:
        raise SaltInvocationError("No function '{0}()' found: {1}".format(func, str(e)))
    try:
        f(**args)
        if not wait:
            log.info('{0} {1} modification requested.'.format(desc.title(), name))
            return True
        log.info('Waiting up to {0} seconds for {1} {2} to be become available.'.format(wait, desc,
                                                                                        name))
        orig_wait = wait
        while wait > 0:
            r = s(name=name, conn=conn)
            if r and r[0].get(status_param) == status_good:
                log.info('{0} {1} modified and available.'.format(desc.title(), name))
                return True
            sleep = wait if wait % 60 == wait else 60
            log.info('Sleeping {0} seconds for {1} {2} to become available.'.format(sleep, desc,
                                                                                    name))
            time.sleep(sleep)
            wait -= sleep
        log.error('{0} {1} not available after {2} seconds!'.format(desc.title(), name, orig_wait))
        return False
    except botocore.exceptions.ClientError as e:
        log.error('Failed to modify {0} {1}: {2}'.format(desc, name, e))
        return False


def run_job_flow(name=None, wait=0, region=None, key=None, keyid=None, profile=None,
                 aws_session_token=None, botocore_session=None, aws_profile=None,
                 **args):
    '''
    RunJobFlow creates and starts running a new cluster (job flow).  The cluster runs the steps
    specified.  After the steps complete, the cluster stops and the HDFS partition is lost.  To
    prevent loss of data, configure the last step of the job flow to store results in Amazon S3.
    If the JobFlowInstancesConfig KeepJobFlowAliveWhenNoSteps parameter is set to TRUE, the cluster
    transitions to the WAITING state rather than shutting down after the steps have completed.  For
    additional protection, you can set the JobFlowInstancesConfig TerminationProtected parameter to
    TRUE to lock the cluster and prevent it from being terminated by API call, user intervention,
    or in the event of a job flow error.

    A maximum of 256 steps are allowed in each job flow.

    If your cluster is long-running (such as a Hive data warehouse) or complex, you may require
    more than 256 steps to process your data.  You can bypass the 256-step limitation in various
    ways, including using the SSH shell to connect to the master node and submitting queries
    directly to the software running on the master node, such as Hive and Hadoop.  For more
    information on how to do this, see Add More than 256 Steps to a Cluster in the Amazon EMR
    Management Guide.

    For long running clusters, we recommend that you periodically store your results.

    Note:  The instance fleets configuration is available only in Amazon EMR versions 4.8.0 and
    later, excluding 5.0.x versions.  The RunJobFlow request can contain InstanceFleets
    parameters or InstanceGroups parameters, but not both.

    Name
        The name of the job flow.  If not specified, the value of `name` will be used, if provided,
        else an error will be raised.
    LogUri
        The location in Amazon S3 to write the log files of the job flow.  If a value is not
        provided, logs are not created.
    AdditionalInfo
        A JSON string for selecting additional features.
    AmiVersion
        For Amazon EMR AMI versions 3.x and 2.x.  For Amazon EMR releases 4.0 and later, the Linux
        AMI is determined by the ReleaseLabel specified or by CustomAmiID.  The version of the
        Amazon Machine Image (AMI) to use when launching Amazon EC2 instances in the job flow.  For
        details about the AMI versions currently supported in EMR version 3.x and 2.x, see AMI
        Versions Supported in EMR in the Amazon EMR Developer Guide.  If the AMI supports multiple
        versions of Hadoop (for example, AMI 1.0 supports both Hadoop 0.18 and 0.20), you can use
        the JobFlowInstancesConfig HadoopVersion parameter to modify the version of Hadoop from the
        defaults shown above.
        Note:  Previously, the EMR AMI version API parameter options allowed you to use latest for
            the latest AMI version rather than specify a numerical value.  Some regions no longer
            support this deprecated option as they only have a newer release label version of EMR,
            which requires you to specify an EMR release label release (EMR 4.x or later).
    ReleaseLabel
        The release label for the Amazon EMR release.  For Amazon EMR 3.x and 2.x AMIs, use
        AmiVersion instead.
    Instances
        A {dict} specification of the number and type of Amazon EC2 instances.
        See XXX for exhasutive details
    Steps
        A [list] of {dict}s providing steps to run.
        See XXX for exhasutive details
    BootstrapActions
        A [list] of {dict}s of bootstrap actions to run before Hadoop starts on the cluster nodes.
        See XXX for exhasutive details
    SupportedProducts
        Note
            This options is only for Amazon EMR releases 3.x and 2.x.  For Amazon EMR releases 4.x
            and later, use Applications.
        A list of strings that indicates third-party software to use.  For more information, see
        Use Third Party Applications with Amazon EMR.  Currently supported values are:
            "mapr-m3" - launch the job flow using MapR M3 Edition.
            "mapr-m5" - launch the job flow using MapR M5 Edition.
    NewSupportedProducts
        Note
            This options is only for Amazon EMR releases 3.x and 2.x.  For Amazon EMR releases 4.x
            and later, use Applications.
        A list of strings that indicates third-party software to use with the job flow that accepts
        a user argument list.  EMR accepts and forwards the argument list to the corresponding
        installation script as bootstrap action arguments.  For more information, see "Launch a Job
        Flow on the MapR Distribution for Hadoop" in the Amazon EMR Developer Guide.
        Supported values are:
            "mapr-m3" - launch the cluster using MapR M3 Edition.
            "mapr-m5" - launch the cluster using MapR M5 Edition.
            "mapr" with the user arguments specifying "--edition,m3" or "--edition,m5" - launch the
                job flow using MapR M3 or M5 Edition respectively.
            "mapr-m7" - launch the cluster using MapR M7 Edition.
            "hunk" - launch the cluster with the Hunk Big Data Analtics Platform.
            "hue"- launch the cluster with Hue installed.
            "spark" - launch the cluster with Apache Spark installed.
            "ganglia" - launch the cluster with the Ganglia Monitoring System installed.
        See XXX for exhasutive details
    Applications
        For Amazon EMR releases 4.0 and later.  A {dict} of applications for the cluster.
        Valid values (case insensitive) are:
            "Hadoop"
             "Hive"
             "Mahout"
             "Pig"
             "Spark."
        An application is any Amazon or third-party software that you can add to the cluster.
        This structure contains a list of strings that indicates the software to use with the
        cluster and accepts a user argument list.  Amazon EMR accepts and forwards the argument
        list to the corresponding installation script as bootstrap action argument.  For more
        information, see Using the MapR Distribution for Hadoop.
        Currently supported values are:
            "mapr-m3" - launch the cluster using MapR M3 Edition.
            "mapr-m5" - launch the cluster using MapR M5 Edition.
            "mapr" with the user arguments specifying "--edition,m3" or "--edition,m5" - launch
                 the cluster using MapR M3 or M5 Edition, respectively.
        Note:  In Amazon EMR releases 4.x and later, the only accepted parameter is the application
        name.  To pass arguments to applications, you supply a configuration for each
        application.
        See XXX for exhasutive details
    Configurations
        For Amazon EMR releases 4.0 and later.  The list of configurations supplied for the EMR
        cluster you are creating.  An optional configuration specification to be used when
        provisioning cluster instances, which can include configurations for applications and
        software bundled with Amazon EMR.  A configuration consists of a classification,
        properties, and optional nested configurations.  A classification refers to an
        application-specific configuration file.  Properties are the settings you want to change in
        that file.  For more information, see Configuring Applications.
        See XXX for exhasutive details
    VisibleToAllUsers
        Whether the cluster is visible to all IAM users of the AWS account associated with the
        cluster.  If this value is set to true, all IAM users of that AWS account can view and (if
        they have the proper policy permissions set) manage the cluster.  If it is set to false,
        only the IAM user that created the cluster can view and manage it.
    JobFlowRole
        Also called instance profile and EC2 role.  An IAM role for an EMR cluster.  The EC2
        instances of the cluster assume this role.  The default role is EMR_EC2_DefaultRole.  In
        order to use the default role, you must have already created it using the CLI or console.
    ServiceRole
        The IAM role that will be assumed by the Amazon EMR service to access AWS resources on your
        behalf.
    Tags
        A [list] of {dict}s defining tags to associate with a cluster and propagate to Amazon EC2
        instances.
    SecurityConfiguration
        The name of a security configuration to apply to the cluster.
    AutoScalingRole
        An IAM role for automatic scaling policies.  The default is EMR_AutoScaling_DefaultRole.
        The IAM role provides permissions that the automatic scaling feature requires to launch and
        terminate EC2 instances in an instance group.
    ScaleDownBehavior
        Specifies the way that individual Amazon EC2 instances terminate when an automatic scale-in
        activity occurs or an instance group is resized.  TERMINATE_AT_INSTANCE_HOUR indicates that
        Amazon EMR terminates nodes at the instance-hour boundary, regardless of when the request
        to terminate the instance was submitted.  This option is only available with Amazon EMR
        5.1.0 and later and is the default for clusters created using that version.
        TERMINATE_AT_TASK_COMPLETION indicates that Amazon EMR blacklists and drains tasks from
        nodes before terminating the Amazon EC2 instances, regardless of the instance-hour boundary.
        With either behavior, Amazon EMR removes the least active nodes first and blocks instance
        termination if it could lead to HDFS corruption.  TERMINATE_AT_TASK_COMPLETION available
        only in Amazon EMR version 4.1.0 and later, and is the default for versions of Amazon EMR
        earlier than 5.1.0.
        Valid values are:
            TERMINATE_AT_INSTANCE_HOUR
            TERMINATE_AT_TASK_COMPLETION
    CustomAmiId
        Available only in Amazon EMR version 5.7.0 and later.  The ID of a custom Amazon EBS-backed
        Linux AMI.  If specified, Amazon EMR uses this AMI when it launches cluster EC2 instances.
        For more information about custom AMIs in Amazon EMR, see Using a Custom AMI in the Amazon
        EMR Management Guide.  If omitted, the cluster uses the base Linux AMI for the ReleaseLabel
        specified.  For Amazon EMR versions 2.x and 3.x, use AmiVersion instead.
    EbsRootVolumeSize
        The size, in GiB, of the EBS root device volume of the Linux AMI that is used for each EC2
        instance.  Available in Amazon EMR version 4.x and later.
    RepoUpgradeOnBoot
        Applies only when CustomAmiID is used.  Specifies which updates from the Amazon Linux AMI
        package repositories to apply automatically when the instance boots using the AMI.  If
        omitted, the default is SECURITY, which indicates that only security updates are applied.
        If NONE is specified, no updates are applied, and all updates must be applied manually.
        Valid values are:
            SECURITY
            NONE
    '''
    try:
        wait = int(wait)
    except:
        raise SaltInvocationError("Bad value ('{0}') passed for 'wait' param - must be an "
                                  "int or boolean.".format(wait))
    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile,
                     aws_session_token=aws_session_token, botocore_session=botocore_session,
                     aws_profile=aws_profile, test_func='list_clusters')
    args.update({'Name': name}) if name and 'Name' not in args else None
    args = {k: v for k, v in args.items() if not k.startswith('_')}
    ## <UGH!>
    sn = args.get('Instances', {}).get('Ec2SubnetId')
    sns = args.get('Instances', {}).get('Ec2SubnetIds', [])
    if sn and not sn.startswith('subnet-'):
        try:
            args['Instances']['Ec2SubnetId'] = _get_subnet_id(name=sn, region=region, key=key,
                    keyid=keyid, profile=profile, aws_session_token=aws_session_token,
                    botocore_session=botocore_session, aws_profile=aws_profile)
        except CommandExecutionError as e:
            log.error(str(e))
            return False
    new_sns = []
    for sn in sns:
        if sn.startswith('subnet-'):
            new_sns += [sn]
        else:
            try:
                snid = _get_subnet_id(name=sn, region=region, key=key, keyid=keyid, profile=profile,
                        aws_session_token=aws_session_token, botocore_session=botocore_session,
                        aws_profile=aws_profile)
            except CommandExecutionError as e:
                log.error(str(e))
                return False
            new_sns += [snid]
    if new_sns:
        args['Instances']['Ec2SubnetIds'] = new_sns
    for a in ('EmrManagedMasterSecurityGroup',
              'EmrManagedSlaveSecurityGroup',
              'ServiceAccessSecurityGroup'):
        if args['Instances'].get(a) and not args['Instances'][a].startswith('sg-'):
            try:
                args['Instances'][a] = _get_sg_id(name=args['Instances'][a], region=region, key=key,
                        keyid=keyid, profile=profile, aws_session_token=aws_session_token,
                        botocore_session=botocore_session, aws_profile=aws_profile)
            except CommandExecutionError as e:
                log.error(str(e))
                return False
    ## </UGH!>
    retries = 30
    while True:
        try:
            ret = conn.run_job_flow(**args)
            break
        except botocore.exceptions.ClientError as e:
            err = __utils__['boto3.get_error'](e)
            if err['code'] not in RETRY_ON:
                log.error('Error running job flow {0}: {1}'.format(args['Name'], e))
                return False
            if retries:
                log.debug('Transient error ({0}) from API, will retry in 5 seconds'.format(err['code']))
                retries -= 1
                time.sleep(5)
                continue
            log.error('Too many API retries while running Job Flow {0}.'.format(name))
            return False
    # Note that for historical reasons, a JobFlowId is the same as a ClusterId...
    ClusterId = ret.get('JobFlowId')
    if not ClusterId:
        log.error('Error running Job Flow / Cluster `{0}`: No ClusterId found'.format(args['Name']))
        return False
    if not wait:
        return describe_cluster(ClusterId=ClusterId, conn=conn)
    log.info('Waiting up to {0} seconds for Job Flow / Cluster `{1}` ({2}) to become ready.'.format(
            wait, args['Name'], ClusterId))
    orig_wait = wait
    while wait > 0:
        r = describe_cluster(ClusterId=ClusterId, conn=conn, ClusterStates=[])
        state = r.get('Status', {}).get('State')
        if state in ('STARTING', 'BOOTSTRAPPING'):
            sleep = wait if wait % 60 == wait else 60
            log.info('Sleeping {0} seconds for Job Flow / Cluster `{1}` to become ready.  '
                     'Current state: {2}'.format(sleep, args['Name'], state))
            time.sleep(sleep)
            wait -= sleep
            continue
        elif state in ('TERMINATED', 'TERMINATED_WITH_ERRORS',):
            reason = r.get('Status', {}).get('StateChangeReason', {}).get('Message')
            log.error('Job Flow / Cluster `{0}` terminated:  {1}'.format(args['Name'], reason))
            return False
        else:  # All other states imply success of some sort or another...
            return r
    log.error('Cluster {0} not ready after {1} seconds.'.format(args['Name'], orig_wait))
    return False


def create_cluster(*args, **kwargs):
    '''
    The only difference between a standing vs. a transient EMR cluster is whether
    `job.Instances.KeepJobFlowAliveWhenNoSteps` is True, so let's create a convenience alias.
    '''
    return run_job_flow(*args, **kwargs)


def get_cluster_ids(name, conn=None, region=None, key=None, keyid=None, profile=None,
                    aws_session_token=None, botocore_session=None, aws_profile=None,
                    **args):
    '''
    Given the name of a cluster, return the ClusterIds of any clusters with that Name tag.
    If a ClusterId is passed in, return it unchanged.

    Example:

    .. code-block:: bash

        salt myminion boto3_emr.get_cluster_ids my_emr_cluster
    '''
    ret = list_clusters(conn=conn, region=region, key=key, keyid=keyid, profile=profile,
                        aws_session_token=aws_session_token, botocore_session=botocore_session,
                        aws_profile=aws_profile, **args)
    if not ret or not isinstance(ret, list):
        msg = 'No cluster found with Name `{0}`'.format(name)
        log.info(msg)
        return []
    return [n['Id'] for n in ret if name in (n['Id'], n['Name'])]


def list_bootstrap_actions(name=None, conn=None, region=None, key=None, keyid=None, profile=None,
                           aws_session_token=None, botocore_session=None, aws_profile=None,
                           ClusterStates=RUNNING, **args):
    '''
    Return details about the Bootstrap Actions associated with a given cluster

    Example:

    .. code-block:: bash

        salt myminion boto3_emr.list_bootstrap_actions my_emr_cluster
    '''
    name_param = 'ClusterId'
    if name_param in args:
        name = args[name_param]
    else:
        args[name_param] = name
    if name:
        clids = get_cluster_ids(name=name, conn=conn, region=region, key=key, keyid=keyid,
                                profile=profile, aws_session_token=aws_session_token,
                                botocore_session=botocore_session, aws_profile=aws_profile,
                                ClusterStates=ClusterStates)
        if not clids:
            msg = 'No resource found with Name {0}'.format(name)
            log.error(msg)
            return None
        if len(clids) > 1:
            msg = 'Multiple resources found with Name {0}: {1}'.format(name, clids)
            log.error(msg)
            return None
        args.update({name_param: clids[0]})
    return _list_resource(name=name, name_param=name_param, res_type='bootstrap_actions',
                          info_node='BootstrapActions', conn=conn, region=region, key=key,
                          keyid=keyid, profile=profile, aws_session_token=aws_session_token,
                          botocore_session=botocore_session, aws_profile=aws_profile, **args)


def list_clusters(conn=None, region=None, key=None, keyid=None, profile=None,
                  aws_session_token=None, botocore_session=None, aws_profile=None,
                  **args):
    '''
    Return details about all EMR clusters.

    Example:

    .. code-block:: bash

        salt myminion boto3_emr.list_clusters
    '''
    args.update({'ClusterStates': RUNNING}) if 'ClusterStates' not in args else None
    return _list_resource(res_type='clusters', info_node='Clusters', conn=conn, region=region,
                          key=key, keyid=keyid, profile=profile,
                          aws_session_token=aws_session_token, botocore_session=botocore_session,
                          aws_profile=aws_profile, **args)


def list_instance_fleets(name=None, conn=None, region=None, key=None, keyid=None, profile=None,
                         aws_session_token=None, botocore_session=None, aws_profile=None,
                         ClusterStates=RUNNING, **args):
    '''
    Return details about all Instance Fleets associated with a given cluster

    Example:

    .. code-block:: bash

        salt myminion boto3_emr.list_clusters
    '''
    name_param = 'ClusterId'
    if name_param in args:
        name = args[name_param]
    else:
        args[name_param] = name
    if name:
        clids = get_cluster_ids(name=name, conn=conn, region=region, key=key, keyid=keyid,
                                profile=profile, aws_session_token=aws_session_token,
                                botocore_session=botocore_session, aws_profile=aws_profile,
                                ClusterStates=ClusterStates)
        if not clids:
            msg = 'No resource found with Name {0}'.format(name)
            log.error(msg)
            return None
        if len(clids) > 1:
            msg = 'Multiple resources found with Name {0}: {1}'.format(name, clids)
            log.error(msg)
            return None
        args.update({name_param: clids[0]})
    return _list_resource(name=name, name_param=name_param, res_type='instance_fleets',
                          info_node='InstanceFleets', conn=conn, region=region, key=key,
                          keyid=keyid, profile=profile, aws_session_token=aws_session_token,
                          botocore_session=botocore_session, aws_profile=aws_profile, **args)


def list_instance_groups(name=None, conn=None, region=None, key=None, keyid=None, profile=None,
                         aws_session_token=None, botocore_session=None, aws_profile=None,
                         ClusterStates=RUNNING, **args):
    '''
    Return details about all Instance Groups associated with a given cluster

    Example:

    .. code-block:: bash

        salt myminion boto3_emr.list_clusters
    '''
    name_param = 'ClusterId'
    if name_param in args:
        name = args[name_param]
    else:
        args[name_param] = name
    if name:
        clids = get_cluster_ids(name=name, conn=conn, region=region, key=key, keyid=keyid,
                                profile=profile, aws_session_token=aws_session_token,
                                botocore_session=botocore_session, aws_profile=aws_profile,
                                ClusterStates=ClusterStates)
        if not clids:
            msg = 'No resource found with Name {0}'.format(name)
            log.error(msg)
            return None
        if len(clids) > 1:
            msg = 'Multiple resources found with Name {0}: {1}'.format(name, clids)
            log.error(msg)
            return None
        args.update({name_param: clids[0]})
    return _list_resource(name=name, name_param=name_param, res_type='instance_groups',
                          info_node='InstanceGroups', conn=conn, region=region, key=key,
                          keyid=keyid, profile=profile, aws_session_token=aws_session_token,
                          botocore_session=botocore_session, aws_profile=aws_profile, **args)


def list_instances(name=None, conn=None, region=None, key=None, keyid=None, profile=None,
                   aws_session_token=None, botocore_session=None, aws_profile=None,
                   ClusterStates=RUNNING, **args):
    '''
    Return details about all Instances associated with a given cluster

    Example:

    .. code-block:: bash

        salt myminion boto3_emr.list_clusters
    '''
    name_param = 'ClusterId'
    if name_param in args:
        name = args[name_param]
    else:
        args[name_param] = name
    if name:
        clids = get_cluster_ids(name=name, conn=conn, region=region, key=key, keyid=keyid,
                                profile=profile, aws_session_token=aws_session_token,
                                botocore_session=botocore_session, aws_profile=aws_profile,
                                ClusterStates=ClusterStates)
        if not clids:
            msg = 'No resource found with Name {0}'.format(name)
            log.error(msg)
            return None
        if len(clids) > 1:
            msg = 'Multiple resources found with Name {0}: {1}'.format(name, clids)
            log.error(msg)
            return None
        args.update({name_param: clids[0]})
    return _list_resource(name=name, name_param=name_param, res_type='instances', info_node='Instances',
                          conn=conn, region=region, key=key, keyid=keyid, profile=profile,
                          aws_session_token=aws_session_token, botocore_session=botocore_session,
                          aws_profile=aws_profile, **args)


def list_security_configurations(conn=None, region=None, key=None, keyid=None, profile=None,
                                 aws_session_token=None, botocore_session=None, aws_profile=None,
                                 **args):
    '''
    Return details about all defined security_configurations.

    Example:

    .. code-block:: bash

        salt myminion boto3_emr.list_clusters
    '''
    return _list_resource(res_type='security_configurations', info_node='SecurityConfigurations',
                          conn=conn, region=region, key=key, keyid=keyid, profile=profile,
                          aws_session_token=aws_session_token, botocore_session=botocore_session,
                          aws_profile=aws_profile, **args)


def list_steps(name=None, conn=None, region=None, key=None, keyid=None, profile=None,
               aws_session_token=None, botocore_session=None, aws_profile=None,
               ClusterStates=RUNNING, **args):
    '''
    Provides a list of steps for the cluster in reverse order unless you specify stepIds with the request.

    Example:

    .. code-block:: bash

        salt myminion boto3_emr.list_clusters
    '''
    name_param = 'ClusterId'
    if name_param in args:
        name = args[name_param]
    else:
        args[name_param] = name
    if name:
        clids = get_cluster_ids(name=name, conn=conn, region=region, key=key, keyid=keyid,
                                profile=profile, aws_session_token=aws_session_token,
                                botocore_session=botocore_session, aws_profile=aws_profile,
                                ClusterStates=ClusterStates)
        if not clids:
            msg = 'No resource found with Name {0}'.format(name)
            log.error(msg)
            return None
        if len(clids) > 1:
            msg = 'Multiple resources found with Name {0}: {1}'.format(name, clids)
            log.error(msg)
            return None
        args.update({name_param: clids[0]})
    return _list_resource(name=name, name_param=name_param, res_type='steps', info_node='Steps',
                          conn=conn, region=region, key=key, keyid=keyid, profile=profile,
                          aws_session_token=aws_session_token, botocore_session=botocore_session,
                          aws_profile=aws_profile, **args)


def describe_cluster(name=None, conn=None, region=None, key=None, keyid=None, profile=None,
                     aws_session_token=None, botocore_session=None, aws_profile=None,
                     ClusterStates=RUNNING, **args):
    '''
    Return details about a given cluster.

    Example:

    .. code-block:: bash

        salt myminion boto3_enr.describe_cluster my_emr_cluster
    '''
    name_param = 'ClusterId'
    if name_param in args:
        name = args[name_param]
    else:
        args[name_param] = name
    if name:
        clids = get_cluster_ids(name=name, conn=conn, region=region, key=key, keyid=keyid,
                                profile=profile, aws_session_token=aws_session_token,
                                botocore_session=botocore_session, aws_profile=aws_profile,
                                ClusterStates=ClusterStates)
        if not clids:
            msg = 'No resource found with Name {0}'.format(name)
            log.error(msg)
            return None
        if len(clids) > 1:
            msg = 'Multiple resources found with Name {0}: {1}'.format(name, clids)
            log.error(msg)
            return None
        args.update({name_param: clids[0]})
    return _describe_resource(name=name, name_param=name_param, res_type='cluster',
                              info_node='Cluster', conn=conn, region=region,
                              key=key, keyid=keyid, profile=profile,
                              aws_session_token=aws_session_token,
                              botocore_session=botocore_session, aws_profile=aws_profile, **args)


def terminate_job_flows(name=None, wait=0, region=None, key=None, keyid=None, profile=None,
                        aws_session_token=None, botocore_session=None, aws_profile=None,
                        **args):
    '''
    Delete one or more job flows.

    Example:

    .. code-block:: bash

        salt myminion boto3_emr.terminate_job_flows my_emr_cluster
    '''
    try:
        wait = int(wait)
    except:
        raise SaltInvocationError("Bad value ('{0}') passed for 'wait' param - must be an "
                                  "int or boolean.".format(wait))
    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile,
                     aws_session_token=aws_session_token, botocore_session=botocore_session,
                     aws_profile=aws_profile, test_func='list_clusters')
    jfids = args.get('JobFlowIds')
    if 'JobFlowIds' not in args:
        if name:
            args['JobFlowIds'] = get_cluster_ids(name=name, conn=conn)
        else:
            raise SaltInvocationError('Either `JobFlowIds` or `name` required.')
    args = {k: v for k, v in args.items() if not k.startswith('_')}
    retries = 30
    while True:
        try:
            conn.terminate_job_flows(**args)
            break
        except botocore.exceptions.ClientError as e:
            err = __utils__['boto3.get_error'](e)
            if err['code'] not in RETRY_ON:
                log.error('Error terminating job flow(s) {0}: {1}'.format(jfids or name, e))
                return False
            if retries:
                log.debug('Transient error ({0}) from API, will retry in 5 seconds'.format(err['code']))
                retries -= 1
                time.sleep(5)
                continue
            log.error('Too many API retries while terminating job flow(s) {0}.'.format(jfids or name))
            return False
    JobFlowIds = args['JobFlowIds']
    if not wait:
        return [describe_cluster(ClusterId=c, conn=conn, ClusterStates=[]) for c in JobFlowIds]
    log.info('Waiting up to {0} seconds for job flow(s) {1} to be terminated.'.format(wait,
              jfids or name))
    orig_wait = wait
    ret = []
    while wait > 0:
        if not JobFlowIds:  # All done, one way or another.
            return ret
        for jfid in [j for j in JobFlowIds]:  # Dupe so we don't mutate while inside loop
            r = describe_cluster(ClusterId=jfid, conn=conn, ClusterStates=[])
            state = r.get('Status', {}).get('State')
            if state in (None, 'TERMINATED'):
                ret += [r]
                JobFlowIds.remove(jfid)
            elif state in ('TERMINATED_WITH_ERRORS',):
                reason = r.get('Status', {}).get('StateChangeReason', {}).get('Message')
                log.warning('Job flow `{0}` terminated with errors:  {1}'.format(jfid, reason))
                ret += [r]
                JobFlowIds.remove(jfid)
            else:
                sleep = wait if wait % 60 == wait else 60
                log.info('Sleeping {0} seconds for Job flow(s) `{1}` to be terminated.  '
                         'Current state: {2}'.format(sleep, JobFlowIds, state))
                time.sleep(sleep)
                wait -= sleep
                continue
    # Also return deets on any remaining unfinished terms so the user can see their status...
    log.error('Some Job flow(s) not terminated after {0} seconds: {1}.'.format(orig_wait, JobFlowIds))
    ret += [describe_cluster(ClusterId=c, conn=conn, ClusterStates=[]) for c in JobFlowIds]
    return ret


def delete_clusters(*args, **kwargs):
    return terminate_job_flows(*args, **kwargs)


def _get_subnet_id(name, region=None, key=None, keyid=None, profile=None,
                   aws_session_token=None, botocore_session=None, aws_profile=None):
    conn = __utils__['boto3.get_connection']('ec2', region=region, key=key, keyid=keyid,
                                             profile=profile, aws_session_token=aws_session_token,
                                             botocore_session=botocore_session,
                                             aws_profile=aws_profile)
    retries = 30
    while True:
        try:
            ret = conn.describe_subnets(Filters=[{'Name': 'tag:Name', 'Values': [name]}])
            break
        except botocore.exceptions.ClientError as e:
            err = __utils__['boto3.get_error'](e)
            if err['code'] not in RETRY_ON:
                msg = 'Error resolving Subnet Name tag {0} to an ID: {1}'.format(name, e)
                log.error(msg)
                raise CommandExecutionError(msg)
            if retries:
                log.debug('Transient error ({0}) from API, will retry in 5 seconds'.format(err['code']))
                retries -= 1
                time.sleep(5)
                continue
            msg = 'Too many API retries while resolving Subnet Name {0} to an ID.'.format(name)
            log.error(msg)
            raise CommandExecutionError(msg)
    if not isinstance(ret, dict):
        msg = 'Error resolving Subnet Name tag `{0}` to an ID'.format(name)
        log.error(msg)
        raise CommandExecutionError(msg)
    subnets = ret.get('Subnets', [])
    if len(subnets) > 1:
        msg = 'Given Subnet Name tag `{0}` resolved to multiple IDs: {1}'.format(name, subnets)
        log.error(msg)
        raise CommandExecutionError(msg)
    elif len(subnets) < 1:
        msg = 'Subnet Name tag `{0}` did not resolve to an ID'.format(name)
        log.error(msg)
        raise CommandExecutionError(msg)
    return subnets[0]['SubnetId']


def _get_sg_id(name, region=None, key=None, keyid=None, profile=None,
               aws_session_token=None, botocore_session=None, aws_profile=None):
    conn = __utils__['boto3.get_connection']('ec2', region=region, key=key, keyid=keyid,
                                             profile=profile, aws_session_token=aws_session_token,
                                             botocore_session=botocore_session,
                                             aws_profile=aws_profile)
    retries = 30
    while True:
        try:
            ret = conn.describe_security_groups(Filters=[{'Name': 'group-name', 'Values': [name]}])
            break
        except botocore.exceptions.ClientError as e:
            err = __utils__['boto3.get_error'](e)
            if err['code'] not in RETRY_ON:
                msg = 'Error resolving Security Group Name {0} to an ID: {1}'.format(name, e)
                log.error(msg)
                raise CommandExecutionError(msg)
            if retries:
                log.debug('Transient error ({0}) from API, will retry in 5 seconds'.format(err['code']))
                retries -= 1
                time.sleep(5)
                continue
            msg = 'Too many API retries while resolving Security Group Name {0} to an ID.'.format(name)
            log.error(msg)
            raise CommandExecutionError(msg)
    if not isinstance(ret, dict):
        msg = 'Error resolving Security Group Name `{0}` to an ID'.format(name)
        log.error(msg)
        raise CommandExecutionError(msg)
    subnets = ret.get('SecurityGroups', [])
    if len(subnets) > 1:
        msg = 'Given Security Group Name `{0}` resolved to multiple IDs: {1}'.format(name, subnets)
        log.error(msg)
        raise CommandExecutionError(msg)
    elif len(subnets) < 1:
        msg = 'Security Group Name `{0}` did not resolve to an ID'.format(name)
        log.error(msg)
        raise CommandExecutionError(msg)
    return subnets[0]['GroupId']
