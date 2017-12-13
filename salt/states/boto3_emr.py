# -*- coding: utf-8 -*-
'''
Manage EMR with boto3
=====================

.. versionadded:: Nitrogen

Create, destroy and update EMR job flows / clusters. Be aware that this interacts
with Amazon's services, and so may incur charges.

This module uses boto3 behind the scenes - as a result it inherits any limitations
it boto3's implementation of the AWS API.  It is also designed to as directly as
possible leverage boto3's parameter naming and semantics.  This allows one to use
http://boto3.readthedocs.io/en/latest/reference/services/emr.html as an excellent
source for details too involved to reiterate here.

Note:  This module is designed to be transparent ("intentionally ignorant" is the
phrase I used to describe it to my boss) to new AWS / boto options - since all
AWS API params are passed directly through both the state and executions modules,
any new args to existing functions which become available after this documentation
is written should work immediately.

Brand new API calls, of course, would still require new functions to be added :)

This module accepts explicit elasticache credentials but can also utilize IAM
roles assigned to the instance through Instance Profiles. Dynamic credentials are
then automatically obtained from AWS API and no further configuration is necessary.
More information is available
`here <http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html>`_.

If IAM roles are not used you need to specify them either in a pillar file or
in the minion's config file:

.. code-block:: yaml

    elasticache.keyid: GKTADJGHEIQSXMKKRBJ08H
    elasticache.key: askdjghsdfjkghWupUjasdflkdfklgjsdfjajkghs

It's also possible to specify ``key``, ``keyid`` and ``region`` via a profile, either
passed in as a dict, or as a string to pull from pillars or minion config:

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

XXX FIXME
.. code-block:: yaml

    Ensure my_job_flow exists:
      boto3_emr.run_job_flow:
        - name: my_job_flow
        - XXX
        - region: us-east-1
        - keyid: GKTADJGHEIQSXMKKRBJ08H
        - key: askdjghsdfjkghWupUjasdflkdfklgjsdfjajkghs

    # Using an AWS profile from ~/.aws/credentials
    Ensure my_job_flow exists:
      boto3_emr.cluster_present:
        - name: my_job_flow
        - XXX
        - region: us-east-1
        - aws_profile: myAWSprofile
'''

# Import Python Libs
from __future__ import absolute_import
import logging
from salt.exceptions import CommandExecutionError

log = logging.getLogger(__name__)
# AWS AWI states we consider "running" for our purposes...
RUNNING = ['STARTING', 'BOOTSTRAPPING', 'RUNNING', 'WAITING']


def __virtual__():
    '''
    Only load if boto3_emr is available.
    '''
    if 'boto3_emr.list_clusters' in __salt__:
        return 'boto3_emr'
    else:
        return False


def job_flow_present(name, wait=1800, region=None, key=None, keyid=None, profile=None,
                     aws_session_token=None, botocore_session=None, aws_profile=None,
                     **args):
    '''
    Ensure a given Job Flow / Cluster exists.

    NOTE:  This state cannot currently MODIFY existing Job Flows / Clusters - it will create
    the specified configuration if the cluster does not yet exist, but if one with the given
    name is found to be running, it will be assumed to be in the correct state and no attempt
    to validate or update its configuration will be made.  Hopefully this lack will be fixed
    REAL SOON NOW™.

    name
        Name of the state definition.  Will be used as the Name parameter for the Job Flow if
        one is not otherwise specified in the state call.

    wait
        Integer describing how long, in seconds, to wait for confirmation from AWS that the
        resource is in the desired state.  Zero meaning to return success or failure immediately
        of course.  Note that waiting for the cluster to become available is generally the
        better course, as failure to do so will often lead to subsequent failures when managing
        dependent resources.

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

    region
        AWS region to connect to.

    key
        AWS API secret key to be used.

    keyid
        AWS API access key to be used.

    profile
        A dict with region, key and keyid, or a pillar key (string) that contains a dict with
        region, key and keyid.

    aws_session_token
        The session token to use.  This is typically only needed when using temporary credentials.  
        If you don't know what this is, you likely don't need it, but it is supported for those
        unusual cases where it might be of use.

    botocore_session
        A session token which the underlying botocore library can use if passed in.  Rarely needs
        to be set by hand, but it is supported for very unusual circumstances.

    aws_profile
        Name of an AWS profile (generally stored in ~/.aws/credentials or ~/.aws/config) providing
        the bits needed for boto3 to authenticate and talk to AWS.

    XXX example FIXME
    '''
    ret = {'name': name, 'result': True, 'comment': '', 'changes': {}}
    args['Name'] = name if 'Name' not in args else args['Name']
    args = {k: v for k, v in args.items() if not k.startswith('_')}
    d_args = {'ClusterId': args['ClusterId']} if 'ClusterId' in args else {}
    current = __salt__['boto3_emr.describe_cluster'](name=args['Name'], region=region, key=key,
            keyid=keyid, profile=profile, aws_session_token=aws_session_token,
            botocore_session=botocore_session, aws_profile=aws_profile, **d_args)
    if current:
        ret['comment'] = 'Job Flow / Cluster `{0}` ({1}) exists.'.format(args['Name'], current['Id'])
        return ret

    if __opts__['test']:
        ret['result'] = None
        ret['comment'] = 'Job Flow / Cluster `{0}` would be created.'.format(args['Name'])
        return ret

    new = __salt__['boto3_emr.create_cluster'](name, wait=wait, region=region, key=key,
            keyid=keyid, profile=profile, aws_session_token=aws_session_token,
            botocore_session=botocore_session, aws_profile=aws_profile, **args)
    if new:
        ret['comment'] = 'Job Flow / Cluster {0} was created.'.format(args['Name'])
        ret['changes']['old'] = current
        ret['changes']['new'] = new
    else:
        ret['result'] = False
        ret['comment'] = 'Failed to create {0} Job Flow / Cluster.'.format(args['Name'])

    return ret


def job_flow_absent(name, wait=600, region=None, key=None, keyid=None, profile=None,
                    aws_session_token=None, botocore_session=None, aws_profile=None,
                    **args):
    '''
    Ensure a given cache cluster is deleted.

    name
        Name of the state definition.  If JobFlowIds is not provided, this value will be used.
        As a convenience, `name` may be either a JobFlowId or the Name field of the target Job
        Flow / Cluster.  In the latter case, it will be resolved to the corresponding JobFlowId
        before use.  

    wait
        Integer describing how long, in seconds, to wait for confirmation from AWS that the
        resource is in the desired state.  Zero meaning to return success or failure immediately
        of course.  Note that waiting for the cluster to become available is generally the
        better course, as failure to do so will often lead to subsequent failures when managing
        dependent resources.

    JobFlowIds
        A [list] containing a single JobFlowId (also known as a ClusterId throughout the AWS
        documentation) of the Job Flow / Cluster to be terminated.  If not provided, the value of
        `name` will be used.  Note that while the underlying function call supports multiple
        JobFlowIds in this parameter, ensuring state on a non-singleton is convoluted and unlikely
        to have sane semantics, so this state function limits itself to a single resource per
        state definition.

    region
        Region to connect to.

    key
        Secret key to be used.

    keyid
        Access key to be used.

    profile
        A dict with region, key and keyid, or a pillar key (string)
        that contains a dict with region, key and keyid.

    aws_session_token
        The session token to use.  This is typically only needed when using temporary credentials.  
        If you don't know what this is, you likely don't need it, but it is supported for those
        unusual cases where it might be of use.

    botocore_session
        A session token which the underlying botocore library can use if passed in.  Rarely needs
        to be set by hand, but it is supported for very unusual circumstances.

    aws_profile
        Name of an AWS profile (generally stored in ~/.aws/credentials or ~/.aws/config) providing
        the bits needed for boto3 to authenticate and talk to AWS.

    XXX example FIXME
    '''
    ret = {'name': name, 'result': True, 'comment': '', 'changes': {}}
    args = {k: v for k, v in args.items() if not k.startswith('_')}
    d_args = {'ClusterId': args['ClusterId']} if 'ClusterId' in args else {}
    Name = name if 'Name' not in args else args['Name']
    current = __salt__['boto3_emr.describe_cluster'](name=Name, region=region, key=key,
            keyid=keyid, profile=profile, aws_session_token=aws_session_token,
            botocore_session=botocore_session, aws_profile=aws_profile, **d_args)
    if not current:
        ret['comment'] = 'Job flow / cluster `{0}` absent.'.format(name)
        return ret
    jfid = current['Id']
    if current.get('Status', {}).get('State') in ('TERMINATED', 'TERMINATED_WITH_ERRORS'):
        ret['comment'] = 'Job flow / cluster `{0}` ({1}) already terminated'.format(name, jfid)
        return ret

    if __opts__['test']:
        ret['comment'] = 'Job Flow / Cluster `{0}` ({0}) would be terminated.'.format(name, jfid)
        ret['result'] = None
        return ret

    new = __salt__['boto3_emr.delete_clusters'](name=name, wait=wait, region=region, key=key,
            keyid=keyid, profile=profile, aws_session_token=aws_session_token,
            botocore_session=botocore_session, aws_profile=aws_profile, **args)
    if new:
        ret['comment'] = 'Job Flow / Cluster `{0}` ({0}) terminated.'.format(name, jfid)
        ret['changes']['old'] = current
        ret['changes']['new'] = new
    else:
        ret['result'] = False
        msg = 'Failed to terminate Job Flow / Cluster `{0}` ({1}).'.format(name, jfid)
        ret['comment'] = msg
        log.error(msg)
    return ret

