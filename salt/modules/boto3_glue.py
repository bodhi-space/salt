# -*- coding: utf-8 -*-
'''
Execution module for Amazon Glue using boto3
============================================

.. versionadded:: 2017.7.0

:configuration: This module accepts explicit Glue credentials but can
    also utilize IAM roles assigned to the instance through Instance Profiles.
    Dynamic credentials are then automatically obtained from AWS API and no
    further configuration is necessary. More Information available at:

    .. code-block:: text

        http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html

    If IAM roles are not used you need to specify them either in a pillar or
    in the minion's config file:

    .. code-block:: yaml

        glue.keyid: GKTADJGHEIQSXMKKRBJ08H
        glue.key: askdjghsdfjkghWupUjasdflkdfklgjsdfjajkghs

    A region may also be specified in the configuration:

    .. code-block:: yaml

        glue.region: us-east-1

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

# Import Python libs
from __future__ import absolute_import, print_function, unicode_literals
import logging

# Import Salt libs
import salt.utils.boto3
import salt.utils.compat
import salt.utils.versions
from salt.exceptions import SaltInvocationError, CommandExecutionError  #pylint: disable=unused-import
log = logging.getLogger(__name__)   # pylint: disable=W1699

# Import third party libs
try:
    import boto3  #pylint: disable=unused-import
    from botocore.exceptions import ClientError, ParamValidationError
    logging.getLogger('boto3').setLevel(logging.CRITICAL)
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False


def __virtual__():
    '''
    Only load if boto libraries exist and if boto libraries are greater than a given version.
    '''
    return salt.utils.versions.check_boto_reqs()


def __init__(opts):
    salt.utils.compat.pack_dunder(__name__)
    if HAS_BOTO3:
        __utils__['boto3.assign_funcs'](__name__, 'glue', exactly_one_funcname=None)


def _update_extend(dest, src):
    '''
    Very simplistic "deep merge with update" - designed for merging the JSON info returned from
    AWS API calls, and thus only handles JSON supported data types.
    '''
    ret = copy.deepcopy(dest)
    for k, v in src.items():
        if isinstance(v, list):
            ret[k] = copy.deepcopy(v) if k not in ret else (ret[k] + v)
        elif isinstance(v, dict):
            ret[k] = copy.deepcopy(v) if k not in ret else _update_extend(ret[k], v)
        else:  # Hope you're a string, int, or other scalar type, buddy...
            ret[k] = copy.copy(v)
    return ret


def _call_with_retries(func, kwargs, wait=10, retries=30):
    try:
        wait = int(wait)
    except:
        raise SaltInvocationError('Bad value `%s` passed for `wait` - must be an int.' % wait)
    while retries:
        try:
            return func(**kwargs)
        except ClientError as err:
            if err.response.get('Error', {}).get('Code') == 'Throttling':
                log.debug('Throttled by AWS API.  Sleeping %s seconds for retry...' % wait)
                time.sleep(wait)
                continue
            raise err
        except ParamValidationError as err:
            raise SaltInvocationError(err)
    raise CommandExecutionError('Failed %s retries over %s seconds' % (retries, retries * wait))


def _do_generic_thing(region=None, key=None, keyid=None, profile=None, fname='', kwargs=None):
    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
    func = getattr(conn, fname, None)
    kwargs = {key: val for key, val in kwargs.items() if not key.startswith('_')} if kwargs else {}
    if func is None:
        raise SaltInvocationError('Function `%s()` not available.' % fname)
    try:
        res = _call_with_retries(func=func, kwargs=kwargs)
        res.pop('ResponseMetadata', None)
        return res
    except (ClientError, CommandExecutionError) as err:
        log.error('Failed calling `%s()`:  %s' % (fname, err))
        return None


def get_query_results(region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Returns the results of a single query execution specified by QueryExecutionId.  This request
    does NOT execute the query - it merely returns results from a previously executed query.

    QueryExecutionId
        The unique ID of the query execution.

    '''
    ret = {}
    page = ''
    fname = sys._getframe().f_code.co_name
    kwargs.update({'MaxResults': 50})
    while page is not None:
        res = _do_generic_thing(region=region, key=key, keyid=keyid, profile=profile,
                                fname=fname, kwargs=kwargs)
        if res is None:  # Error condition of some kind
            return res
        ret = _update_extend(ret, res['ResultSet'])
        page = res.get('NextToken', None)
        kwargs.update({'NextToken': page})
    return ret


def batch_create_partition(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def batch_delete_connection(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def batch_delete_partition(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def batch_delete_table(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def batch_delete_table_version(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def batch_get_partition(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def batch_stop_job_run(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def can_paginate(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def create_classifier(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def create_connection(region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Creates a connection definition in the Data Catalog.

    CatalogId
        The ID of the Data Catalog in which to create the connection. If none is supplied, the
        bound AWS account ID is used by default.
    ConnectionInput [REQUIRED]
        A ConnectionInput object (as a dict), defining the connection to create.
            Name [REQUIRED]
                The name of the connection.
            Description
                Description of the connection.
            ConnectionType
                The type of the connection.  Currently, only JDBC is supported.
            MatchCriteria
                A list of criteria (strings) that can be used in selecting this connection.
            ConnectionProperties [REQUIRED]
                A dict of key-value pairs used as parameters for this connection.
            PhysicalConnectionRequirements
                A map (as a dict) of physical connection requirements, such as VPC and
                SecurityGroup, needed for making this connection successfully.
                SubnetId
                    The subnet ID used by the connection.
                SecurityGroupIdList
                    A list of Security Group IDs used by the connection.
                AvailabilityZone
                    The connection's availability zone.  This field is deprecated and unused.


    '''
    return _do_generic_thing(region=region, key=key, keyid=keyid, profile=profile,
                             fname=sys._getframe().f_code.co_name, kwargs=kwargs)


def create_crawler(region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Creates a new crawler with specified targets, role, configuration, and optional schedule.
    At least one crawl target must be specified, in either the S3Targets or the JdbcTargets field.

    Name [REQUIRED]
        Name of the new crawler.
    Role [REQUIRED]
        The IAM role (or ARN of an IAM role) used by the new crawler to access customer resources.
    DatabaseName [REQUIRED]
        The AWS Glue database where results are written, such as:
        `arn:aws:daylight:us-east-1::database/sometable/*`
    Description
        A description of the new crawler.
    Targets [REQUIRED]
        A dict of collection of targets to crawl.
        S3Targets
            A list of dicts specifying Amazon S3 targets.
            Path
                The path to the Amazon S3 target.
            Exclusions
                A list of glob patterns used to exclude from the crawl.
        JdbcTargets
            A list of dicts specifying JDBC targets.
            ConnectionName
                The name of the connection to use to connect to the JDBC target.
            Path
                The path of the JDBC target.
            Exclusions
                A list of glob patterns used to exclude from the crawl.
    Schedule
        A cron expression used to specify the schedule.  For example, to run something every
        day at 12:15 UTC, you would specify:  `cron(15 12 * * ? *)`
    Classifiers
        A list of custom classifiers that the user has registered.  By default, all AWS
        classifiers are included in a crawl, but these custom classifiers always override the
        default classifiers for a given classification.
    TablePrefix
        The table prefix used for catalog tables that are created.
    SchemaChangePolicy
        A dict specifying the policy for the crawler's update and deletion behavior.
        UpdateBehavior
            The update behavior when the crawler finds a changed schema.
        DeleteBehavior
            The deletion behavior when the crawler finds a deleted object.
    Configuration
        Crawler configuration information.  This versioned JSON string allows users to specify
        aspects of a Crawler's behavior.  You can use this field to force partitions to inherit
        metadata such as classification, input format, output format, serde information, and
        schema from their parent table, rather than detect this information separately for each
        partition.  For example, use the following JSON string to specify that behavior:

        .. code-block:: json
            '{ "Version": 1.0,
               "CrawlerOutput": { "Partitions": { "AddOrUpdateBehavior": "InheritFromTable" } } }'

    '''
    return _do_generic_thing(region=region, key=key, keyid=keyid, profile=profile,
                             fname=sys._getframe().f_code.co_name, kwargs=kwargs)



def create_database(region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Creates a new database in a Data Catalog.

    CatalogId
        The ID of the Data Catalog in which to create the database.  If none is supplied, the
        bound AWS account ID is used by default.
    DatabaseInput [REQUIRED]
        A DatabaseInput object (as a dict) defining the metadata database to create in the catalog.
        Name [REQUIRED]
            Name of the database.  For Hive compatibility, this is folded to lowercase when it
            is stored.
        Description
            Description of the database
        LocationUri
            The location of the database (for example, an HDFS path).
        Parameters
            A dict of key-value pairs that define parameters and properties of the database.

    '''
    return _do_generic_thing(region=region, key=key, keyid=keyid, profile=profile,
                             fname=sys._getframe().f_code.co_name, kwargs=kwargs)


def create_dev_endpoint(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def create_job(region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Creates a new job definition.

    Name [REQUIRED]
        The name you assign to this job definition. It must be unique in your account.
    Description
        Description of the job being defined.
    LogUri
        This field is reserved for future use.
    Role [REQUIRED]
        The name or ARN of the IAM role associated with this job.
    ExecutionProperty
        An ExecutionProperty dict, specifying the properties for this job.
        MaxConcurrentRuns
            The maximum number of concurrent runs allowed for the job.  The default is 1.  An
            error is returned when this threshold is reached.  The maximum value you can specify
            is controlled by a service limit.
    Command [REQUIRED]
        The JobCommand (dict) that executes this job.
        Name
            The name of the job command: this must be `glueetl`.
        ScriptLocation
            Specifies the S3 path to a script that executes a job (required).
    DefaultArguments
        A dict specifying default arguments for this job.  You can specify arguments here that
        your own job-execution script consumes, as well as arguments that AWS Glue itself consumes.
    Connections
        A dict specifying the connections used for this job.
        Connections
            A list of connections used by the job.
    MaxRetries
        The maximum number of times to retry this job if it fails.
    AllocatedCapacity
        The number of AWS Glue data processing units (DPUs) to allocate to this Job.  Min 2,
        default 10, max 100 DPUs may be allocated.  A DPU is a relative measure of processing
        power that consists of 4 vCPUs of compute capacity and 16 GB of memory. For more
        information, see the AWS Glue pricing page.
    Timeout
        The job timeout in minutes.  The default is 2880 minutes (48 hours).

    '''
    return _do_generic_thing(region=region, key=key, keyid=keyid, profile=profile,
                             fname=sys._getframe().f_code.co_name, kwargs=kwargs)


def create_partition(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def create_script(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def create_table(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def create_trigger(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def create_user_defined_function(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def delete_classifier(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def delete_connection(region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Deletes a connection from the Data Catalog.

    CatalogId
        The ID of the Data Catalog in which the connection resides.  If none is supplied, the
        bound AWS account ID is used by default.
    ConnectionName [REQUIRED]
        The name of the connection to delete.
    '''
    return _do_generic_thing(region=region, key=key, keyid=keyid, profile=profile,
                             fname=sys._getframe().f_code.co_name, kwargs=kwargs)


def delete_crawler(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def delete_database(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def delete_dev_endpoint(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def delete_job(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def delete_partition(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def delete_table(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def delete_table_version(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def delete_trigger(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def delete_user_defined_function(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def generate_presigned_url(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def get_catalog_import_status(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def get_classifier(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def get_classifiers(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def get_connection(region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Retrieves a connection definition from the Data Catalog.

    CatalogId
        The ID of the Data Catalog in which the connection resides.  If none is supplied, the
        bound AWS account ID is used by default.
    Name [REQUIRED]
        The name of the connection definition to retrieve.

    '''
    return _do_generic_thing(region=region, key=key, keyid=keyid, profile=profile,
                             fname=sys._getframe().f_code.co_name, kwargs=kwargs)


def get_connections(region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Retrieves a list of connection definitions from the Data Catalog.

    CatalogId
        The ID of the Data Catalog in which the connections reside.  If none is supplied, the
        bound AWS account ID is used by default.
    Filter
        (A dict of) filters that control which connections will be returned.
        MatchCriteria (list) --

            A criteria string that must match the criteria recorded in the connection definition for that connection definition to be returned.
                (string) --
            ConnectionType (string) --

            The type of connections to return. Currently, only JDBC is supported; SFTP is not supported.
    NextToken (string) -- A continuation token, if this is a continuation call.
    MaxResults (integer) -- The maximum number of connections to return in one response.

    '''


def get_crawler(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def get_crawler_metrics(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def get_crawlers(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def get_database(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def get_databases(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def get_dataflow_graph(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def get_dev_endpoint(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def get_dev_endpoints(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def get_job(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def get_job_run(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def get_job_runs(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def get_jobs(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def get_mapping(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def get_paginator(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def get_partition(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def get_partitions(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def get_plan(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def get_table(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def get_table_version(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def get_table_versions(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def get_tables(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def get_trigger(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def get_triggers(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def get_user_defined_function(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def get_user_defined_functions(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def get_waiter(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def import_catalog_to_glue(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def reset_job_bookmark(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def start_crawler(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def start_crawler_schedule(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def start_job_run(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def start_trigger(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def stop_crawler(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def stop_crawler_schedule(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def stop_trigger(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def update_classifier(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def update_connection(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def update_crawler(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def update_crawler_schedule(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def update_database(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def update_dev_endpoint(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def update_job(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def update_partition(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def update_table(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def update_trigger(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass


def update_user_defined_function(region=None, key=None, keyid=None, profile=None, **kwargs):
    pass
