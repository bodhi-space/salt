# -*- coding: utf-8 -*-
'''
Boto 3 based module for Amazon EC2

.. versionadded:: Boron

:configuration: This module accepts explicit EC2 credentials but can also
    utilize IAM roles assigned to the instance trough Instance Profiles.
    Dynamic credentials are then automatically obtained from AWS API and no
    further configuration is necessary. More Information available at:

    .. code-block:: text

        http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html

    If IAM roles are not used you need to specify credentials either in a pillar or
    in the minion's config file:

    .. code-block:: yaml

        ec2.keyid: GKTADJGHEIQSXMKKRBJ08H
        ec2.key: askdjghsdfjkghWupUjasdflkdfklgjsdfjajkghs

    A region may also be specified in the configuration:

    .. code-block:: yaml

        ec2.region: us-east-1

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
from __future__ import absolute_import
import logging
import json
from distutils.version import LooseVersion as _LooseVersion  # pylint: disable=import-error,no-name-in-module
import time
from ast import literal_eval
import socket

# Import Salt libs
import salt.utils.boto3
import salt.utils.compat
import salt.utils
import salt.utils.dictupdate as dictupdate
from salt.exceptions import SaltInvocationError
from salt.ext.six import string_types

log = logging.getLogger(__name__)

# Import third party libs

# pylint: disable=import-error
try:
    #pylint: disable=unused-import
    import boto3
    #pylint: enable=unused-import
    from botocore.exceptions import ClientError
    logging.getLogger('boto3').setLevel(logging.CRITICAL)
    HAS_BOTO = True
except ImportError:
    HAS_BOTO = False
# pylint: enable=import-error


def __virtual__():
    '''
    Only load if boto3 libraries exist and their versions are are greater than
    a given version.
    '''
    required_boto3_version = '1.2.1'

    if not HAS_BOTO:
        return (False, 'The boto_ec2 module could not be loaded: '
                'boto3 libraries not found')
    elif _LooseVersion(boto3.__version__) < _LooseVersion(required_boto3_version):
        return (False, 'The boto_ec2 module could not be loaded: '
                'boto3 version {0} or later must be installed.'.format(required_boto3_version))
    else:
        return True


def __init__(opts):
    salt.utils.compat.pack_dunder(__name__)
    if HAS_BOTO:
        __utils__['boto3.assign_funcs'](__name__, 'ec2')


def _aws_tags_to_dict(aws_tags):
    if not isinstance(aws_tags, list):
        raise SaltInvocationError('Param aws_tags must be a list of dicts')
    for e in aws_tags:
        if not isinstance(e, dict):
            raise SaltInvocationError('Param aws_tags must be a list of dicts')

    return {e['Key']: e['Value'] for e in aws_tags}


def _dict_to_aws_tags(dictionary):
    if not isinstance(d, dict):
        raise SaltInvocationError('Param dictionary must be a dict')

    return [{'Key': k, 'Value': v} for k, v in dictionary]


def _build_filters(accept, env, key='Name', tags=None):
    filts = []
    filts += _opts_to_filter(accept, env, key)
    filts += _tags_to_filter(tags)
    return filts


### I've seen upwards of 4 minutes at times before e.g. route tables become
#   active and taggable...  Allow 10 minutes for such pathological cases.
def _create_tags(resources, tags, tries=120, sleep=5,
           region=None, key=None, keyid=None, profile=None):
    # Be flexible.  AWS likes [{k:v, ...}, ...], while common sense prefers
    # simple {k:v, ...} when practical.  Given the nature of setting tags (as
    # opposed to filtering with them) it's always OK and safe to use the latter
    # here, but we cover both bases for safety.
    if isinstance(tags, list):
        tagset = tags
    elif isinstance(tags, dict):
        tagset = [ {'Key': '{0}'.format(k),
                    'Value': '{0}'.format(tags[k])} for k in tags ]
    else:
        raise SaltInvocationError('Invalid tags param passed, must be '
                                  'either a {dict} or [list].')
    conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
    for attempt in range(tries):
        try:
            conn.create_tags(Resources=resources, Tags=tagset)
            return {'success': True}
        except ClientError as e:
            if attempt >= tries:
                raise
            log.info('Waiting up to {0} seconds for object {1} to become '
                    'taggable...'.format(sleep*tries, ', '.join(resources)))
            attempt += 1
            time.sleep(sleep)


def _page_collector(func, args, restype, tok='NextToken'):
    collect = []
    while args[tok] is not None:
        if not args[tok]:
            del args[tok]
        r = func(**args)
        collect += r.get(restype)
        args[tok] = r.get(tok, None)
    return collect


def _opts_to_filter(accept, env, key='Name'):
    # Convert **args into Filters=[{k:v}, ...] format based on an accept list
    filts = []
    for a in accept:
        if isinstance(a, dict):
            k, o = a.popitem()
            v = env.get(o)
            # Filter vals must be strings, and True / False are lowercase :-/
            if v in [True, False]:
                v = '{0}'.format(v).lower()
            filts += [{key: '{0}'.format(k), 'Values': v if isinstance(v, list)
                       else ['{0}'.format(v)]}] if v is not None else []
        else:
            v = env.get(a.replace('-', '_').replace('.', '_'), None)
            if v in [True, False]:
                v = '{0}'.format(v).lower()
            filts += [{key: '{0}'.format(a), 'Values': v if isinstance(v, list)
                       else ['{0}'.format(v)]}] if v is not None else []
    return filts


def _tags_to_filter(tags):
    # Convert [{k,v}, ...] and/or {k,v, ...} style tags to Filters=[{k:v}, ...]
    filts = []
    if tags is not None:
        if isinstance(tags, dict):
            filts += [{'Name': 'tag:{0}'.format(k),
                       'Values': ['{0}'.format(tags[k])]} for k in tags]
        elif isinstance(tags, list):
            filts += tags
        else:
            raise SaltInvocationError('Invalid tags param passed, must be '
                                      'either a {dict} or [list].')
    return filts


def accept_vpc_peering_connection(vpc_peering_connection_id, region=None,
                                  key=None, keyid=None, profile=None):
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.accept_vpc_peering_connection(VpcPeeringConnectionId=vpc_peering_connection_id)
        return r.get('VpcPeeringConnection')
    except ClientError as e:
        return {'error': salt.utils.boto3.get_error(e)}


def allocate_address(domain='vpc', region=None, key=None, keyid=None, profile=None):
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.allocate_address(Domain=domain)
        junk = r.pop('ResponseMetadata') if 'ResponseMetadata' in r else ''
        addr = r.get('PublicIp')
        if addr:
            log.info('The newly allocated pubilc IP is {0}'.format(addr))
        return r
    except ClientError as e:
        return {'error': salt.utils.boto3.get_error(e)}


def allocate_hosts(instance_type, quantity, availability_zone,
                   autoplacement='on', client_token=None, region=None, key=None,
                   keyid=None, profile=None):
    args = {'InstanceType': instance_type, 'Quantity': quantity,
            'AvailabilityZone': availability_zone,
            'AutoPlacement': autoplacement}
    # Grrr.  Dedicated hosts don't allow tags, so no Name tag to default to.
    # Idempotency -> out the window...
    args.update({'ClientToken': client_token}) if client_token else None
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.allocate_hosts(**args)
        return r.get('HostIds')
    except ClientError as e:
        return {'error': salt.utils.boto3.get_error(e)}


def assign_private_ip_addresses(network_interface_id, private_ip_addresses=None,
                                secondary_private_ip_address_count=None,
                                allow_reassignment=False, region=None, key=None,
                                keyid=None, profile=None):
    args = {'NetworkInterfactId': network_interfact_id}
    args.update({'PrivateIpAddresses':
                 private_ip_addresses}) if private_ip_addresses else None
    args.update({'SecondaryPrivateIpAddressCount':
                 secondary_private_ip_address_count}) if secondary_private_ip_address_count else None
    args.update({'AllowReassignment':
                 allow_reassignment}) if allow_reassignment else None
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.assign_private_ip_addresses(**args)
        return {'success': True}
    except ClientError as e:
        return {'success': False, 'error': salt.utils.boto3.get_error(e)}


def associate_address(instance_id=None, public_ip=None, allocation_id=None,
                      network_interface_id=None, private_ip_address=None,
                      allow_reassociation=False, region=None, key=None,
                      keyid=None, profile=None):
    args = {'AllowReassociation': allow_reassociation}
    args.update({'InstanceId': instance_id}) if instance_id else None
    args.update({'PublicIp': public_ip}) if public_ip else None
    args.update({'AllocationId': allocation_id}) if allocation_id else None
    args.update({'NetworkInterfaceId': network_interface_id}) if network_interface_id else None
    args.update({'PrivateIpAddress': private_ip_address}) if private_ip_address else None
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.assign_private_ip_addresses(**args)
        junk = r.pop('ResponseMetadata') if 'ResponseMetadata' in r else ''
        return r
    except ClientError as e:
        return {'error': salt.utils.boto3.get_error(e)}


def associate_dhcp_options(dhcp_options_id=None, dhcp_options_name=None,
                           vpc_id=None, vpc_name=None,
                           region=None, key=None, keyid=None, profile=None):
    if not _exactly_one((dhcp_options_id, dhcp_options_name)):
        raise SaltInvocationError('Exactly one of dhcp_options_id OR '
                                  'dhcp_options_name must be provided.')
    if not _exactly_one((vpc_id, vpc_name)):
        raise SaltInvocationError('Exactly one of vpc_id OR vpc_name '
                                  'must be provided.')
    if dhcp_options_name is not None:
        r = get_resource_id(name=dhcp_options_name,
                              resource_type='dhcp-options', region=region,
                              key=key, keyid=keyid, profile=profile)
        if 'error' in r:
            return {'success': False, 'error': r['error']}
        if 'id' not in r:
            return {'success': False, 'error': "Couldn't resolve "
                                                  "'dhcp_options_name' to ID"}
        dhcp_options_id = r['id']
    if vpc_name is not None:
        r = get_resource_id(name=vpc_name, resource_type='vpc',
                              region=region, key=key, keyid=keyid,
                              profile=profile)
        if 'error' in r:
            return {'success': False, 'error': r['error']}
        if 'id' not in r:
            return {'success': False, 'error': "Couldn't resolve "
                                                  "'vpc_name' to ID"}
        vpc_id = r['id']

    args = {'DhcpOptionsId': dhcp_options_id, 'VpcId': vpc_id}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        conn.associate_dhcp_options(**args)
        return {'success': True}
    except ClientError as e:
        return {'success': False, 'error': salt.utils.boto3.get_error(e)}


def associate_route_table(subnet_id, route_table_id, region=None, key=None,
                          keyid=None, profile=None):
    args = {'SubnetId': subnet_id, 'RouteTableId': route_table_id}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.associate_route_table(**args)
        junk = r.pop('ResponseMetadata') if 'ResponseMetadata' in r else ''
        return r
    except ClientError as e:
        return {'error': salt.utils.boto3.get_error(e)}


def attach_classic_link_vpc(instance_id, vpc_id, groups, region=None, key=None,
                            keyid=None, profile=None):
    args = {'InstanceId': instance_id, 'VpcId': vpc_id, 'Groups': groups}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.attach_classic_link_vpc(**args)
        junk = r.pop('ResponseMetadata') if 'ResponseMetadata' in r else ''
        return r
    except ClientError as e:
        return {'error': salt.utils.boto3.get_error(e)}


def attach_internet_gateway(internet_gateway_id, vpc_id, region=None, key=None,
                            keyid=None, profile=None):
    args = {'InternetGatewayId': internet_gateway_id, 'VpcId': vpc_id}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.attach_internet_gateway(**args)
        return {'success': True}
    except ClientError as e:
        return {'success': False, 'error': salt.utils.boto3.get_error(e)}


def attach_network_interface(network_interface_id, instance_id, device_index,
                             region=None, key=None, keyid=None, profile=None):
    args = {'NetworkInterfaceId': network_interface_id,
            'InstanceId': instance_id, 'DeviceIndex': device_index}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.attach_network_interface(**args)
        junk = r.pop('ResponseMetadata') if 'ResponseMetadata' in r else ''
        return r
    except ClientError as e:
        return {'error': salt.utils.boto3.get_error(e)}


def attach_volume(volume_id, instance_id, device, region=None, key=None,
                  keyid=None, profile=None):
    args = {'VolumeId': volume_id, 'InstanceId': instance_id, 'Device': device}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.attach_volume(**args)
        junk = r.pop('ResponseMetadata') if 'ResponseMetadata' in r else ''
        return r
    except ClientError as e:
        return {'error': salt.utils.boto3.get_error(e)}


def attach_vpn_gateway(vpn_gateway_id, vpc_id, region=None, key=None,
                       keyid=None, profile=None):
    args = {'VpnGatewayId': vpn_network_id, 'VpcId': vpc_id}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.attach_vpn_gateway(**args)
        junk = r.pop('ResponseMetadata') if 'ResponseMetadata' in r else ''
        return r
    except ClientError as e:
        return {'error': salt.utils.boto3.get_error(e)}


def authorize_security_group_egress(group_id, ip_permissions, region=None,
                                    key=None, keyid=None, profile=None):
    args = { 'GroupId': group_id, 'IpPermissions': ip_permissions}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        conn.authorize_security_group_egress(**args)
        return {'success': True}
    except ClientError as e:
        return {'success': False, 'error': salt.utils.boto3.get_error(e)}


def authorize_security_group_ingress(group_name=None, group_id=None,
                                     source_security_group_name=None,
                                     source_security_group_owner_id=None,
                                     ip_protocol=None, from_port=None,
                                     to_port=None, cidr_ip=None,
                                     ip_permissions=None, region=None, key=None,
                                     keyid=None, profile=None):
    pass


def bundle_instance():
    pass


def can_paginate():
    pass


def cancel_bundle_task():
    pass


def cancel_conversion_task():
    pass


def cancel_export_task():
    pass


def cancel_import_task():
    pass


def cancel_reserved_instances_listing():
    pass


def cancel_spot_fleet_requests():
    pass


def cancel_spot_instance_requests():
    pass


def compare_tagsets(has, wants):
    if isinstance(has, list):
        has = _aws_tags_to_dict(has)
    if isinstance(wants, list):
        wants = _aws_tags_to_dict(wants)
    r = {}
    has_keys = set(has.keys())
    wants_keys = set(wants.keys())
    intersect_keys = has_keys.intersection(wants_keys)
    r['added'] = list(wants_keys - has_keys)
    r['removed'] = list(has_keys - wants_keys)
    r['modified'] = {o: (has[o], wants[o])
                     for o in intersect_keys if has[o] != wants[o]}
    return r


def ensure_tags(obj_id, tags, region=None, key=None, keyid=None, profile=None):

    r = describe_tags(resource_id=obj_id, region=region, key=key, keyid=keyid,
                      profile=profile)
    if 'error' in r:
        return r

    current = _aws_tags_to_dict(r)

    ret = {'success': True, 'changes': {'old': {}, 'new': {}}}
    r = compare_tagsets(current, tags)
    if r['added'] or r['modified']:
        t = create_tags(obj_id, tags, region=region, key=key, keyid=keyid,
                        profile=profile)
        if 'error' in t:
            return {'success': False, 'error': t['error']}
    if r['removed']:
        t = delete_tags(obj_id, r['removed'])
        if 'error' in t:
            return {'success': False, 'error': t['error']}

    if r['added'] or r['modified'] or r['removed']:
        ret['changes']['old']['Tags'] = current
        ret['changes']['new']['Tags'] = tags

    return ret

def confirm_product_instance():
    pass


def copy_image():
    pass


def copy_snapshot():
    pass


def create_customer_gateway():
    pass


def create_dhcp_options(name, domain_name=None, domain_name_servers=None,
            ntp_servers=None, netbios_name_servers=None, netbios_node_type=None,
            tags=None, config_doc=None, region=None, key=None, keyid=None,
            profile=None):

    tagset = {'Name': name}
    tagset.update(tags) if tags else None

    if config_doc is not None:
        dhcp_config = config_doc
    else:
        opts = ['domain-name', 'domain-name-servers', 'ntp-servers',
                'netbios-name-servers', 'netbios-node-type']
        dhcp_config = _opts_to_filter(opts, locals(), 'Key')

    args = {'DhcpConfigurations': dhcp_config}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.create_dhcp_options(**args)
        obj_id = r.get('DhcpOptions', {}).get('DhcpOptionsId')
        if obj_id:
            _create_tags(resources=[obj_id], tags=tagset, region=region,
                         key=key, keyid=keyid, profile=profile)
            _cache_id(name, obj_id, region=region, key=key, keyid=keyid,
                      profile=profile)
            log.info('The newly created DHCP Option Set ID is '
                     '{0}'.format(obj_id))
            return {'success': True, 'id': obj_id, 'details': r['DhcpOptions']}
        else:
            log.warning('DHCP option set not created')
            return {'success': False, 'error': 'Failed to create'}
    except ClientError as e:
        return {'success': False, 'error': salt.utils.boto3.get_error(e)}

    # The boto 2 module carries on to associate the new options with a vpc, but
    # I can't see any way to make that idempotent.  My guess for the reason is
    # the difficulties in getting back out the created dhcp_options_id for use
    # in binding to the VPC later on.  We don't have that issue so...


def create_flow_logs():
    pass


def create_image():
    pass


def create_instance_export_task():
    pass


def create_internet_gateway(name=None, vpc_id=None, vpc_name=None, tags=None,
                            region=None, key=None, keyid=None, profile=None):
    '''
    Create an Internet Gateway, optionally attaching it to an existing VPC.

    Returns the internet gateway id if the internet gateway was created and
    returns False if the internet gateways was not created.

    .. versionadded:: 2015.8.0

    CLI Example:

    .. code-block:: bash

        salt myminion boto_vpc.create_internet_gateway \\
                internet_gateway_name=myigw vpc_name=myvpc

    '''

    if vpc_id and vpc_name:
        raise SaltInvocationError('At most one of vpc_id OR vpc_name '
                                  'may be provided.')
    if vpc_name is not None:
        r = get_resource_id(name=vpc_name, resource_type='vpc',
                              region=region, key=key, keyid=keyid,
                              profile=profile)
        if 'error' in r:
            return {'success': False, 'error': r['error']}
        if 'id' not in r:
            return {'success': False, 'error': "Couldn't resolve "
                                                  "'vpc_name' to ID"}
        vpc_id = r['id']

    tagset = {'Name': name}
    tagset.update(tags) if tags else None

    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.create_internet_gateway()
        igw = r['InternetGateway']
        obj_id = igw['InternetGatewayId']
        log.debug('Internet Gateay created: {0}'.format(obj_id))
        if vpc_id:
            args = {'InternetGatewayId': obj_id, 'VpcId': vpc_id}
            conn.attach_internet_gateway(**args)
            log.debug('Attached internet gateway {0} to VPC {1}'.format(
                      obj_id, vpc_name or vpc_id))
        _create_tags(resources=[obj_id], tags=tagset, region=region,
                     key=key, keyid=keyid, profile=profile)
        _cache_id(name, obj_id, region=region, key=key, keyid=keyid,
                  profile=profile)
        log.info('The newly created Internet Gateway ID is {0}'.format(obj_id))
        return {'success': True, 'id': obj_id,
                'details': igw}
    except ClientError as e:
        return {'success': False, 'error': salt.utils.boto3.get_error(e)}


def create_key_pair(name):
        pass


def create_nat_gateway(name, subnet_id, allocation_id, client_token=None,
                       region=None, key=None, keyid=None, profile=None):
    # client_token is limited to 64 ascii chars
    client_token = client_token[:64] if client_token else name[:64]
    args = {'SubnetId': subnet_id,
            'AllocationId': allocation_id,
            'ClientToken': client_token}

    already_there = True
    state = 'pending'
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        while state == 'pending':
            r = conn.create_nat_gateway(**args)
            if 'FailureMessage' in r:  # This is often set long before state is set to failed.
                raise ClientError(r['FailureMessage'])
            state = r.get('NatGateway', {}).get('State')
            if state in ['deleted', 'deleting']:
                raise ClientError('NAT Gateway was deleted')
            obj_id = r['NatGateway']['NatGatewayId']
            if state == 'available':
                _cache_id(name, obj_id, region=region, key=key, keyid=keyid,
                        profile=profile)
                log.info('The newly created NAT Gateway ID is '
                        '{0}'.format(obj_id))
                return {'success': True, 'id': obj_id,
                        'details': r['NatGateway'], 'already_there': already_there}
            else:
                already_there = False
                log.info('Waiting for NAT Gateway {0} to come '
                         'up...'.format(obj_id))
                time.sleep(5)

    except ClientError as e:
        return {'success': False, 'error': salt.utils.boto3.get_error(e)}


def create_network_acl(name, vpc_id, tags=None, region=None, key=None,
                       keyid=None, profile=None):
    tagset = {'Name': name}
    tagset.update(tags) if tags else None
    args = {'VpcId': vpc_id}

    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.create_network_acl(**args)
        acl = r['NetworkAcl']
        obj_id = acl['NetworkAclId']
        if obj_id:
            _create_tags(resources=[obj_id], tags=tagset, region=region,
                         key=key, keyid=keyid, profile=profile)
            _cache_id(name, obj_id, region=region, key=key, keyid=keyid,
                      profile=profile)
            log.info('The newly created Network ACL ID is {0}'.format(obj_id))
            return {'success': True, 'id': obj_id, 'details': acl}
        else:
            log.warning('Network ACL not created')
            return {'success': False, 'error': salt.utils.boto3.get_error(e)}
    except ClientError as e:
        return {'success': False, 'error': salt.utils.boto3.get_error(e)}


def create_network_acl_entry(network_acl_id=None, network_acl_name=None,
                             rule_number=None, protocol=None, rule_action=None,
                             egress=None, cidr_block=None, icmp_type_code=None,
                             port_range=None, region=None, key=None, keyid=None,
                             profile=None):
    if not _exactly_one((network_acl_id, network_acl_name)):
        raise SaltInvocationError('Exactly one of network_acl_id OR '
                                  'network_acl_name must be provided.')
    for a in ['rule_number', 'protocol', 'rule_action', 'egress', 'cidr_block']:
        if a not in locals() or locals()[a] == None:
            raise SaltInvocationError("'{0}' is a required parameter".format(a))
    if network_acl_name is not None:
        r = get_resource_id(name=network_acl_name,
                              resource_type='network-acl', region=region,
                              key=key, keyid=keyid, profile=profile)
        if 'error' in r:
            return {'success': False, 'error': r['error']}
        if 'id' not in r:
            return {'success': False,
                    'error': "Couldn't resolve network_acl_name {0} "
                              "to ID".format(network_acl_name)}
        network_acl_id = r['id']

    # Boto does NOT resolve protocol names correctly, despite the documentation.
    if isinstance(protocol, str) and not protocol.isdigit():
        try:
            protocol = socket.getprotobyname(protocol)
        except socket.error as e:
            log.warning("Couldn't resolve protocol '{0}' to a number, passing "
                        "as-is - this may produce a later failure.".format(
                        protocol))
    protocol = '{0}'.format(protocol)

    args = {'NetworkAclId': network_acl_id, 'RuleNumber': rule_number,
            'Protocol': protocol, 'RuleAction': rule_action,
            'Egress': egress, 'CidrBlock': cidr_block}
    args.update({'IcmpTypeCode': icmp_type_code}) if icmp_type_code else None
    args.update({'PortRange': port_range}) if port_range else None
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        conn.create_network_acl_entry(**args)
        return {'success': True}
    except ClientError as e:
        return {'success': False, 'error': salt.utils.boto3.get_error(e)}


def create_network_interface():
    pass


def create_placement_group():
    pass


def create_reserved_instances_listing():
    pass


def create_route(route_table_id, destination_cidr_block, gateway_id=None,
                 instance_id=None, network_interface_id=None,
                 vpc_peering_connection_id=None, nat_gateway_id=None,
                 region=None, key=None, keyid=None, profile=None):
    args = {'RouteTableId': route_table_id,
            'DestinationCidrBlock': destination_cidr_block}
    args.update({'GatewayId': gateway_id}) if gateway_id else None
    args.update({'InstanceId': instance_id}) if instance_id else None
    args.update({'NetworkInterfaceId':
                 network_interface_id}) if network_interface_id else None
    args.update({'VpcPeeringConnectionId':
                 vpc_peering_connection_id}) if vpc_peering_connection_id else None
    args.update({'NatGatewayId': nat_gateway_id}) if nat_gateway_id else None

    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.create_route(**args)
        junk = r.pop('ResponseMetadata') if 'ResponseMetadata' in r else ''
        return {'success': True, 'details': r}
    except ClientError as e:
        return {'success': False, 'error': salt.utils.boto3.get_error(e)}


def create_route_table(name, vpc_id, tags=None, region=None, key=None, keyid=None,
                       profile=None):
    tagset = {'Name': name}
    tagset.update(tags) if tags else None
    args = {'VpcId': vpc_id}

    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.create_route_table(**args)
        junk = r.pop('ResponseMetadata') if 'ResponseMetadata' in r else ''
        obj_id = r.get('RouteTable', {}).get('RouteTableId')
        if obj_id:
            _create_tags(resources=[obj_id], tags=tagset, region=region,
                         key=key, keyid=keyid, profile=profile)
            _cache_id(name, obj_id, region=region, key=key, keyid=keyid,
                      profile=profile)
            log.info('The newly created Route Table ID is {0}'.format(obj_id))
            return {'success': True, 'id': obj_id, 'details': r['RouteTable']}
        else:
            log.warning('Route table not created')
            return {'success': False, 'error': salt.utils.boto3.get_error(e)}
    except ClientError as e:
        return {'success': False, 'error': salt.utils.boto3.get_error(e)}


def create_security_group():
    pass


def create_snapshot():
    pass


def create_spot_datafeed_subscription():
    pass


def create_subnet(name, vpc_id=None, vpc_name=None, cidr_block=None,
                  availability_zone=None, tags=None, region=None, key=None,
                  keyid=None, profile=None):

    tagset = {'Name': name}
    tagset.update(tags) if tags else None

    if not _exactly_one((vpc_id, vpc_name)):
        raise SaltInvocationError('Exactly one of vpc_id OR vpc_name '
                                  'must be provided.')
    if vpc_name is not None:
        r = get_resource_id(name=vpc_name, resource_type='vpc',
                              region=region, key=key, keyid=keyid,
                              profile=profile)
        if 'error' in r:
            return {'success': False, 'error': r['error']}
        if 'id' not in r:
            return {'success': False, 'error': "Couldn't resolve "
                                                  "'vpc_name' to ID"}
        vpc_id = r['id']
    if cidr_block is None:
        raise SaltInvocationError("'cidr_block' is a required parameter.")

    args = {'VpcId': vpc_id, 'CidrBlock': cidr_block}
    args.update({'AvailabilityZone': availability_zone}) if availability_zone else None

    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.create_subnet(**args)
        obj_id = r.get('Subnet', {}).get('SubnetId')
        if obj_id:
            _create_tags(resources=[obj_id], tags=tagset, region=region,
                         key=key, keyid=keyid, profile=profile)
            _cache_id(name, obj_id, region=region, key=key, keyid=keyid,
                      profile=profile)
            log.info('The newly created Subnet ID is {0}'.format(obj_id))
            return {'success': True, 'id': obj_id, 'details': r.get('Subnet')}
        else:
            log.warning('Subnet was not created')
            return {'success': False, 'error': 'The Subnet was not created'}
    except ClientError as e:
        return {'success': False, 'error': salt.utils.boto3.get_error(e)}


def create_tags(resources, tags, region=None, key=None, keyid=None, profile=None):
    res = resources if isinstance(resources, list) else [resources]
    try:
        _create_tags(resources=res, tags=tags, region=region, key=key,
                     keyid=keyid, profile=profile)
        return {'success': True, 'tags': tags}
    except ClientError as e:
        return {'success': False, 'error': salt.utils.boto3.get_error(e)}


def create_volume():
    pass


def create_vpc(name, cidr_block, instance_tenancy=None, tags=None,
           region=None, key=None, keyid=None, profile=None):
    '''
    Given a valid CIDR block, create a VPC.

    An optional instance_tenancy argument can be provided. If provided, the
    valid values are 'default' or 'dedicated'

    Returns {success: true} if the VPC was created and returns
    {success: False} if the VPC was not created.

    CLI Example:

    .. code-block:: bash

        salt myminion boto_vpc.create '10.0.0.0/24'

    '''

    tagset = {'Name': name}
    tagset.update(tags) if tags else None

    args = {'CidrBlock': cidr_block}
    if instance_tenancy is not None:
        if instance_tenancy not in ('default', 'dedicated'):
            raise SaltInvocationError("Value for 'instance_tenancy' must be "
                                      "either 'default' or 'dedicated'")
        args['InstanceTenancy'] = instance_tenancy

    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.create_vpc(**args)
        vpc = r['Vpc']
        obj_id = vpc['VpcId']
        if obj_id:
            _create_tags(resources=[obj_id], tags=tagset, region=region,
                         key=key, keyid=keyid, profile=profile)
            _cache_id(name, obj_id, region=region, key=key, keyid=keyid,
                      profile=profile)
            log.info('The newly created VPC ID is {0}'.format(obj_id))
            return {'success': True, 'id': obj_id, 'details': vpc}
        else:
            log.warning('VPC was not created')
            return {'success': False, 'error': 'The VPC was not created'}
    except ClientError as e:
        return {'success': False, 'error': salt.utils.boto3.get_error(e)}


def create_vpc_endpoint():
    pass


def create_vpc_peering_connection():
    pass


def create_vpn_connection():
    pass


def create_vpn_connection_route():
    pass


def create_vpn_gateway():
    pass


def delete_customer_gateway():
    pass


def delete_dhcp_options():
    pass


def delete_flow_logs():
    pass


def delete_internet_gateway(name=None, internet_gateway_id=None,
                            detach=False, region=None,
                            key=None, keyid=None, profile=None):
    '''
    Delete an internet gateway (by name or id).

    Returns True if the internet gateway was deleted and otherwise False.

    .. versionadded:: 2015.8.0

    CLI Examples:

    .. code-block:: bash

        salt myminion boto_vpc.delete_internet_gateway internet_gateway_id=igw-1a2b3c
        salt myminion boto_vpc.delete_internet_gateway internet_gateway_name=myigw

    '''

    if not _exactly_one((name, internet_gateway_id)):
        raise SaltInvocationError(
                'Exactly one of name OR internet_gateway_id '
                'must be provided.')

    if name is not None:
        r = get_resource_id(name=name, resource_type='internet-gateway',
                              region=region, key=key, keyid=keyid,
                              profile=profile)
        if 'error' in r:
            return {'success': False, 'error': r['error']}
        if 'id' not in r:
            return {'success': True, 'comment':
                    "Internet Gateway {0} already absent".format(name)}
        internet_gateway_id = r['id']

    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        args = {'InternetGatewayIds': [internet_gateway_id]}
        res = conn.describe_internet_gateways(**args)
        igws = res.get('InternetGateways', [])
        if len(igws) < 1:
            return {'success': True, 'comment':
                    "Internet Gateway {0} already absent".format(name)}
        obj = igws[0]
        if detach:
            for a in obj.get('Attachments', []):
                r = detach_internet_gateway(
                        internet_gateway_id, a['VpcId'], region=region, key=key,
                        keyid=keyid, profile=profile)
                if 'error' in r:
                    return {'success': False, 'error': r['error']}
        args = {'InternetGatewayId': internet_gateway_id}
        conn.delete_internet_gateway(**args)
        return {'success': True}
    except ClientError as e:
        return {'success': False, 'error': salt.utils.boto3.get_error(e)}


def delete_key_pair():
    pass


def delete_nat_gateway(nat_gateway_id, region=None, key=None, keyid=None,
                       profile=None):
    args = {'NatGatewayId': nat_gateway_id}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.delete_nat_gateway(**args)
        if not r.get('NatGatewayId', '') == nat_gateway_id:
            return {'success': False, 'error': 'NAT Gateway not deleted.'}
    except ClientError as e:
        return {'success': False, 'error': salt.utils.boto3.get_error(e)}

    try:
        while True:
            r = describe_nat_gateways(nat_gateway_id=nat_gateway_id,
                                        region=region, key=key, keyid=keyid,
                                        profile=profile)
            if 'error' in r:
                return {'success': False, 'error': r['error']}
            if len(r) < 1:
                return {'success': True}
            if r[0]['State'] == 'deleted':
                return {'success': True}
            log.info('Waiting for NAT Gateway {0} to stop...'.format(
                    nat_gateway_id))
            time.sleep(5)

    except ClientError as e:
        return {'success': False, 'error': salt.utils.boto3.get_error(e)}


def delete_network_acl(network_acl_id=None, network_acl_name=None, region=None,
                       key=None, keyid=None, profile=None):
    if not _exactly_one((network_acl_id, network_acl_name)):
        raise SaltInvocationError('Exactly one of network_acl_id OR '
                                  'network_acl_name must be provided.')
    if network_acl_name is not None:
        r = get_resource_id(name=network_acl_name,
                            resource_type='network-acl', region=region,
                            key=key, keyid=keyid, profile=profile)
        if 'error' in r:
            return {'success': False, 'error': r['error']}
        if 'id' not in r:
            return {'success': True}
        network_acl_id = r['id']

    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        args = {'NetworkAclIds': [network_acl_id]}
        r = conn.describe_network_acls(**args)
        acls = r.get('NetworkAcls', [])
        if len(acls) < 1:
            return {'success': True, 'comment':
                    'Network ACL {0} already absent'.format(network_acl_name or
                    network_acl_id)}
        acl = acls[0]
        if acl.get('IsDefault'):
            return {'success': True, 'comment':
                    "Can't remove default Network ACL, ignoring delete request"}
        args = {'NetworkAclId': network_acl_id}
        r = conn.delete_network_acl(**args)
        return {'success': True}
    except ClientError as e:
        return {'success': False, 'error': salt.utils.boto3.get_error(e)}


def delete_network_acl_entry(network_acl_id=None, network_acl_name=None,
                             rule_number=None, egress=None, region=None,
                             key=None, keyid=None, profile=None):
    if not _exactly_one((network_acl_id, network_acl_name)):
        raise SaltInvocationError('Exactly one of network_acl_id OR '
                                  'network_acl_name must be provided.')
    for a in ['rule_number', 'egress']:
        if a not in locals() or locals()[a] == None:
            raise SaltInvocationError("'{0}' is a required parameter".format(a))
    if network_acl_name is not None:
        r = get_resource_id(name=network_acl_name,
                              resource_type='network-acl', region=region,
                              key=key, keyid=keyid, profile=profile)
        if 'error' in r:
            return {'success': False, 'error': r['error']}
        if 'id' not in r:
            return {'success': False,
                    'error': "Couldn't resolve network_acl_name {0} "
                              "to ID".format(network_acl_name)}
        network_acl_id = r['id']

    args = {'NetworkAclId': network_acl_id,
            'RuleNumber': rule_number,
            'Egress': egress}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.delete_network_acl_entry(**args)
        return {'success': True}
    except ClientError as e:
        return {'success': False, 'error': salt.utils.boto3.get_error(e)}


def delete_network_interface():
    pass


def delete_placement_group():
    pass


def delete_route(route_table_id=None, route_table_name=None,
                 destination_cidr_block=None, region=None, key=None, keyid=None,
                 profile=None):
    if not _exactly_one((route_table_id, route_table_name)):
        raise SaltInvocationError('Exactly one of route_table_id OR '
                                  'route_table_name must be provided.')
    if not destination_cidr_block:
        raise SaltInvocationError("'destination_cidr_block' is a required "
                                  "parameter.")
    if route_table_name is not None:
        r = get_resource_id(name=route_table_name,
                              resource_type='route-table', region=region,
                              key=key, keyid=keyid, profile=profile)
        if 'error' in r:
            return {'success': False, 'error': r['error']}
        if 'id' not in r:
            return {'success': False,
                    'error': "Couldn't resolve route_table_name {0} "
                              "to ID".format(route_table_name)}
        route_table_id = r['id']

    args = {'RouteTableId': route_table_id,
            'DestinationCidrBlock': destination_cidr_block}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.delete_route(**args)
        return {'success': True}
    except ClientError as e:
        return {'success': False, 'error': salt.utils.boto3.get_error(e)}


def delete_route_table(route_table_id=None, route_table_name=None,
                 region=None, key=None, keyid=None, profile=None):
    if not _exactly_one((route_table_id, route_table_name)):
        raise SaltInvocationError('Exactly one of route_table_id OR '
                                  'route_table_name must be provided.')
    if route_table_name is not None:
        r = get_resource_id(name=route_table_name,
                              resource_type='route-table', region=region,
                              key=key, keyid=keyid, profile=profile)
        if 'error' in r:
            return {'success': False, 'error': r['error']}
        if 'id' not in r:
            return {'success': True}
        route_table_id = r['id']

    args = {'RouteTableId': route_table_id}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.delete_route_table(**args)
    except ClientError as e:
        return {'success': False, 'error': salt.utils.boto3.get_error(e)}

    while True:
        r = describe_route_tables(route_table_id=route_table_id,
                                    region=region, key=key, keyid=keyid,
                                    profile=profile)
        if 'error' in r:
            return {'success': False, 'error': r['error']}
        if len(r) < 1:
            return {'success': True}
        else:
            log.info('Waiting for Route Table {0} to disappear...'.format(
                    route_table_name or route_table_id))

def delete_security_group():
    pass


def delete_snapshot():
    pass


def delete_spot_datafeed_subscription():
    pass


def delete_subnet(subnet_id=None, subnet_name=None,
                  region=None, key=None, keyid=None, profile=None):
    if not _exactly_one((subnet_id, subnet_name)):
        raise SaltInvocationError('Exactly one of subnet_id OR '
                                  'subnet_name must be provided.')
    r = describe_subnets(subnet_id=subnet_id, subnet_name=subnet_name,
                         region=region, key=key, keyid=keyid, profile=profile)
    if 'error' in r:
        return {'success': False, 'error': r['error']}
    if len(r) < 1:
        return {'success': True}
    if len(r) > 1:
        return {'success': False, 'error': 'Found more than one Subnet with '
                                           'Name {0}'.format(subnet_name)}
    subnet_id = r[0]['SubnetId']

    args = {'SubnetId': subnet_id}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.delete_subnet(**args)
    except ClientError as e:
        return {'success': False, 'error': salt.utils.boto3.get_error(e)}

    while True:
        r = describe_subnets(subnet_id=subnet_id, region=region, key=key,
                               keyid=keyid, profile=profile)
        if 'error' in r:
            return {'success': False, 'error': r['error']}
        if len(r) < 1:
            return {'success': True}
        else:
            log.info('Waiting for Subnet {0} to disappear...'.format(
                    subnet_name or subnet_id))
            time.sleep(5)


def delete_tags(resources, tags):
    # We're flexible.  We accept tags as a string (of one key), dicts (of
    # key/val pairs), or lists (of keys).  We also take resources as lists
    # or strings.
    if not isinstance(resources, list):
        resources = [resources]
    if isinstance(tags, dict):
        tags = _dict_to_aws_tags(tags)
    if isinstance(tags, list):
        tags = [{'Key': tag} for tag in tags if not isinstance(tag, dict)]
    else:
        tags = [tags]

    args = {'Resources': resources, 'Tags': tags}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        conn.delete_tags(**args)
    except ClientError as e:
        return {'success': False, 'error': salt.utils.boto3.get_error(e)}


def delete_volume():
    pass


def delete_vpc():
    pass


def delete_vpc_endpoints():
    pass


def delete_vpc_peering_connection():
    pass


def delete_vpn_connection():
    pass


def delete_vpn_connection_route():
    pass


def delete_vpn_gateway():
    pass


def deregister_image():
    pass


def describe_account_attributes(filters=None, region=None, key=None, keyid=None,
                                profile=None):
    opts = ['supported-platforms', 'default-vpc', 'max-instances',
            'vpc-max-security-groups-per-interface', 'max-elastic-ips',
            'vpc-max-elastic-ips']

    if not filters:
        filters = []
    if isinstance(filters, string_types):
        filters = [filters]
    elif not isinstance(filters, list):
        raise SaltInvocationError('Invalid attribute arg passed - must be '
                                  'a "string" or a [list of "strings"].')
    for filt in filters:
        if filt not in opts:
            raise SaltInvocationError('Invalid attribute arg passed - must '
                                      'be one of {0}'.format(opts))
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.describe_account_attributes(AttributeNames=filters)
        # OK, I admit it - the returned data format is too stupid, even for me,
        # and I like to think I'm pretty tolerant.  We'll just clean it up a bit
        two = {e['AttributeName']: [x['AttributeValue']
               for x in e['AttributeValues']] for e in r['AccountAttributes']}
        return two
    except ClientError as e:
        return {'error': salt.utils.boto3.get_error(e)}


def describe_addresses(allocation_id=None, association_id=None, domain=None,
                       instance_id=None, network_interface_id=None,
                       network_interface_owner_id=None, private_ip_address=None,
                       public_ip=None, region=None, key=None, keyid=None,
                       profile=None):
    opts = ['allocation-id', 'association-id', 'domain', 'instance-id',
            'network-interface-id', 'network-interface-owner-id',
            'private-ip-address', 'public-ip']
    filts = _build_filters(opts, locals())
    args = {'Filters': filts} if filts else {}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.describe_addresses(**args)
        return r['Addresses']
    except ClientError as e:
        return {'error': salt.utils.boto3.get_error(e)}


def describe_availability_zones(message=None, region_name=None, state=None,
                                zone_name=None, region=None, key=None,
                                keyid=None, profile=None):
    opts = ['message', 'region-name', 'state', 'zone-name']
    filts = _build_filters(opts, locals())
    args = {'Filters': filts} if filts else {}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.describe_availability_zones(**args)
        return r['AvailabilityZones']
    except ClientError as e:
        return {'error': salt.utils.boto3.get_error(e)}


def describe_bundle_tasks(bundle_id=None, error_code=None, error_message=None,
                          instance_id=None, progress=None, s3_bucket=None,
                          s3_prefix=None, start_time=None, state=None,
                          update_time=None, region=None, key=None, keyid=None,
                          profile=None):
    opts = ['bundle-id', 'error-code', 'error-message', 'instance-id',
            'progress', 's3-bucket', 's3-prefix', 'start-time', 'state',
            'update-time']
    filts = _build_filters(opts, locals())
    args = {'Filters': filts} if filts else {}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.describe_bundle_tasks(**args)
        return r['BundleTasks']
    except ClientError as e:
        return {'error': salt.utils.boto3.get_error(e)}


def describe_classic_link_instances(group_id=None, instance_id=None,
                                    tag_key=None, tag_value=None, vpc_id=None,
                                    tags=None, region=None, key=None,
                                    keyid=None, profile=None):
    opts = ['group-id', 'instance-id', 'tag-key', 'tag-value', 'vpc-id']
    filts = _build_filters(opts, locals(), tags=tags)
    args = {'MaxResults': 1000, 'NextToken': '', 'Filters': filts}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        return _page_collector(conn.describe_classic_link_instances, args,
                               'Instances')
    except ClientError as e:
        return {'error': salt.utils.boto3.get_error(e)}


def describe_conversion_tasks(conversion_task_ids=None, region=None, key=None,
                              keyid=None, profile=None):
    c = conversion_task_ids
    args = {'ConversionTaskIds': c if isinstance(c, list) else [c]} if c else {}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.describe_conversion_tasks(**args)
        return r['ConversionTasks']
    except ClientError as e:
        return {'error': salt.utils.boto3.get_error(e)}


def describe_customer_gateways(bgp_asn=None, customer_gateway_id=None,
                               ip_address=None, state=None, gw_type=None,
                               tag_key=None, tag_value=None, tags=None,
                               region=None, key=None, keyid=None, profile=None):
    opts = ['bgp-asn', 'customer-gateway-id', 'ip-address', 'state',
           {'type':'gw_type'},'tag-key', 'tag-value']
    filts = _build_filters(opts, locals(), tags=tags)
    args = {'Filters': filts} if filts else {}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.describe_customer_gateways(**args)
        return r['CustomerGateways']
    except ClientError as e:
        return {'error': salt.utils.boto3.get_error(e)}


def describe_dhcp_options(dhcp_options_id=None, dhcp_option_key=None,
                          dhcp_option_value=None, tag_key=None, tag_value=None,
                          tags=None, region=None, key=None, keyid=None,
                          profile=None):

    opts = ['dhcp-options-id', {'key':'dhcp_option_key'}, {'value':
            'dhcp_option_value'}, 'tag-key', 'tag-value']
    filts = _build_filters(opts, locals(), tags=tags)
    args = {'Filters': filts} if filts else {}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.describe_dhcp_options(**args)
        return r['DhcpOptions']
    except ClientError as e:
        return {'error': salt.utils.boto3.get_error(e)}


def describe_export_tasks(export_task_ids=None, region=None, key=None,
                          keyid=None, profile=None):
    e = export_task_ids
    args = {'ExportTaskIds': e if isinstance(e, list) else [e]} if e else {}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.describe_export_tasks(**args)
        return r['ExportTasks']
    except ClientError as e:
        return {'error': salt.utils.boto3.get_error(e)}


def describe_flow_logs(deliver_log_status=None, flow_log_id=None,
                       log_group_name=None, resource_id=None, traffic_type=None,
                       region=None, key=None, keyid=None, profile=None):
    opts = ['deliver-log-status', 'flow-log-id', 'log-group-name', 'resource-id',
            'traffic-type']
    filts = _build_filters(opts, locals())
    args = {'MaxResults': 1000, 'NextToken': '', 'Filter': filts}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        return _page_collector(conn.describe_flow_logs, args, 'FlowLogs')
    except ClientError as e:
        return {'error': salt.utils.boto3.get_error(e)}


def describe_hosts(host_ids=None, instance_type=None, auto_placement=None,
                   host_reservation_id=None, client_token=None, state=None,
                   availability_zone=None, region=None, key=None, keyid=None,
                   profile=None):
    opts = ['instance-type', 'auto-placement', 'host-reservation-id',
            'client-token', 'state', 'availability-zone']
    filts = _build_filters(opts, locals())
    args = {'NextToken': '', 'Filter': filts}
    args.update({'HostIds': host_ids if isinstance(host_ids, list)
                                     else [host_ids]} if host_ids else {})
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        return _page_collector(conn.describe_hosts, args, 'Hosts')
    except ClientError as e:
        return {'error': salt.utils.boto3.get_error(e)}


def describe_id_format(resource=None, region=None, key=None, keyid=None,
                       profile=None):
    args = {'Resource': resource} if resource else {}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.describe_id_format(**args)
        return r['Statuses']
    except ClientError as e:
        return {'error': salt.utils.boto3.get_error(e)}


def describe_image_attribute():
    pass


def describe_images():
    pass


def describe_import_image_tasks():
    pass


def describe_import_snapshot_tasks():
    pass


def describe_instance_attribute():
    pass


def describe_instance_status():
    pass


def describe_instances():
    pass


def describe_internet_gateways(attachment_state=None, attachment_vpc_id=None,
                               internet_gateway_id=None,
                               internet_gateway_name=None, tag_key=None,
                               tag_value=None, tags=None, region=None, key=None,
                               keyid=None, profile=None):
    if internet_gateway_name:
        if tags:
            tags.update({'Name': internet_gateway_name})
        else:
            tags = {'Name': internet_gateway_name}

    opts = ['attachment.state', 'attachment.vpc-id', 'internet-gateway-id',
            'tag-key', 'tag-value']
    filts = _build_filters(opts, locals(), tags=tags)
    args = {'Filters': filts} if filts else {}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.describe_internet_gateways(**args)
        return r['InternetGateways']
    except ClientError as e:
        return {'error': salt.utils.boto3.get_error(e)}


def describe_key_pairs(fingerprint=None, key_name=None,
                       region=None, key=None, keyid=None, profile=None):
    opts = ['fingerprint', 'key-name']
    filts = _build_filters(opts, locals())
    args = {'Filters': filts} if filts else {}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.describe_key_pairs(**args)
        return r['KeyPairs']
    except ClientError as e:
        return {'error': salt.utils.boto3.get_error(e)}


def describe_moving_addresses():
    pass


def describe_nat_gateways(nat_gateway_id=None, state=None, subnet_id=None,
                          vpc_id=None, region=None, key=None, keyid=None,
                          profile=None):
    opts = ['nat-gateway-id', 'state', 'subnet-id', 'vpc-id']
    filts = _build_filters(opts, locals())
    args = {'MaxResults': 1000, 'NextToken': '', 'Filter': filts}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        return _page_collector(conn.describe_nat_gateways, args, 'NatGateways')
    except ClientError as e:
        return {'error': salt.utils.boto3.get_error(e)}


def describe_network_acls(association_association_id=None,
                          association_network_acl_id=None,
                          association_subnet_id=None, default=None,
                          entry_cidr=None, entry_egress=None,
                          entry_icmp_code=None, entry_icmp_type=None,
                          entry_port_range_from=None, entry_port_range_to=None,
                          entry_protocol=None, entry_rule_action=None,
                          entry_rule_number=None, network_acl_id=None,
                          tag_key=None, tag_value=None, vpc_id=None, tags=None,
                          region=None, key=None, keyid=None, profile=None):
    opts = ['association.association-id', 'association.network-acl-id',
            'association.subnet-id', 'default', 'entry.cidr', 'entry.egress',
            'entry.icmp.code', 'entry.icmp.type', 'entry.port-range.from',
            'entry.port-range.to', 'entry.protocol', 'entry.rule-action',
            'entry.rule-number', 'network-acl-id', 'tag-key', 'tag-value',
            'vpc-id']
    filts = _build_filters(opts, locals(), tags=tags)
    args = {'Filters': filts} if filts else {}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.describe_network_acls(**args)
        return r['NetworkAcls']
    except ClientError as e:
        return {'error': salt.utils.boto3.get_error(e)}


def describe_network_interface_attribute():
    pass


def describe_network_interfaces():
    pass


def describe_placement_groups():
    pass


def describe_prefix_lists():
    pass


def describe_regions(endpoint=None, region_name=None,
                     region=None, key=None, keyid=None, profile=None):
    opts = ['endpoint', 'region-name']
    filts = _build_filters(opts, locals())
    args = {'Filters': filts} if filts else {}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.describe_regions(**args)
        return r['Regions']
    except ClientError as e:
        return {'error': salt.utils.boto3.get_error(e)}
    pass


def describe_reserved_instances():
    pass


def describe_reserved_instances_listings():
    pass


def describe_reserved_instances_modifications():
    pass


def describe_reserved_instances_offerings():
    pass


def describe_route_tables(association_route_table_association_id=None,
                          association_route_table_id=None,
                          association_subnet_id=None, association_main=None,
                          route_table_id=None, route_destination_cidr_block=None,
                          route_destination_prefix_list_id=None,
                          route_gateway_id=None, route_instance_id=None,
                          route_nat_gateway_id=None, route_origin=None,
                          route_state=None, route_vpc_peering_connection_id=None,
                          tag_key=None, tag_value=None, vpc_id=None, tags=None,
                          region=None, key=None, keyid=None, profile=None):

    opts = ['association.route-table-association-id',
            'association.route-table-id', 'association.subnet-id',
            'association.main', 'route-table-id', 'route.destination-cidr-block',
            'route.destination-prefix-list-id', 'route.gateway-id',
            'route.instance-id', 'route.nat-gateway-id', 'route.origin',
            'route.state', 'route.vpc-peering-connection-id', 'tag-key',
            'tag-value', 'vpc-id']
    filts = _build_filters(opts, locals(), tags=tags)
    args = {'Filters': filts} if filts else {}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.describe_route_tables(**args)
        return r['RouteTables']
    except ClientError as e:
        return {'error': salt.utils.boto3.get_error(e)}


def describe_security_groups():
    pass


def describe_snapshot_attribute():
    pass


def describe_snapshots():
    pass


def describe_spot_datafeed_subscription():
    pass


def describe_spot_fleet_instances():
    pass


def describe_spot_fleet_request_history():
    pass


def describe_spot_fleet_requests():
    pass


def describe_spot_instance_requests():
    pass


def describe_spot_price_history():
    pass


def describe_subnets(availability_zone=None, available_ip_address_count=None,
                     cidr_block=None, default_for_az=None, state=None,
                     subnet_id=None, subnet_name=None, tag_key=None,
                     tag_value=None, vpc_id=None, vpc_name=None, tags=None,
                     region=None, key=None, keyid=None, profile=None):
    if vpc_name and vpc_id:
        raise SaltInvocationError('At most one of vpc_id or vpc_name may be '
                                  'provided.')
    if vpc_name is not None:
        r = get_resource_id(name=vpc_name, resource_type='vpc',
                              region=region, key=key, keyid=keyid,
                              profile=profile)
        if 'error' in r:
            return {'success': False, 'error': r['error']}
        if 'id' not in r:
            return {'success': False, 'error': "Couldn't resolve "
                                                  "'vpc_name' to ID"}
        vpc_id = r['id']

    if subnet_name:
        if tags:
            tags.update({'Name': subnet_name})
        else:
            tags = {'Name': subnet_name}

    opts = ['availability-zone', 'available-ip-address-count', 'cidr-block',
            'default-for-az', 'state', 'subnet-id', 'tag-key', 'tag-value',
            'vpc-id']
    filts = _build_filters(opts, locals(), tags=tags)
    args = {'Filters': filts} if filts else {}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.describe_subnets(**args)
        return r['Subnets']
    except ClientError as e:
        return {'error': salt.utils.boto3.get_error(e)}


def describe_tags(resource_id=None, resource_type=None, tags=None,
                  tag_key=None, tag_value=None, region=None, key=None,
                  keyid=None, profile=None):
    # NOTE:  Tags can be passed around as either {k:v, ...} or [{k:v}, ...]
    # On a single resource, tag keys are unique and thus it's safe (and
    # preferred) to use simple {k:v, ...}.  When describing tags across multiple
    # resources, this is not the case, and thus the more obtuse AWS semantics of
    # [{k:v}, ...] must needs be used.
    opts = ['resource-id', 'resource-type', 'tag-key', 'tag-value']
    filts = _build_filters(opts, locals(), tags=tags)
    args = {'MaxResults': 1000, 'NextToken': '', 'Filters': filts}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        return _page_collector(conn.describe_tags, args, 'Tags')
    except ClientError as e:
        return {'error': salt.utils.boto3.get_error(e)}


def describe_volume_attribute():
    pass


def describe_volume_status():
    pass


def describe_volumes():
    pass


def describe_vpc_attribute():
    pass


def describe_vpc_classic_link():
    pass


def describe_vpc_classic_link_dns_support():
    pass


def describe_vpc_endpoint_services():
    pass


def describe_vpc_endpoints():
    pass


def describe_vpc_peering_connections():
    pass


def describe_vpcs(cidr=None, dhcp_options_id=None, isDefault=True, state=None,
                  tags=None, tag_key=None, tag_value=None, vpc_id=None,
                  vpc_name=None, region=None, key=None, keyid=None, profile=None):
    pass


def describe_vpn_connections():
    pass


def describe_vpn_gateways():
    pass


def detach_classic_link_vpc():
    pass


def detach_internet_gateway(internet_gateway_id, vpc_id, region=None, key=None,
                            keyid=None, profile=None):
    args = {'InternetGatewayId': internet_gateway_id, 'VpcId': vpc_id}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        conn.detach_internet_gateway(**args)
        args = {'InternetGatewayIds': [internet_gateway_id]}
        while True:
            r = conn.describe_internet_gateways(**args)
            igws = r['InternetGateways']
            if len(igws) < 1:
                return {'success': True}
            interesting = [a for a in igws[0]['Attachments'] if a.get('VpcId') == vpc_id]
            if not interesting:
                return {'success': True}
            for a in interesting:
                if a.get('State') == 'detached':
                    return {'success': True}
            log.info('Waiting for Internet Gateway {0} to detach...'.format(
                    internet_gateway_id))
            time.sleep(5)
    except ClientError as e:
        return {'success': False, 'error': salt.utils.boto3.get_error(e)}


def detach_network_interface():
    pass


def detach_volume():
    pass


def detach_vpn_gateway():
    pass


def disable_vgw_route_propagation():
    pass


def disable_vpc_classic_link():
    pass


def disable_vpc_classic_link_dns_support():
    pass


def disassociate_address(public_ip=None, association_id=None, region=None,
                         key=None, keyid=None, profile=None):
    if not _exactly_one((public_ip, association_id)):
        raise SaltInvocationError('Exactly one of public_ip OR '
                                  'association_id must be provided.')
    if public_ip:
        args = {'PublicIp': public_ip}
    else:
        args = {'AssociationId': association_id}

    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        conn.disassociate_address(**args)
        return {'success': True}
    except ClientError as e:
        return {'success': False, 'error': salt.utils.boto3.get_error(e)}


def disassociate_route_table(association_id, region=None, key=None, keyid=None,
                             profile=None):
    args = {'AssociationId': association_id}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        conn.disassociate_route_table(**args)
        return {'success': True}
    except ClientError as e:
        return {'success': False, 'error': salt.utils.boto3.get_error(e)}


def enable_vgw_route_propagation():
    pass


def enable_volume_io():
    pass


def enable_vpc_classic_link():
    pass


def enable_vpc_classic_link_dns_support():
    pass


def generate_presigned_url():
    pass


def get_console_output():
    pass


def get_paginator():
    pass


def get_password_data():
    pass


def get_resource_id(name, resource_type=None,
                    region=None, key=None, keyid=None, profile=None):
    tags = {'Name': name}
    r = describe_tags(resource_type=resource_type, tags=tags,
                      region=region, key=key, keyid=keyid, profile=profile)
    if 'error' in r:
        return r
    if len(r) < 1:
        return {}
    if len(r) > 1:
        return {'error': 'Name tag {0} matched more than one resource.  Try '
                         'refining search with a resource_type'.format(name)}
    return {'id': r[0]['ResourceId'] }


def get_waiter():
    pass


def import_image():
    pass


def import_instance():
    pass


def import_key_pair():
    pass


def import_snapshot():
    pass


def import_volume():
    pass


def modify_hosts():
    pass


def modify_id_format():
    pass


def modify_image_attribute():
    pass


def modify_instance_attribute():
    pass


def modify_instance_placement():
    pass


def modify_network_interface_attribute():
    pass


def modify_reserved_instances():
    pass


def modify_snapshot_attribute():
    pass


def modify_spot_fleet_request():
    pass


def modify_subnet(subnet_id, vpc_id=None, vpc_name=None, cidr_block=None,
                  availability_zone=None, map_public_ip_on_launch=False,
                  tags=None, region=None, key=None, keyid=None, profile=None):
    # Technically, the only mutable elements on a Subnet object in AWS are
    # Tags and MapPublicIpOnLaunch, so we permit these and error on any other
    # update request.  Note that 'name' is actually stored in a Tag...
    r = describe_subnets(availability_zone=availability_zone,
                         cidr_block=cidr_block, subnet_id=subnet_id,
                         vpc_id=vpc_id, vpc_name=vpc_name, tags=tags,
                         region=region, key=key, keyid=keyid, profile=profile)
    if 'error' in r:
        return {'success': False, 'error': r['error']}
    if len(r) == 1:
        # Short-circuit if all items are correct.
        return {'success': True, 'changes': {}}

    if vpc_id and vpc_name:
        raise SaltInvocationError('At most one of vpc_id or vpc_name'
                                  'may be provided.')
    if vpc_name is not None:
        r = get_resource_id(name=vpc_name, resource_type='vpc', region=region,
                            key=key, keyid=keyid, profile=profile)
        if 'error' in r:
            return {'success': False, 'error': r['error']}
        if 'id' not in r:
            e = "Couldn't resolve VPC name {0} to ID".format(vpc_name)
            return {'success': False, 'error': e}
        vpc_id = r['id']

    subnet = None
    if subnet_id:
        r = describe_subnets(subnet_id=subnet_id, region=region,
                             key=key, keyid=keyid, profile=profile)
        if 'error' in r:
            return {'success': False, 'error': r['error']}
        if len(r) < 1:
            # SubnetId is authoritative - if not found we fail...
            e = 'Subnet with ID {0} not found'.format(subnet_id)
            return {'success': False, 'error': e}
        subnet = r[0]

    if subnet['CidrBlock'] != cidr_block:
        e = ('Subnet {0} found but with wrong CIDR Block:  {1} - should be '
             '{2}'.format(subnet_id, subnet['CidrBlock'], cidr_block))
        return {'success': False, 'error': e}
    if availability_zone:
        if subnet['AvailabilityZone'] != availability_zone:
            e = ('Subnet {0} found but in wrong Availability Zone:  {1} - '
                 'should be {2}'.format(subnet_id, subnet['AvailabilityZone'],
                 availability_zone))
            return {'success': False, 'error': e}
    if vpc_id:
        if subnet['VpcId'] != vpc_id:
            e = ('Subnet {0} found but in wrong VPC:  {1} - should be '
                '{2}'.format(subnet_id, subnet['VpcId'], vpc_id))
            return {'success': False, 'error': e}

    # OK, we've made it past all the hurdles, let's see what we need to update
    ret = {'success': True, 'changes': {'old': {}, 'new': {}}}
    if subnet['MapPublicIpOnLaunch'] != map_public_ip_on_launch:
        try:
            args = {'SubnetId': subnet_id,
                    'MapPublicIpOnLaunch': map_public_ip_on_launch}
            conn.modify_subnet_attribute(**args)
        except ClientError as e:
            return {'success': False,'error': salt.utils.boto3.get_error(e)}
        ret['changes']['old']['MapPublicIpOnLaunch'] = subnet['MapPublicIpOnLaunch']
        ret['changes']['new']['MapPublicIpOnLaunch'] = map_public_ip_on_launch

    r = ensure_tags(subnet.get('Tags', []), tags)
    if 'error' in r:
        return {'success': False, 'error': r['error']}
    ret['changes'] = dictupdate.update(ret['changes'], r['changes'])
    return ret


def modify_subnet_attribute(subnet_id, map_public_ip_on_launch=False,
                            region=None, key=None, keyid=None, profile=None):
    args = {'SubnetId': subnet_id,
            'MapPublicIpOnLaunch': map_public_ip_on_launch}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.modify_subnet_attribute(**args)
        return {'success': True}
    except ClientError as e:
        return {'error': salt.utils.boto3.get_error(e)}


def modify_volume_attribute():
    pass


def modify_vpc_attribute():
    pass


def modify_vpc_endpoint():
    pass


def monitor_instances():
    pass


def move_address_to_vpc():
    pass


def purchase_reserved_instances_offering():
    pass


def reboot_instances():
    pass


def register_image():
    pass


def reject_vpc_peering_connection():
    pass


def release_address(public_ip=None, allocation_id=None,
                    region=None, key=None, keyid=None, profile=None):
    if not _exactly_one((public_ip, allocation_id)):
        raise SaltInvocationError('Exactly one of public_ip OR '
                                  'allocation_id must be provided.')
    if public_ip:  # EC2 Classic
        args = {'PublicIp': public_ip}
    else:
        args = {'AllocationId': allocation_id}
        addrs = describe_addresses(allocation_id=allocation_id, region=region,
                                   key=key, keyid=keyid, profile=profile)
        if 'error' in addrs:
            log.warning('Failed to free allocation-id {0}'.format(_id))
        if len(addrs) < 1:  # Seems to already be gone...  OK
            return {'success': True}
        assoc = addrs[0].get('AssociationId')
        if assoc:
            r = disassociate_address(association_id=assoc, region=region,
                    key=key, keyid=keyid, profile=profile)
            if 'error' in r:
                log.warning('Failed to disassociate allocation-id {0}'.format(
                        allocation_id))

    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        conn.release_address(**args)
        return {'success': True}
    except ClientError as e:
        # Special case - if an address has already been released, AND allocated
        # to someone else, you'll get AuthFailure.  Dumb?  Yeah, but WCYD?
        if e.response['Error']['Code'] == 'AuthFailure':
            return {'success': True}
        else:
            return {'success': False, 'error': salt.utils.boto3.get_error(e)}


def release_hosts():
    pass


def replace_network_acl_association(association_id=None, subnet_id=None,
                                    subnet_name=None, network_acl_id=None,
                                    network_acl_name=None, region=None,
                                    key=None, keyid=None, profile=None):
    if not _exactly_one((association_id, subnet_id, subnet_name)):
        raise SaltInvocationError('Exactly one of association_id, subnet_id, '
                                  'or subnet_name must be provided.')
    if not _exactly_one((network_acl_id, network_acl_name)):
        raise SaltInvocationError('Exactly one of network_acl_id OR '
                                  'network_acl_name must be provided.')
    if subnet_name is not None:
        r = get_resource_id(name=subnet_name,
                              resource_type='subnet', region=region,
                              key=key, keyid=keyid, profile=profile)
        if 'error' in r:
            return {'success': False, 'error': r['error']}
        if 'id' not in r:
            return {'success': False,
                    'error': "Couldn't resolve subnet_name {0} "
                              "to ID".format(subnet_name)}
        subnet_id = r['id']
    if subnet_id is not None:
        r = describe_network_acls(
                association_subnet_id=subnet_id, region=region, key=key,
                keyid=keyid, profile=profile)
        if 'error' in r:
            return {'success': False, 'error': r['error']}
        if len(r) < 1:
            return {'success': False,
                    'error': "Subnet {0} not found".format(subnet_name or
                                                           subnet_id)}
        associations = r[0].get('Associations', [])
        association_ids = [a.get('NetworkAclAssociationId') for a in associations
                if a.get('SubnetId') == subnet_id]
        association_id = association_ids[0]
    if network_acl_name is not None:
        r = get_resource_id(name=network_acl_name,
                              resource_type='network-acl', region=region,
                              key=key, keyid=keyid, profile=profile)
        if 'error' in r:
            return {'success': False, 'error': r['error']}
        if 'id' not in r:
            return {'success': False,
                    'error': "Couldn't resolve network_acl_name {0} "
                              "to ID".format(network_acl_name)}
        network_acl_id = r['id']

    args = {'AssociationId': association_id, 'NetworkAclId': network_acl_id}
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        r = conn.replace_network_acl_association(**args)
        if 'NewAssociationId' not in r:
            return {'success': False, 'error': 'Network Association not '
                    'replaced'}
        return {'success': True, 'id': r['NewAssociationId']}
    except ClientError as e:
        return {'success': False, 'error': salt.utils.boto3.get_error(e)}


def replace_network_acl_entry(network_acl_id=None, network_acl_name=None,
                              rule_number=None, protocol=None, rule_action=None,
                              egress=None, cidr_block=None, icmp_type_code=None,
                              port_range=None, region=None, key=None,
                              keyid=None, profile=None):
    if not _exactly_one((network_acl_id, network_acl_name)):
        raise SaltInvocationError('Exactly one of network_acl_id OR '
                                  'network_acl_name must be provided.')
    for a in ['rule_number', 'protocol', 'rule_action', 'egress', 'cidr_block']:
        if a not in locals() or locals()[a] == None:
            raise SaltInvocationError("'{0}' is a required parameter".format(a))
    if network_acl_name is not None:
        r = get_resource_id(name=network_acl_name,
                              resource_type='network-acl', region=region,
                              key=key, keyid=keyid, profile=profile)
        if 'error' in r:
            return {'success': False, 'error': r['error']}
        if 'id' not in r:
            return {'success': False,
                    'error': "Couldn't resolve network_acl_name {0} "
                              "to ID".format(network_acl_name)}
        network_acl_id = r['id']

    # Boto does NOT resolve protocol names correctly, despite the documentation.
    if isinstance(protocol, str) and not protocol.isdigit():
        try:
            protocol = socket.getprotobyname(protocol)
        except socket.error as e:
            log.warning("Couldn't resolve protocol '{0}' to a number, passing "
                        "as-is - this may produce a later failure.".format(
                        protocol))
    protocol = '{0}'.format(protocol)

    args = {'NetworkAclId': network_acl_id, 'RuleNumber': network_acl_id,
            'Protocol': network_acl_id, 'RuleAction': network_acl_id,
            'Egress': network_acl_id, 'CidrBlock': network_acl_id}
    args.update({'IcmpTypeCode': icmp_type_code}) if icmp_type_code else None
    args.update({'PortRange': port_range}) if port_range else None
    try:
        conn = _get_conn(region=region, key=key, keyid=keyid, profile=profile)
        conn.replace_network_acl_entry(**args)
        return {'success': True}
    except ClientError as e:
        return {'success': False, 'error': salt.utils.boto3.get_error(e)}


def replace_route():
    pass


def replace_route_table_association():
    pass


def report_instance_status():
    pass


def request_spot_fleet():
    pass


def request_spot_instances():
    pass


def reset_image_attribute():
    pass


def reset_instance_attribute():
    pass


def reset_network_interface_attribute():
    pass


def reset_snapshot_attribute():
    pass


def restore_address_to_classic():
    pass


def revoke_security_group_egress():
    pass


def revoke_security_group_ingress():
    pass


def run_instances():
    pass


def start_instances():
    pass


def stop_instances():
    pass


def terminate_instances():
    pass


def unassign_private_ip_addresses():
    pass


def unmonitor_instances():
    pass


# vim: ts=4 sw=4 sts=4 et
