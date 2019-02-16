# -*- coding: utf-8 -*-
'''
Manage EC2 via boto3 bindings

'''

# Import Python Libs
from __future__ import absolute_import
import logging
from time import time, sleep

# Import salt libs
import salt.utils.dictupdate as dictupdate
from salt.utils import exactly_one
from salt.utils.odict import OrderedDict
from salt.exceptions import SaltInvocationError, CommandExecutionError

log = logging.getLogger(__name__)


def __virtual__():
    '''
    Only load if boto is available.
    '''
    if 'boto3_ec2.get_resource_id' in __salt__:
        return 'boto3_ec2'
    else:
        return False


def internet_gateway_present(name, internet_gateway_id=None, vpc_id=None,
                             vpc_name=None, tags=None, region=None, key=None,
                             keyid=None, profile=None):
    '''
    Ensure an EC2 instance is running with the given attributes and state.

    name
        (string) - The name of the state definition.  Recommended that this
        match the the FQDN of the instance.


    region
        (string) - Region to connect to.
    key
        (string) - Secret key to be used.
    keyid
        (string) - Access key to be used.
    profile
        (variable) - A dict with region, key and keyid, or a pillar key (string)
        that contains a dict with region, key and keyid.

    .. versionadded:: Boron
    '''
    ret = {'name': name,
           'result': True,
           'comment': '',
           'changes': {}
          }

    if tags:
        tags.update({'Name': name})
    else:
        tags = {'Name': name}

    if vpc_name and vpc_id:
        ret['result'] = False
        ret['comment'] = "At most one of 'vpc_name' or 'vpc_id' may be provided"
        return ret

    if vpc_name is not None:
        r = __salt__['boto3_ec2.get_resource_id'](
                name=vpc_name, resource_type='vpc', region=region, key=key,
                keyid=keyid, profile=profile)
        if 'error' in r:
            ret['result'] = False
            ret['comment'] = "Couldn't resolve 'vpc_name' to id: {0}.".format(
                             r['error'])
            return ret
        vpc_id = r.get('id')

    igw = None
    if internet_gateway_id:
        args = {'internet_gateway_id': internet_gateway_id, 'region': region,
                'key': key, 'keyid': keyid, 'profile': profile}
        args.update({'attachment_vpc_id': vpc_id}) if vpc_id else None
        r = __salt__['boto3_ec2.describe_internet_gateways'](**args)
        if 'error' in r:
            ret['result'] = False
            ret['comment'] = r['error']
            return ret
        if len(r):
            igw = r[0]

    if not igw:
        args = {'internet_gateway_name': name,
                'region': region, 'key': key, 'keyid': keyid,
                'profile': profile}
        args.update({'attachment_vpc_id': vpc_id}) if vpc_id else None
        r = __salt__['boto3_ec2.describe_internet_gateways'](**args)
        if 'error' in r:
            ret['result'] = False
            ret['comment'] = r['error']
            return ret
        if len(r):
            igw = r[0]

    if not igw:
        if __opts__['test']:
            msg = 'The Internet Gateway {0} set to be created.'.format(name)
            ret['comment'] = msg
            ret['result'] = None
            return ret
        r = __salt__['boto3_ec2.create_internet_gateway'](
                name=name, vpc_id=vpc_id, tags=tags, region=region, key=key,
                keyid=keyid, profile=profile)
        if 'error' in r:
            ret['result'] = False
            ret['comment'] = r['error']
            return ret
        ret['changes'] = {'old': {}, 'new': {}}
        ret['changes']['old']['nat_gateway'] = None
        ret['changes']['new']['nat_gateway'] = r['id']
    else:
        obj_id = igw['InternetGatewayId']
        r = __salt__['boto3_ec2.compare_tagsets'](igw.get('Tags', []), tags)
        if r['added'] or r['modified'] or r['removed']:
            if __opts__['test']:
                msg = 'The Internet Gateway {0} set to be updated.'.format(name)
                ret['comment'] = msg
                ret['result'] = None
                return ret
        t = __salt__['boto3_ec2.ensure_tags'](obj_id, tags, region=region,
                                              key=key, keyid=keyid,
                                              profile=profile)
        if 'error' in t:
            ret['result'] = False
            ret['comment'] = t['error']
            return ret
        if r['added'] or r['modified'] or r['removed']:
            t = {[e['Key']]: e['Value'] for e in igw.get('Tags', [])}
            ret['changes']['old']['tags'] = t
            ret['changes']['new']['tags'] = tags

    return ret


def internet_gateway_absent(name, detach=False, region=None,
                            key=None, keyid=None, profile=None):
    '''
    Ensure the named internet gateway is absent.

    name
        Name of the internet gateway.

    detach
        First detach the internet gateway from a VPC, if attached.

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

    ret = {'name': name,
           'result': True,
           'comment': '',
           'changes': {}
          }

    r = __salt__['boto3_ec2.get_resource_id'](
            name=name, resource_type='internet-gateway', region=region, key=key,
            keyid=keyid, profile=profile)
    if 'error' in r:
        ret['result'] = False
        ret['comment'] = 'Failed to delete Internet Gateway: {0}.'.format(
                r['error'])
        return ret
    if 'id' not in r:
        ret['comment'] = 'Internet Gateway {0} already absent.'.format(name)
        return ret

    obj_id = r['id']
    if __opts__['test']:
        ret['comment'] = 'Internet gateway {0} is set to be removed.'.format(
                name)
        ret['result'] = None
        return ret
    r = __salt__['boto3_ec2.delete_internet_gateway'](
            internet_gateway_id=obj_id, detach=detach, region=region, key=key,
            keyid=keyid, profile=profile)
    if 'error' in r:
        ret['result'] = False
        ret['comment'] = 'Failed to delete internet gateway: {0}.'.format(
                r['error'])
        return ret
    ret['changes']['old'] = {'internet_gateway': obj_id}
    ret['changes']['new'] = {'internet_gateway': None}
    ret['comment'] = 'Internet gateway {0} deleted.'.format(name)
    return ret


def nat_gateway_present(name, subnet_id=None, subnet_name=None,
                        allocation_id=None, region=None, key=None, keyid=None,
                        profile=None):
    '''
    Ensure an EC2 instance is running with the given attributes and state.

    name
        (string) - The name of the state definition.  Recommended that this
        match the the FQDN of the instance.

    subnet_id
    subnet_name
    allocation_id

    region
        (string) - Region to connect to.
    key
        (string) - Secret key to be used.
    keyid
        (string) - Access key to be used.
    profile
        (variable) - A dict with region, key and keyid, or a pillar key (string)
        that contains a dict with region, key and keyid.

    .. versionadded:: Boron
    '''
    ret = {'name': name,
           'result': True,
           'comment': '',
           'changes': {}
          }
    _try_create = True
    changed_attrs = {}

    if not exactly_one((subnet_id, subnet_name)):
        ret['result'] = False
        ret['comment'] = "Exactly one of 'subnet_id' or 'subnet_name' is required"
        return ret

    if not subnet_id:
        r = __salt__['boto3_ec2.get_resource_id'](
                name=subnet_name, resource_type='subnet', region=region, key=key,
                keyid=keyid, profile=profile)
        if 'error' in r:
            ret['result'] = False
            ret['comment'] = r.get('error', 'Unknown error')
            return ret
        if 'id' not in r:
            ret['result'] = False
            ret['comment'] = "Couldn't resolve 'subnet_name' to ID."
            return ret
        subnet_id = r['id']

    nats = __salt__['boto3_ec2.describe_nat_gateways'](subnet_id=subnet_id,
                                                       region=region, key=key,
                                                       keyid=keyid,
                                                       profile=profile)
    if 'error' in nats:
        ret['result'] = False
        ret['comment'] = nats.get('error', 'Unknown error')
        return ret
    # Note:  without a provided allocation_id, the max number of gateways we
    # can support on a given subnet_id is one - otherwise we'd create a new one
    # at every run.  Idempotency is HARD :(
    if len(nats):
        if allocation_id:
            for nat in nats:
                for addr in nat.get('NatGatewayAddresses', []):
                    if addr['AllocationId'] == allocation_id:
                        _try_create = False
        else:
            _try_create = False

    if _try_create:
        if __opts__['test']:
            allocation_id = allocation_id if allocation_id else 'eipalloc-TBD'
            msg = 'The NAT Gateway {0}/{1} set to be created.'.format(
                    subnet_id, allocation_id)
            ret['comment'] = msg
            ret['result'] = None
            return ret

        if not allocation_id:
            eip = __salt__['boto3_ec2.allocate_address'](region=region, key=key,
                                                         keyid=keyid,
                                                         profile=profile)
            if 'error' in eip:
                ret['result'] = False
                ret['comment'] = eip.get('error', 'Unknown error')
                return ret
            allocation_id = eip['AllocationId']

        r = __salt__['boto3_ec2.create_nat_gateway'](
                name=name, subnet_id=subnet_id, allocation_id=allocation_id,
                region=region, key=key, keyid=keyid, profile=profile)
        if 'error' in r:
            ret['result'] = False
            ret['comment'] = r['error']
            return ret

        if not r.get('already_there', False):
            ret['changes'] = {'old': {}, 'new': {}}
            ret['changes']['old']['nat_gateway'] = None
            ret['changes']['new']['nat_gateway'] = r['id']

    return ret


def nat_gateway_absent(name, nat_gateway_id=None, subnet_id=None,
                       subnet_name=None, free_addresses=True, region=None,
                       key=None, keyid=None, profile=None):
    '''
    Ensure an EC2 NAT Gateway does not exist (is stopped and removed).

    name
        (string) - The name of the state definition.
    nat_gateway_id
    subnet_id
    subnet_name
    free_addresses
    region
        (string) - Region to connect to.
    key
        (string) - Secret key to be used.
    keyid
        (string) - Access key to be used.
    profile
        (variable) - A dict with region, key and keyid, or a pillar key (string)
        that contains a dict with region, key and keyid.

    .. versionadded:: Boron
    '''
    ret = {'name': name,
           'result': True,
           'comment': '',
           'changes': {}
          }

    if not exactly_one((nat_gateway_id, subnet_id, subnet_name)):
        ret['result'] = False
        ret['comment'] = ("Exactly one of 'nat_gateway_id', 'subnet_id' or "
                          "'subnet_name' must be specified.")
        return ret

    if not nat_gateway_id:
        if not subnet_id:
            r = __salt__['boto3_ec2.get_resource_id'](
                    name=subnet_name, resource_type='subnet', region=region,
                    key=key, keyid=keyid, profile=profile)
            if 'error' in r:
                ret['result'] = False
                ret['comment'] = r.get('error', 'Unknown error')
                return ret
            if 'id' not in r:
                # Can't look up NAT Gateways by name, only by associated subnet
                ret['comment'] = ('Subnet {0} already gone, assuming '
                        'associated NAT Gateway is too.'.format(subnet_name))
                return ret
            subnet_id = r['id']

        r = __salt__['boto3_ec2.describe_nat_gateways'](
                subnet_id=subnet_id, region=region, key=key, keyid=keyid,
                profile=profile)
        if 'error' in r:
            ret['result'] = False
            msg = ('Error looking up id of nat_gateway for subnet '
                   '{0}: {1}'.format(subnet_name if subnet_name else subnet_id,
                   r['error']))
            ret['comment'] = msg
        if len(r) < 1:
            ret['comment'] = ('NAT Gateway in subnet {0} already absent.'
                    ''.format(subnet_name if subnet_name else subnet_id))
            return ret
        allocation_ids = [n['AllocationId'] for n in r[0]['NatGatewayAddresses']]
        nat_gateway_id = r[0]['NatGatewayId']
    else:
        r = __salt__['boto3_ec2.describe_nat_gateways'](
                nat_gateway_id=nat_gateway_id, region=region, key=key,
                keyid=keyid, profile=profile)
        if 'error' in r:
            ret['result'] = False
            msg = 'Error looking up NAT Gateway with id {0}: {1}'.format(
                    nat_gateway_id, r['error'])
            ret['comment'] = msg
        if len(r) < 1:
            ret['comment'] = ('NAT Gateway in subnet {0} already absent.'
                    ''.format(subnet_name if subnet_name else subnet_id))
            return ret
        allocation_ids = [n['AllocationId'] for n in r[0]['NatGatewwayAddresses']]

    if __opts__['test']:
        ret['result'] = None
        msg = 'The NAT Gateway {0} is set to be deleted.'.format(nat_gateway_id)
        ret['comment'] = msg
        return ret

    r = __salt__['boto3_ec2.delete_nat_gateway'](nat_gateway_id=nat_gateway_id,
                                                 region=region, key=key,
                                                 keyid=keyid, profile=profile)
    if 'error' in r:
        ret['result'] = False
        ret['comment'] = 'Failed to delete NAT Gateway {0}: {1}.'.format(
                nat_gateway_id, ret['error'])
        return ret

    if free_addresses:
        for _id in allocation_ids:
            r = __salt__['boto3_ec2.release_address'](
                    allocation_id=_id, region=region, key=key,
                    keyid=keyid, profile=profile)
            if 'error' in r:
                log.warning('Failed to free allocation-id {0}'.format(_id))

    ret['changes']['old'] = {'nat_gateway_id': nat_gateway_id}
    ret['changes']['new'] = None
    return ret


def route_table_present(name, vpc_id=None, vpc_name=None, routes=None,
                        subnet_ids=None, subnet_names=None, tags=None,
                        region=None, key=None, keyid=None, profile=None):
    '''
    Ensure route table with routes exists and is associated to a VPC.

    Example:

    .. code-block:: yaml

        boto3_ec2.route_table_present:
            - name: my_route_table
            - vpc_id: vpc-123456
            - routes:
              - destination_cidr_block: 0.0.0.0/0
                internet_gateway_name: InternetGateway
              - destination_cidr_block: 10.10.11.0/24
                instance_id: i-123456
              - destination_cidr_block: 10.10.12.0/24
                interface_id: eni-123456
              - destination_cidr_block: 10.10.13.0/24
                instance_name: mygatewayserver
              - destination_cidr_block: 10.10.14.0/24
                nat_gateway: nat-0123456789abcdef0
            - subnet_names:
              - subnet1
              - subnet2

    name
        Name of the route table.

    vpc_id
        Id of the VPC with which the route table should be associated.
        Either vpc_name or vpc_id must be provided.

    vpc_name
        Name of the VPC with which the route table should be associated.

    routes
        A list of routes.  Each route has a cidr and a target.

    subnet_ids
        A list of subnet ids to associate

    subnet_names
        A list of subnet names to associate

    tags
        A list of tags.

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
    ret = {'name': name,
           'result': True,
           'comment': '',
           'changes': {}
          }

    if not exactly_one((vpc_name, vpc_id)):
        ret['result'] = False
        ret['comment'] = "Exactly one of 'vpc_name' or 'vpc_id' are required"
        return ret

    if vpc_name:
        r = __salt__['boto3_ec2.get_resource_id'](
                name=vpc_name, resource_type='vpc', region=region, key=key,
                keyid=keyid, profile=profile)
        if 'error' in r:
            ret['result'] = False
            ret['comment'] = "Couldn't resolve 'vpc_name' to id: {0}.".format(
                             r['error'])
            return ret
        vpc_id = r.get('id')

    r = _route_table_present(name=name, vpc_id=vpc_id,
                             tags=tags, region=region, key=key,
                             keyid=keyid, profile=profile)
    ret['changes'] = r['changes']
    ret['comment'] = ' '.join([ret['comment'], r['comment']])
    if not r['result']:
        ret['result'] = r['result']
        if ret['result'] is False:
            return ret
    r = _routes_present(name=name, routes=routes, vpc_id=vpc_id, tags=tags,
                        region=region, key=key, keyid=keyid, profile=profile)
    ret['changes'] = dictupdate.update(ret['changes'], r['changes'])
    ret['comment'] = ' '.join([ret['comment'], r['comment']])
    if not r['result']:
        ret['result'] = r['result']
        if ret['result'] is False:
            return ret
    r = _subnets_present(name=name, subnet_ids=subnet_ids,
                            subnet_names=subnet_names, tags=tags, region=region,
                            key=key, keyid=keyid, profile=profile)
    ret['changes'] = dictupdate.update(ret['changes'], r['changes'])
    ret['comment'] = ' '.join([ret['comment'], r['comment']])
    if not r['result']:
        ret['result'] = r['result']
        if ret['result'] is False:
            return ret
    return ret


def _route_table_present(name, vpc_id, tags=None, region=None, key=None,
                         keyid=None, profile=None):
    ret = {'name': name,
           'result': True,
           'comment': '',
           'changes': {}
          }

    r = __salt__['boto3_ec2.get_resource_id'](
            name=name, resource_type='route-table', region=region, key=key,
            keyid=keyid, profile=profile)
    if 'error' in r:
        ret['result'] = False
        ret['comment'] = 'Failed to create route table: {0}.'.format(r['error'])
        return ret

    _id = r.get('id')
    if _id:
        ret['comment'] = 'Route table {0} ({1}) present.'.format(name, _id)
        return ret

    if __opts__['test']:
        msg = 'Route table {0} is set to be created.'.format(name)
        ret['comment'] = msg
        ret['result'] = None
        return ret

    r = __salt__['boto3_ec2.create_route_table'](name=name, vpc_id=vpc_id,
                                                 tags=tags, region=region,
                                                 key=key, keyid=keyid,
                                                 profile=profile)
    if 'error' in r:
        ret['result'] = False
        ret['comment'] = 'Failed to create route table: {0}.'.format(r['error'])
        return ret

    ret['changes']['old'] = {'route_table': None}
    ret['changes']['new'] = {'route_table': r['id']}
    ret['comment'] = 'Route table {0} created.'.format(name)
    return ret


def _route_table_by_name(name, region=None, key=None, keyid=None, profile=None):
    ret = {'name': name,
           'result': True,
           'comment': '',
           'changes': {}
          }

    filts = {'Name': name}
    route_tables = __salt__['boto3_ec2.describe_route_tables'](
            tags=filts, region=region, key=key, keyid=keyid, profile=profile)
    if 'error' in route_tables:
        ret['comment'] = ("Couldn't retrieve configuration for route table {0}:"
                          " {1}.".format(name, route_tables['error']))
        ret['result'] = False
        return ret
    if len(route_tables) < 1:
        ret['comment'] = 'Route table with name {0} not found.'.format(name)
        ret['result'] = False
        return ret
    if len(route_tables) > 1:
        ret['comment'] = ('Route table name {0} matched multiple entries.'
                          ''.format(name))
        ret['result'] = False
        return ret

    return route_tables[0]


def _routes_present(name, routes, vpc_id, tags=None,
                    region=None, key=None, keyid=None, profile=None):
    ret = {'name': name,
           'result': True,
           'comment': '',
           'changes': {}
          }

    route_keys = {'DestinationCidrBlock': 'destination_cidr_block',
                  'GatewayId': 'gateway_id', 'InstanceId': 'instance_id',
                  'NetworkInterfaceId': 'network_interface_id',
                  'VpcPeeringConnectionId': 'vpc_peering_connection_id',
                  'NatGatewayId': 'nat_gateway_id'}

    route_table = _route_table_by_name(name, region, key, keyid, profile)
    if 'RouteTableId' not in route_table:
        ret['result'] = False
        ret['comment'] = route_table['comment']
        return ret

    _id = route_table['RouteTableId']
    is_routes = [dict((route_keys[k], r.get(k)) for k in route_keys)
                 for r in route_table['Routes']]

    want_routes = []
    if routes:
        for i in routes:
            _r = dict((k, i.get(k)) for k in route_keys.values())
            if i.get('internet_gateway_name'):
                _name = i['internet_gateway_name']
                r = __salt__['boto3_ec2.get_resource_id'](
                        name=_name, resource_type='internet-gateway',
                        region=region, key=key, keyid=keyid, profile=profile)
                if 'error' in r:
                    msg = ('Error looking up id for internet gateway {0}: '
                           '{1}'.format(_name, r['error']))
                    ret['comment'] = msg
                    ret['result'] = False
                    return ret
                if 'id' not in r:
                    msg = 'Internet gateway {0} does not exist.'.format(i)
                    ret['comment'] = msg
                    ret['result'] = False
                    return ret
                _r['gateway_id'] = r['id']
            if i.get('instance_name'):
                _name = i['instance_name']
                r = __salt__['boto3_ec2.get_resource_id'](
                        name=_name, resource_type='instance',
                        region=region, key=key, keyid=keyid, profile=profile)
                if 'error' in r:
                    ret['comment'] = ('Error looking up id for instance {0}: '
                                      '{1}'.format(_name, r['error']))
                    ret['result'] = False
                    return ret
                if 'id' not in r:
                    msg = 'Instance {0} does not exist.'.format(_name)
                    ret['comment'] = msg
                    ret['result'] = False
                    return ret
                _r['instance_id'] = r['id']
            if i.get('nat_gateway_subnet_name'):
                _name = i['nat_gateway_subnet_name']
                r = __salt__['boto3_ec2.get_resource_id'](
                        name=_name, resource_type='subnet',
                        region=region, key=key, keyid=keyid, profile=profile)
                if 'error' in r:
                    msg = ('Error looking up id for subnet_name {0}: {1}'.format(
                            _name, r['error']))
                    ret['comment'] = msg
                    ret['result'] = False
                    return ret
                if 'id' not in r:
                    msg = 'Subnet with name {0} does not exist.'.format(_name)
                    ret['comment'] = msg
                    ret['result'] = False
                    return ret
                i['nat_gateway_subnet_id'] = r['id']
            if i.get('nat_gateway_subnet_id'):
                _sn = i['nat_gateway_subnet_id']
                r = __salt__['boto3_ec2.describe_nat_gateways'](
                        subnet_id=_sn, region=region, key=key, keyid=keyid,
                        profile=profile)
                if 'error' in r:
                    msg = ('Error looking up id of nat_gateway for subnet '
                           '{0}: {1}'.format(_sn, r['error']))
                    ret['comment'] = msg
                    ret['result'] = False
                r = [g for g in r if g['State'] in ('pending', 'available')]
                if len(r) < 1:
                    ret['comment'] = ('NAT Gateway in subnet {0} does not '
                                      'exist.'.format(_sn))
                    ret['result'] = False
                    return ret
                _r['nat_gateway_id'] = r[0]['NatGatewayId']
            if i.get('vpc_peering_connection_name'):
                _vpcn = i['vpc_peering_connection_name']
                good_peering_states = ['pending-acceptance', 'provisioning', 'active']
                r = __salt__['boto3_ec2.describe_vpc_peering_connections'](
                        tags={'Name': _vpcn}, requester_vpc_info_vpc_id=vpc_id,
                        status_code=good_peering_states, region=region, key=key, keyid=keyid,
                        profile=profile)
                if 'error' in r:
                    msg = ('Error looking up id for VPC peering connection '
                           '{0}: {1}'.format(_vpcn, r['error']))
                    ret['comment'] = msg
                    ret['result'] = False
                    return ret
                if len(r) < 1:
                    ret['comment'] = 'VPC peering connection {0} does not exist.'.format(_vpcn)
                    ret['result'] = False
                    return ret
                if len(r) > 1:
                    ret['comment'] = 'Multiple VPC peering connections found with name {0}'.format(_vpcn)
                    ret['result'] = False
                    return ret
                _r['vpc_peering_connection_id'] = r[0]['VpcPeeringConnectionId']
            if i.get('instance_name'):
                running_states = ('pending', 'rebooting', 'running', 'stopping', 'stopped')
                r = __salt__['boto_ec2.get_id'](name=i['instance_name'], region=region,
                                                key=key, keyid=keyid, profile=profile,
                                                in_states=running_states)
                if r is None:
                    msg = 'Instance {0} does not exist.'.format(i['instance_name'])
                    ret['comment'] = msg
                    ret['result'] = False
                    return ret
                _r['instance_id'] = r

            want_routes.append(_r)

    to_delete = []
    to_create = []
    for route in want_routes:
        if route not in is_routes:
            to_create.append(dict(route))
    for route in is_routes:
        if route not in want_routes:
            if route['gateway_id'] != 'local':
                to_delete.append(route)
    if to_create or to_delete:
        if __opts__['test']:
            msg = 'Route table {0} set to have routes modified.'.format(name)
            ret['comment'] = msg
            ret['result'] = None
            return ret
        if to_delete:
            for r in to_delete:
                block = r['destination_cidr_block']
                res = __salt__['boto3_ec2.delete_route'](
                        route_table_id=_id, destination_cidr_block=block,
                        region=region, key=key, keyid=keyid, profile=profile)
                if not res['success']:
                    msg = ('Failed to delete route {0} from route table {1}: '
                           '{2}.'.format(block, name, res['error']))
                    ret['comment'] = msg
                    ret['result'] = False
                    return ret
                ret['comment'] = ('Deleted route {0} from route table '
                                  '{1}.'.format(block, name))
        if to_create:
            for r in to_create:
                block = r['destination_cidr_block']
                res = __salt__['boto3_ec2.create_route'](
                        route_table_id=_id, region=region, key=key, keyid=keyid,
                        profile=profile, **r)
                if not res['success']:
                    msg = ('Failed to create route {0} in route table '
                           '{1}: {2}.'.format(block, name, res['error']))
                    ret['comment'] = msg
                    ret['result'] = False
                    return ret
                ret['comment'] = 'Created route {0} in route table {1}.'.format(
                        r, name)

        ret['changes']['old'] = {'routes': route_table['Routes']}
        filts = {'Name': name}
        newrt = _route_table_by_name(name, region, key, keyid, profile)
        ret['changes']['new'] = {'routes': newrt['Routes']}

    return ret


def _subnets_present(name, subnet_ids=None, subnet_names=None, tags=None,
                     region=None, key=None, keyid=None, profile=None):
    ret = {'name': name,
           'result': True,
           'comment': '',
           'changes': {}
           }

    if not subnet_ids:
        subnet_ids = []

    # Look up subnet ids
    if subnet_names:
        for i in subnet_names:
            r = __salt__['boto3_ec2.get_resource_id'](
                    name=i, resource_type='subnet', region=region, key=key,
                    keyid=keyid, profile=profile)
            if 'error' in r:
                msg = 'Error looking up subnet ids: {0}'.format(r['error'])
                ret['comment'] = msg
                ret['result'] = False
                return ret
            if 'id' not in r:
                msg = 'Subnet {0} does not exist.'.format(i)
                ret['comment'] = msg
                ret['result'] = False
                return ret
            subnet_ids.append(r['id'])

    route_table = _route_table_by_name(name, region, key, keyid, profile)
    if 'RouteTableId' not in route_table:
        ret['result'] = False
        ret['comment'] = route_table['comment']
        return ret

    _id = route_table['RouteTableId']
    assoc_ids = [x['SubnetId'] for x in route_table['Associations']]
    to_create = [x for x in subnet_ids if x not in assoc_ids]
    to_delete = [x for x in route_table['Associations'] if x['SubnetId'] and
            x['SubnetId'] not in subnet_ids]

    if to_create or to_delete:
        if __opts__['test']:
            msg = 'Subnet associations for route table {0} set to be modified.'.format(name)
            ret['comment'] = msg
            ret['result'] = None
            return ret
        if to_delete:
            for r_asc in to_delete:
                r = __salt__['boto3_ec2.disassociate_route_table'](r_asc, region, key, keyid, profile)
                if 'error' in r:
                    msg = 'Failed to dissociate {0} from route table {1}: {2}.'.format(r_asc, name,
                                                                                       r['error'])
                    ret['comment'] = msg
                    ret['result'] = False
                    return ret
                ret['comment'] = 'Dissociated subnet {0} from route table {1}.'.format(r_asc, name)
        if to_create:
            for sn in to_create:
                r = __salt__['boto3_ec2.associate_route_table'](route_table_id=_id,
                                                               subnet_id=sn,
                                                               region=region, key=key,
                                                               keyid=keyid, profile=profile)
                if 'error' in r:
                    msg = 'Failed to associate subnet {0} with route table {1}: {2}.'.format(sn, name,
                                                                                             r['error'])
                    ret['comment'] = msg
                    ret['result'] = False
                    return ret
                ret['comment'] = 'Associated subnet {0} with route table {1}.'.format(sn, name)
        ret['changes']['old'] = {'subnets_associations': route_table['Associations']}
        filts = {'Name': name}
        new_sub = _route_table_by_name(name, region, key, keyid, profile)
        ret['changes']['new'] = {'subnets_associations': new_sub['Associations']}
    return ret


def route_table_absent(name, route_table_id=None, region=None,
                       key=None, keyid=None, profile=None):
    '''
    Ensure the named route table is absent.

    name
        Name of the route table.

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

    ret = {'name': name,
           'result': True,
           'comment': '',
           'changes': {}
           }

    if not route_table_id:
        r = __salt__['boto3_ec2.get_resource_id'](
                name=name, resource_type='route-table', region=region, key=key,
                keyid=keyid, profile=profile)
        if 'error' in r:
            ret['result'] = False
            ret['comment'] = r['error']
            return ret
        if 'id' not in r:
            ret['comment'] = 'Route Table {0} already absent.'.format(name)
            return ret
        route_table_id = r.get('id')

    if __opts__['test']:
        ret['comment'] = 'Route table {0} is set to be removed.'.format(name)
        ret['result'] = None
        return ret

    r = __salt__['boto3_ec2.delete_route_table'](route_table_name=name,
                                                region=region,
                                                key=key, keyid=keyid,
                                                profile=profile)
    if 'error' in r:
        ret['result'] = False
        ret['comment'] = 'Failed to delete route table: {0}'.format(r['error'])
        return ret

    ret['changes']['old'] = {'route_table': route_table_id}
    ret['changes']['new'] = {'route_table': None}
    ret['comment'] = 'Route table {0} deleted.'.format(name)
    return ret


def _default_network_acl(vpc_id=None,
                   region=None, key=None, keyid=None, profile=None):
    ret = {}
    r = __salt__['boto3_ec2.describe_network_acls'](
            default=True, vpc_id=vpc_id,
            region=region, key=key, keyid=keyid, profile=profile)
    if 'error' in r:
        ret['error'] = r['error']
        return ret
    if len(r) < 1:
        ret['error'] = ("Couldn't determine default Network ACL for VPC "
                '{0}'.format(vpc_id))
        return ret
    ret['id'] = r[0]['NetworkAclId']
    return ret


def subnet_present(name, cidr_block, vpc_id=None, vpc_name=None,
                   availability_zone=None, map_public_ip_on_launch=False,
                   network_acl_id=None, network_acl_name=None, tags=None,
                   region=None, key=None, keyid=None, profile=None):
    '''
    Ensure a subnet exists.

    name
        Name of the subnet.

    cidr_block
        The range if IPs for the subnet, in CIDR format. For example:
        10.0.0.0/24. Block size must be between /16 and /28 netmask.

    vpc_name
        Name of the VPC in which the subnet should be placed. Either
        vpc_name or vpc_id must be provided.

    vpc_id
        Id of the VPC in which the subnet should be placed. Either vpc_name
        or vpc_id must be provided.

    availability_zone
        AZ in which the subnet should be placed.

    tags
        A list of tags.

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
    # For practical purposes, the only mutable things about a Subnet are Network
    # ACL association, Tags, and MapPublicIpOnLaunch, so we need to error on any
    # other update request.  Remember 'name' is actually stored in a Tag...

    ret = {'name': name,
           'result': True,
           'comment': '',
           'changes': {}
           }

    if network_acl_id and network_acl_name:
        ret['result'] = False
        ret['comment'] = ("At most one of 'name' or 'subnet_id' may be "
                          "specified.")
        return ret

    if tags:
        tags.update({'Name': name})
    else:
        tags = {'Name': name}

    if network_acl_name:
        r = __salt__['boto3_ec2.get_resource_id'](
                name=network_acl_name, resource_type='network-acl',
                region=region, key=key, keyid=keyid, profile=profile)
        if 'error' in r:
            ret['result'] = False
            ret['comment'] = r['error']
            return ret
        if 'id' not in r:
            ret['result'] = False
            ret['comment'] = ("Couldn't resolve Network ACL Name {0} to an "
                    "ID".format(network_acl_name))
            return ret
        network_acl_id = r['id']

    subnet = None
    # First, try to find it by Name
    r = __salt__['boto3_ec2.describe_subnets'](
            vpc_id=vpc_id, vpc_name=vpc_name, subnet_name=name,
            region=region, key=key, keyid=keyid, profile=profile)
    if 'error' in r:
        ret['result'] = False
        ret['comment'] = r['error']
        return ret
    if len(r) > 1:
        ret['result'] = False
        ret['comment'] = ('More than one subnet found in VPC {0} with '
                          'Name {1}'.format(vpc_name or vpc_id, name))
        return ret
    if len(r):
        subnet = r[0]
    # Else, try to find by CIDR
    if not subnet:
        r = __salt__['boto3_ec2.describe_subnets'](
                cidr_block=cidr_block, vpc_id=vpc_id, vpc_name=vpc_name,
                region=region, key=key, keyid=keyid, profile=profile)
        if 'error' in r:
            ret['result'] = False
            ret['comment'] = r['error']
            return ret
        if len(r) > 1:
            ret['result'] = False
            ret['comment'] = ('More than one subnet found in VPC {0} with '
                              'CIDR:  {1}.'.format(vpc_name or vpc_id,
                              cidr_block))
            return ret
        if len(r):
            subnet = r[0]

    if not subnet:
        if __opts__['test']:
            ret['comment'] = 'The Subnet {0} set to be created.'.format(name)
            ret['result'] = None
            return ret
        r = __salt__['boto3_ec2.create_subnet'](
                name=name, vpc_id=vpc_id, vpc_name=vpc_name,
                cidr_block=cidr_block, availability_zone=availability_zone,
                tags=tags, region=region, key=key, keyid=keyid, profile=profile)
        if 'error' in r:
            ret['result'] = False
            ret['comment'] = 'Failed to create subnet: {0}'.format(r['error'])
            return ret
        log.info('Subnet {0} created.'.format(name))
        ret['changes']['old'] = {'subnet': None}
        ret['changes']['new'] = {'subnet': r['details']}

        r = __salt__['boto3_ec2.replace_network_acl_association'](
                subnet_id=r['id'], network_acl_id=network_acl_id,
                region=region, key=key, keyid=keyid, profile=profile)
        if 'error' in r:
            ret['result'] = False
            ret['comment'] = r['error']
            return ret
        changes = {'old': {'subnet': {'NetworkAclId': None}},
                   'new': {'subnet': {'NetworkAclId': r['id']}}}
        ret['changes'] = dictupdate.update(ret['changes'], changes)

        ret['comment'] = 'Subnet {0} created.'.format(name)
        return ret

    # else we're updating
    if not network_acl_id:
        r = _default_network_acl(vpc_id, region, key, keyid, profile)
        if 'id' not in r:
            ret['result'] = False
            ret['comment'] = r['error']
            return ret
        network_acl_id = r['id']

    m = True if subnet['MapPublicIpOnLaunch'] == map_public_ip_on_launch else False
    r = __salt__['boto3_ec2.compare_tagsets'](subnet.get('Tags', []), tags)
    sid = subnet['SubnetId']

    r = __salt__['boto3_ec2.describe_network_acls'](
            association_subnet_id=sid, vpc_id=vpc_id, region=region, key=key,
            keyid=keyid, profile=profile)
    if 'error' in r:
        ret['result'] = False
        ret['comment'] = r['error']
        return ret
    assocs = [a for a in r[0]['Associations'] if a['SubnetId'] == sid]
    assoc = assocs[0]  ## There can be only one
    n = None
    if assoc['NetworkAclId'] != network_acl_id:
        n = network_acl_id

    if n or m or r['added'] or r['modified'] or r['removed']:
        if __opts__['test']:
            ret['comment'] = 'The Subnet {0} set to be updated.'.format(name)
            ret['result'] = None
            return ret
    else:
        return ret

    if m or r['added'] or r['modified'] or r['removed']:
        r = __salt__['boto3_ec2.modify_subnet'](
                subnet_id=sid, vpc_id=vpc_id, vpc_name=vpc_name,
                cidr_block=cidr_block, availability_zone=availability_zone,
                map_public_ip_on_launch=map_public_ip_on_launch, tags=tags,
                region=region, key=key, keyid=keyid, profile=profile)
        if 'error' in r:
            ret['result'] = False
            ret['comment'] = 'Failed to update subnet: {0}'.format(r['error'])
            return ret
        ret['changes'] = dictupdate.update(ret['changes'], r['changes'])
    if n:
        r = __salt__['boto3_ec2.replace_network_acl_association'](
                subnet_id=sid, network_acl_id=n,
                region=region, key=key, keyid=keyid, profile=profile)
        if 'error' in r:
            ret['result'] = False
            ret['comment'] = r['error']
            return ret
        changes = {'old': {'subnet': {'NetworkAclId': assoc['NetworkAclId']}},
                   'new': {'subnet': {'NetworkAclId': network_acl_id}}}
        ret['changes'] = dictupdate.update(ret['changes'], changes)

    ret['comment'] = 'Subnet {0} updated.'.format(name)
    return ret


def subnet_absent(name=None, subnet_id=None, region=None, key=None, keyid=None, profile=None):
    '''
    Ensure subnet with passed properties is absent.

    name
        Name of the subnet.

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

    ret = {'name': name,
           'result': True,
           'comment': '',
           'changes': {}
           }

    if not exactly_one((name, subnet_id)):
        ret['result'] = False
        ret['comment'] = ("Exactly one of 'name' or 'subnet_id' must be "
                          "specified.")
        return ret

    if not subnet_id:
        r = __salt__['boto3_ec2.get_resource_id'](
                name=name, resource_type='subnet', region=region, key=key,
                keyid=keyid, profile=profile)
        if 'error' in r:
            ret['result'] = False
            ret['comment'] = 'Failed to delete subnet: {0}.'.format(r['error'])
            return ret
        if 'id' not in r:
            ret['comment'] = 'Subnet {0} absent'.format(name or subnet_id)
            return ret
        subnet_id = r['id']

    if __opts__['test']:
        ret['comment'] = 'Subnet {0} is set to be removed.'.format(
                name or subnet_id)
        ret['result'] = None
        return ret

    r = __salt__['boto3_ec2.delete_subnet'](
            subnet_id=subnet_id, region=region, key=key, keyid=keyid,
            profile=profile)
    if 'error' in r:
        ret['result'] = False
        ret['comment'] = 'Failed to delete subnet {0]: {0}'.format(name or
                subnet_id, r['error'])
        return ret

    ret['changes']['old'] = {'subnet': subnet_id}
    ret['changes']['new'] = {'subnet': None}
    ret['comment'] = 'Subnet {0} deleted.'.format(name or subnet_id)
    return ret


def network_acl_present(name, network_acl_id=None, entries=None, vpc_id=None,
                        vpc_name=None, tags=None, region=None, key=None,
                        keyid=None, profile=None):
    '''
    Ensure the named Network ACL is absent.

    name
        Name of the Network ACL.

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

    ret = {'name': name,
           'result': True,
           'comment': '',
           'changes': {}
          }

    if not exactly_one((vpc_name, vpc_id)):
        ret['result'] = False
        ret['comment'] = "Exactly one of 'vpc_name' or 'vpc_id' is required"
        return ret

    if vpc_name:
        r = __salt__['boto3_ec2.get_resource_id'](
                name=vpc_name, resource_type='vpc', region=region, key=key,
                keyid=keyid, profile=profile)
        if 'error' in r:
            ret['result'] = False
            ret['comment'] = "Couldn't resolve 'vpc_name' to id: {0}.".format(
                             r['error'])
            return ret
        vpc_id = r.get('id')

    r = _ensure_network_acl(name, network_acl_id, vpc_id, tags, region, key,
                            keyid, profile)
    if r['result'] == False:
        ret['result'] = False
        ret['comment'] = r['comment']
        return ret
    ret['changes'] = dictupdate.update(ret['changes'], r['changes'])
    ret['comment'] += r['comment']

    acl = r['acl']
    if __opts__['test']:
        ret['result'] = None
        if not acl:
            ret['comment'] = 'Network ACL {0} is set to be created'.format(name)
        else:
            ret['comment'] = 'Network ACL {0} is set to be updated'.format(name)
        return ret

    r = _ensure_network_acl_entries(name, acl, entries, region, key, keyid,
                                    profile)
    if r['result'] == False:
        ret['result'] = False
        ret['comment'] = r['comment']
        return ret
    ret['changes'] = dictupdate.update(ret['changes'], r['changes'])
    ret['comment'] += r['comment']

    return ret


def _ensure_network_acl(name, network_acl_id=None, vpc_id=None, tags=None,
                        region=None, key=None, keyid=None, profile=None):
    ret = {'name': name,
           'result': True,
           'comment': '',
           'changes': {},
           'acl': None
          }

    if tags:
        tags.update({'Name': name})
    else:
        tags = {'Name': name}

    if network_acl_id:
        r = __salt__['boto3_ec2.describe_network_acls'](
                network_acl_id=network_acl_id, vpc_id=vpc_id, region=region,
                key=key, keyid=keyid, profile=profile)
        if 'error' in r:
            ret['result'] = False
            ret['comment'] = r['error']
            return ret
        if len(r) < 1:
            ret['result'] = False
            ret['comment'] = 'Network ACL with ID {0} does not exist'.format(
                    network_acl_id)
            return ret
        ret['acl'] = r[0]
    if not ret['acl']:
        r = __salt__['boto3_ec2.describe_network_acls'](
                tags={'Name': name}, vpc_id=vpc_id, region=region, key=key,
                keyid=keyid, profile=profile)
        if 'error' in r:
            ret['result'] = False
            ret['comment'] = r['error']
            return ret
        if len(r) > 1:
            ret['result'] = False
            ret['comment'] = ('More than one Network ACL found in VPC {0} with '
                              'Name {1}'.format(vpc_id, name))
            return ret
        if len(r):
            ret['acl'] = r[0]
    if not ret['acl']:
        if __opts__['test']:
            msg = 'Network ACL {0} is set to be created.  '.format(name)
            ret['comment'] = msg
            ret['result'] = None
            return ret
        r = __salt__['boto3_ec2.create_network_acl'](
                name=name, vpc_id=vpc_id, tags=tags, region=region, key=key,
                keyid=keyid, profile=profile)
        if 'error' in r:
            ret['result'] = False
            ret['comment'] = r['error']
            return ret
        changes = {'old': {'network_acl': None},
                   'new': {'network_acl': r['details']}}
        ret['changes'] = dictupdate.update(ret['changes'], changes)
        ret['comment'] = 'Network ACL {0} created.  '.format(name)
        ret['acl'] = r['details']
    else:
        obj_id = ret['acl']['NetworkAclId']
        r = __salt__['boto3_ec2.compare_tagsets'](ret['acl'].get('Tags', []),
                tags)
        if r['added'] or r['modified'] or r['removed']:
            if __opts__['test']:
                msg = 'Network ACL {0} is set to be updated.  '.format(name)
                ret['comment'] = msg
                ret['result'] = None
                return ret
        t = __salt__['boto3_ec2.ensure_tags'](obj_id, tags, region=region,
                                              key=key, keyid=keyid,
                                              profile=profile)
        if 'error' in t:
            ret['result'] = False
            ret['comment'] = t['error']
            return ret
        if r['added'] or r['modified'] or r['removed']:
            t = {[e['Key']]: e['Value'] for e in igw.get('Tags', [])}
            changes = {'old': {'network_acl': {'tags': t}},
                       'new': {'network_acl': {'tags': tags}}}
            ret['comment'] = 'Network ACL {0} updated.  '.format(name)
            ret['changes'] = dictupdate.update(ret['changes'], changes)
        else:
            ret['comment'] = 'Network ACL {0} already correct.  '.format(name)

    return ret


def _normalize_network_acl_entry(layer):
    ### Fugly, but what can you do?
    ret = layer
    if isinstance(layer, OrderedDict):
        ret = dict(layer)
    if isinstance(ret, dict):
        for key, value in ret.items():
            if key == 'Protocol':
                value = str(value)
            ret[_normalize_network_acl_entry(key)] = _normalize_network_acl_entry(value)
    elif isinstance(ret, list):
        ret = [_normalize_network_acl_entry(t) for t in ret]
    elif isinstance(ret, tuple):
        ret = tuple([_normalize_network_acl_entry(t) for t in ret])
    elif isinstance(ret, unicode):
        ret = ret.encode('utf-8')

    return ret


def _ensure_network_acl_entries(name, acl, entries, region, key, keyid, profile):
    ret = {'name': name,
           'result': True,
           'comment': '',
           'changes': {},
           'acl': None
          }

    obj_id = acl['NetworkAclId']

    # Ignore automatic deny-all at end, we can't change it and it just confuses things...
    has = [a for a in _normalize_network_acl_entry(acl['Entries']) if a['RuleNumber'] != 32767]
    want = _normalize_network_acl_entry(entries)
    delete = []
    add = []
    add = [ w for w in want if w not in has ]
    delete = [ h for h in has if h not in want ]

    if add or delete:
        if __opts__['test']:
            msg = 'Network ACL {0} entries are set to be updated.'.format(name)
            ret['comment'] = msg
            ret['result'] = None
            return ret

    # Bah!  There's actually a replace_network_acl_entry(), but using it
    # needlessly complexifies a very simple operation :-/
    for d in delete:
        r = __salt__['boto3_ec2.delete_network_acl_entry'](
                network_acl_id=obj_id, rule_number=d['RuleNumber'],
                egress=d['Egress'], region=region, key=key, keyid=keyid,
                profile=profile)
        if 'error' in r:
            ret['result'] = False
            ret['comment'] = r['error']
            return ret
    for a in add:
        # Default to ingress since it's the much more common case
        r = __salt__['boto3_ec2.create_network_acl_entry'](
                network_acl_id=obj_id, rule_number=a['RuleNumber'],
                protocol=a['Protocol'], rule_action=a['RuleAction'],
                egress=a.get('Egress', False), cidr_block=a['CidrBlock'],
                icmp_type_code=a.get('IcmpTypeCode', None),
                port_range=a.get('PortRange', None), region=region, key=key,
                keyid=keyid, profile=profile)
        if 'error' in r:
            ret['result'] = False
            ret['comment'] = r['error']
            return ret

    if add or delete:
        ret['comment'] = 'Network ACL entries for {0} updated.'.format(name)
        changes = {'old': {'network_acl': {'entries': {name: has}}},
                   'new': {'network_acl': {'entries': {name: want}}}}
        ret['changes'] = dictupdate.update(ret['changes'], changes)
    else:
        ret['comment'] = ('Network ACL entries for {0} already correct.'.format(
                          name))

    return ret


def network_acl_absent(name, network_acl_id=None, region=None, key=None,
                       keyid=None, profile=None):
    '''
    Ensure the named Network ACL is absent.

    name
        Name of the Network ACL.

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

    ret = {'name': name,
           'result': True,
           'comment': '',
           'changes': {}
          }

    if not network_acl_id:
        r = __salt__['boto3_ec2.get_resource_id'](
                name=name, resource_type='network-acl', region=region, key=key,
                keyid=keyid, profile=profile)
        if 'error' in r:
            ret['result'] = False
            ret['comment'] = r['error']
            return ret
        if 'id' not in r:
            ret['comment'] = 'Network ACL {0} already absent.'.format(name)
            return ret
        network_acl_id = r['id']

    if __opts__['test']:
        ret['comment'] = 'Network ACL {0} is set to be removed.'.format(name)
        ret['result'] = None
        return ret

    r = __salt__['boto3_ec2.delete_network_acl'](network_acl_id=network_acl_id,
                                                region=region, key=key,
                                                keyid=keyid, profile=profile)
    if 'error' in r:
        ret['result'] = False
        ret['comment'] = 'Failed to delete Network ACL: {0}'.format(r['error'])
        return ret

    ret['changes']['old'] = {'network_acl': network_acl_id}
    ret['changes']['new'] = {'network_acl': None}
    ret['comment'] = 'Network ACL {0} deleted.'.format(name)
    return ret


# vim: ts=4 sw=4 sts=4 et
