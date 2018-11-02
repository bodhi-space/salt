# -*- coding: utf-8 -*-
'''
Manage CloudFront distributions

.. versionadded:: 2018.3.0

Create, update and destroy CloudFront distributions.

This module accepts explicit AWS credentials but can also utilize
IAM roles assigned to the instance through Instance Profiles.
Dynamic credentials are then automatically obtained from AWS API
and no further configuration is necessary.
More information available `here
<https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html>`_.

If IAM roles are not used you need to specify them,
either in a pillar file or in the minion's config file:

.. code-block:: yaml

    cloudfront.keyid: GKTADJGHEIQSXMKKRBJ08H
    cloudfront.key: askdjghsdfjkghWupUjasdflkdfklgjsdfjajkghs

It's also possible to specify ``key``, ``keyid``, and ``region`` via a profile,
either passed in as a dict, or a string to pull from pillars or minion config:

.. code-block:: yaml

    myprofile:
        keyid: GKTADJGHEIQSXMKKRBJ08H
        key: askdjghsdfjkghWupUjasdflkdfklgjsdfjajkghs
        region: us-east-1

.. code-block:: yaml

    aws:
        region:
            us-east-1:
                profile:
                    keyid: GKTADJGHEIQSXMKKRBJ08H
                    key: askdjghsdfjkghWupUjasdflkdfklgjsdfjajkghs
                    region: us-east-1

:depends: boto3
'''

# Import Python Libs
from __future__ import absolute_import, print_function, unicode_literals
import difflib
import logging
import uuid
import jmespath
import copy

# Import Salt conveniences
from salt.exceptions import SaltInvocationError
import salt.utils.boto3

log = logging.getLogger(__name__)


def __virtual__():
    '''
    Only load if boto is available.
    '''
    if 'boto_cloudfront.get_distribution' not in __salt__:
        msg = 'The boto_cloudfront state module could not be loaded: {}.'
        return (False, msg.format('boto_cloudfront exec module unavailable.'))
    return 'boto_cloudfront'


def present(
    name,
    config,
    tags,
    region=None,
    key=None,
    keyid=None,
    profile=None,
):
    '''
    Ensure the CloudFront distribution is present.

    name (string)
        Name of the CloudFront distribution

    config (dict)
        Configuration for the distribution

    tags (dict)
        Tags to associate with the distribution

    region (string)
        Region to connect to

    key (string)
        Secret key to use

    keyid (string)
        Access key to use

    profile (dict or string)
        A dict with region, key, and keyid,
        or a pillar key (string) that contains such a dict.

    Example:

    .. code-block:: yaml

        Manage my_distribution CloudFront distribution:
            boto_cloudfront.present:
              - name: my_distribution
              - config:
                  Comment: 'partial config shown, most parameters elided'
                  Enabled: True
              - tags:
                  testing_key: testing_value
    '''
    ret = {
        'name': name,
        'comment': '',
        'changes': {},
    }

    res = __salt__['boto_cloudfront.get_distribution'](
        name,
        region=region,
        key=key,
        keyid=keyid,
        profile=profile,
    )
    if 'error' in res:
        ret['result'] = False
        ret['comment'] = 'Error checking distribution {0}: {1}'.format(
            name,
            res['error'],
        )
        return ret

    old = res['result']
    if old is None:
        if __opts__['test']:
            ret['result'] = None
            ret['comment'] = 'Distribution {0} set for creation.'.format(name)
            ret['pchanges'] = {'old': None, 'new': name}
            return ret

        res = __salt__['boto_cloudfront.create_distribution'](
            name,
            config,
            tags,
            region=region,
            key=key,
            keyid=keyid,
            profile=profile,
        )
        if 'error' in res:
            ret['result'] = False
            ret['comment'] = 'Error creating distribution {0}: {1}'.format(
                name,
                res['error'],
            )
            return ret

        ret['result'] = True
        ret['comment'] = 'Created distribution {0}.'.format(name)
        ret['changes'] = {'old': None, 'new': name}
        return ret
    else:
        full_config_old = {
            'config': old['distribution']['DistributionConfig'],
            'tags': old['tags'],
         }
        full_config_new = {
            'config': config,
            'tags': tags,
         }
        diffed_config = __utils__['dictdiffer.deep_diff'](
            full_config_old,
            full_config_new,
        )

        def _yaml_safe_dump(attrs):
            '''
            Safely dump YAML using a readable flow style
            '''
            dumper_name = 'IndentedSafeOrderedDumper'
            dumper = __utils__['yaml.get_dumper'](dumper_name)
            return __utils__['yaml.dump'](
                attrs,
                default_flow_style=False,
                Dumper=dumper)

        changes_diff = ''.join(difflib.unified_diff(
            _yaml_safe_dump(full_config_old).splitlines(True),
            _yaml_safe_dump(full_config_new).splitlines(True),
        ))

        any_changes = bool('old' in diffed_config or 'new' in diffed_config)
        if not any_changes:
            ret['result'] = True
            ret['comment'] = 'Distribution {0} has correct config.'.format(
                name,
            )
            return ret

        if __opts__['test']:
            ret['result'] = None
            ret['comment'] = '\n'.join([
                'Distribution {0} set for new config:'.format(name),
                changes_diff,
            ])
            ret['pchanges'] = {'diff': changes_diff}
            return ret

        res = __salt__['boto_cloudfront.update_distribution'](
            name,
            config,
            tags,
            region=region,
            key=key,
            keyid=keyid,
            profile=profile,
        )
        if 'error' in res:
            ret['result'] = False
            ret['comment'] = 'Error updating distribution {0}: {1}'.format(
                name,
                res['error'],
            )
            return ret

        ret['result'] = True
        ret['comment'] = 'Updated distribution {0}.'.format(name)
        ret['changes'] = {'diff': changes_diff}
        return ret


def _fix_quantities(tree):
    '''
    Stupidly simple function to fix any Items/Quantity disparities inside a
    DistributionConfig block before use.  Since AWS only accepts JSON-encodable
    data types, this implementation is "good enough" for our purposes.
    '''
    if isinstance(tree, dict):
        tree = {k: _fix_quantities(v) for k, v in tree.items()}
        if isinstance(tree.get('Items'), list):
            tree['Quantity'] = len(tree['Items'])
            if len(tree['Items']) == 0:
                tree.pop('Items')  # Silly, but AWS requires it....
        return tree
    elif isinstance(tree, list):
        return [_fix_quantities(t) for t in tree]
    else:
        return tree


def distribution_present(name, region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Ensure the given CloudFront distribution exists in the described state.

    Note that the semantics of DistributionConfig (below) are rather arcane, and vary
    wildly depending on whether the distribution already exists or not (e.g. is being
    initially created, or being updated in place).  Lots more details can be found at
    __: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-overview-required-fields.html

    name (string)
        Name of the state definition.

    Name (string)
        Name of the resource (for purposes of Salt's idempotency).  If not provided, the value of
        `name` will be used.

    DistributionConfig (dict)
        Configuration for the distribution.
        Notes:
        - The CallerReference field should NOT be provided - it will be autopopulated by Salt.
        - A large number of sub- (and sub-sub-) fields require a `Quantity` element, which simply
          COUNTS the number of items in the `Items` element.  This is bluntly stupid, and thus as
          a convenience, Salt will traverse the given configuration, and add (or fix) a `Quantity`
          element for any `Items` elements of list-type it encounters.  This adds a bit of sanity
          to an otherwise error-prone situation.  Note that for this to work, zero-length lists
          must be inlined as `[]`.
        - Due to the unavailibity of a better way to store stateful idempotency information about
          Distributions, the Comment sub-element (as the only user-settable attribute without weird
          self-blocking semantics, and which is available from the core `get_distribution()` API
          call) is utilized to store the Salt `Name` value, which is used to determine resource
          existence and state.  That said, to enable SOME usability of this field, only the value
          up to the first colon character is taken as the `Name` attribute, while anything
          afterward is free-form and ignored (but preserved) by Salt.

    Tags (dict)
        Tags to associate with the distribution.

    region (string)
        Region to connect to.

    key (string)
        Secret key to use.

    keyid (string)
        Access key to use.

    profile (dict or string)
        Dict, or pillar key pointing to a dict, containing AWS region/key/keyid.

    Example:

    .. code-block:: yaml

          plt-dev-spaapi-cf-dist-cf_dist-present:
            boto_cloudfront.distribution_present:
            - Name: plt-dev-spaapi-cf-dist
            - DistributionConfig:
                Comment: SPA
                Logging:
                  Enabled: false
                  Prefix: ''
                  Bucket: ''
                  IncludeCookies: false
                WebACLId: ''
                Origins:
                  Items:
                  - S3OriginConfig:
                      OriginAccessIdentity: the-SPA-OAI
                    OriginPath: ''
                    CustomHeaders:
                      Items: []
                    Id: S3-hs-backend-srpms
                    DomainName: hs-backend-srpms.s3.amazonaws.com
                PriceClass: PriceClass_All
                DefaultRootObject: ''
                Enabled: true
                DefaultCacheBehavior:
                  ViewerProtocolPolicy: allow-all
                  TrustedSigners:
                    Items: []
                    Enabled: false
                  SmoothStreaming: false
                  TargetOriginId: S3-hs-backend-srpms
                  FieldLevelEncryptionId: ''
                  ForwardedValues:
                    Headers:
                      Items: []
                    Cookies:
                      Forward: none
                    QueryStringCacheKeys:
                      Items: []
                    QueryString: false
                  MaxTTL: 31536000
                  LambdaFunctionAssociations:
                    Items: []
                  DefaultTTL: 86400
                  AllowedMethods:
                    CachedMethods:
                      Items:
                      - HEAD
                      - GET
                    Items:
                    - HEAD
                    - GET
                  MinTTL: 0
                  Compress: false
                IsIPV6Enabled: true
                ViewerCertificate:
                  CloudFrontDefaultCertificate: true
                  MinimumProtocolVersion: TLSv1
                  CertificateSource: cloudfront
                Aliases:
                  Items:
                  - bubba-hotep.bodhi-dev.io
                HttpVersion: http2
            - Tags:
                Owner: dev_engrs

    '''
    ret = {'name': name, 'result': True, 'comment': '', 'changes': {}}
    kwargs = {k:v for k, v in kwargs.items() if not k.startswith('_')}
    authargs = {'region': region, 'key': key, 'keyid': keyid, 'profile': profile}
    Name = kwargs.pop('Name', name)
    Tags = kwargs.pop('Tags', None)
    DistributionConfig = kwargs.get('DistributionConfig', {})

    ## Sub-element munging on config data should go in here, before we proceed:
    #  For instance, origin access identities must be of the form
    #  `origin-access-identity/cloudfront/ID-of-origin-access-identity`, but we can't really
    #  know that ID apriori, so any OAI state names inside the config data must be resolved
    #  and converted into that format before submission.  Be aware that the `state names` of
    #  salt managed OAIs are stored in their Comment fields for lack of any better place...
    for item in range(len(DistributionConfig.get('Origins', {}).get('Items', []))):
        oai = DistributionConfig['Origins']['Items'][item].get('S3OriginConfig',
                                                   {}).get('OriginAccessIdentity', '')
        if oai and not oai.startswith('origin-access-identity/cloudfront/'):
            res = __salt__['boto_cloudfront.get_cloud_front_origin_access_identities_by_comment'](
                    Comment=oai, region=region, key=key, keyid=keyid, profile=profile)
            if res is None:  ## An error occurred, bubble it up...
                log.warning('Error encountered while trying to determine the Resource ID of'
                            ' CloudFront origin access identity `%s`.  Passing as-is.', oai)
            elif len(res) < 1:
                log.warning('Failed to determine the Resource ID of CloudFront origin access'
                            ' identity `%s`.  Passing as-is.', oai)
            elif len(res) > 1:
                log.warning('Failed to find unique Resource ID for CloudFront origin access'
                            ' identity `%s`.  Passing as-is.', oai)
            else:
                # One unique OAI resource found -- deref and replace it...
                new = 'origin-access-identity/cloudfront/{}'.format(res[0]['Id'])
                DistributionConfig['Origins']['Items'][item]['S3OriginConfig']['OriginAccessIdentity'] = new
    # Munge Name into the Comment field...
    DistributionConfig['Comment'] = '{}:{}'.format(Name, DistributionConfig['Comment']) \
            if DistributionConfig.get('Comment') else Name

    # Fix up any missing (or wrong) Quantity sub-elements...
    DistributionConfig = _fix_quantities(DistributionConfig)
    kwargs['DistributionConfig'] = DistributionConfig

    # Current state of the thing?
    res = __salt__['boto_cloudfront.get_distributions_by_comment'](Comment=Name, region=region,
            key=key, keyid=keyid, profile=profile)
    if res is None:
        msg = 'Error determining current state of distribution `{}`.'.format(Name)
        log.error(msg)
        ret['comment'] = msg
        ret['result'] = False
        return ret
    if len(res) > 1:
        msg = 'Multiple CloudFront distibutions matched `{}`.'.format(Name)
        log.error(msg)
        ret['comment'] = msg
        ret['result'] = False
        return ret

    # Luckily, the `DistributionConfig` structure returned by `get_distribution()` (as a sub-
    # element of `Distribution`) is identical to that returned by `get_distribution_config(),
    # and as a bonus, the ETag's are ALSO compatible...
    # Since "updates" are actually "replace everything from scratch" events, this implies that
    # it's enough to simply determine SOME update is necessary to trigger one, rather than
    # exhaustively calculating all changes needed - this makes life MUCH EASIER :)
    # Thus our workflow here is:
    # - check if the distribution exists
    # - if it doesn't, create it fresh with the requested DistributionConfig, and Tag it if needed
    # - if it does, grab its ETag, and TWO copies of the current DistributionConfig
    # - merge the requested DistributionConfig on top of one of them
    # - compare the copy we just merged against the one we didn't
    # - if they differ, send the merged copy, along with the ETag we got, back as an update
    # - lastly, verify and set/unset any Tags which may need changing...
    exists = bool(res)
    if not exists:
        if 'CallerReference' not in kwargs['DistributionConfig']:
            kwargs['DistributionConfig']['CallerReference'] = str(uuid.uuid4())
        if __opts__['test']:
            ret['result'] = None
            ret['comment'] = 'CloudFront distribution `{}` would be created.'.format(Name)
            new = {'DistributionConfig': kwargs['DistributionConfig']}
            new.update({'Tags': Tags}) if Tags else None
            ret['pchanges'] = {'old': None, 'new': new}
            return ret
        kwargs.update(authargs)
        comments = []
        res = __salt__['boto_cloudfront.create_distribution_v2'](**kwargs)
        if res is None:
            ret['result'] = False
            msg = 'Error occurred while creating distribution `{}`.'.format(Name)
            log.error(msg)
            ret['comment'] = msg
            return ret
        new = {'DistributionConfig': res['Distribution']['DistributionConfig']}
        comments += ['Created distribution `{}`.'.format(Name)]
        newARN = res.get('Distribution', {}).get('ARN')
        tagged = __salt__['boto_cloudfront.tag_resource'](Tags=Tags, **authargs)
        if tagged is False:
            ret['result'] = False
            msg = 'Error occurred while tagging distribution `{}`.'.format(Name)
            log.error(msg)
            comments += [msg]
            ret['comment'] = '  '.join(comments)
            return ret
        comments += ['Tagged distribution `{}`.'.format(Name)]
        new['Tags'] = Tags
        ret['comment'] = '  '.join(comments)
        ret['changes'] = {'old': None, 'new': new}
        return ret
    else:
        currentId = res[0]['Id']
        current = __salt__['boto_cloudfront.get_distribution_v2'](Id=currentId, **authargs)
        # Insanely unlikely given that we JUST got back this Id from the previous search, but....
        if not current:
            msg = 'Failed to lookup CloudFront distribution with Id `{}`.'.format(currentId)
            log.error(msg)
            ret['comment'] = msg
            ret['result'] = False
            return ret
        currentDC = current['Distribution']['DistributionConfig']
        currentARN = current['Distribution']['ARN']
        currentETag = current['ETag']
        currentTags = __salt__['boto_cloudfront.list_tags_for_resource'](Resource=currentARN,
                                                                         **authargs)
        copyOne = copy.deepcopy(currentDC)
        copyTwo = copy.deepcopy(currentDC)
        copyTwo.update(kwargs['DistributionConfig'])
        correct = salt.utils.boto3.json_objs_equal(copyOne, copyTwo)
        tags_correct = (currentTags == Tags)
        comments = []
        old = {}
        new = {}

        if correct and tags_correct:
            ret['comment'] = 'CloudFront distribution `{}` is in the correct state.'.format(Name)
            return ret
        if __opts__['test']:
            ret['result'] = None
            if not correct:
                comments += ['CloudFront distribution `{}` config would be updated.'.format(Name)]
                old['DistributionConfig'] = copyOne
                new['DistributionConfig'] = copyTwo
            if not tags_correct:
                comments += ['CloudFront distribution `{}` Tags would be updated.'.format(Name)]
                old['Tags'] = currentTags
                new['Tags'] = Tags
            ret['comment'] = '  '.join(comments)
            ret['pchanges'] = {'old': old, 'new': new}
            return ret
        if not correct:
            kwargs = {'DistributionConfig': copyTwo, 'Id': currentId, 'IfMatch': currentETag}
            kwargs.update(authargs)
            log.debug('Calling `boto_cloudfront.update_distribution_v2()` with **kwargs =='
                      ' %s', kwargs)
            res = __salt__['boto_cloudfront.update_distribution_v2'](**kwargs)
            if res is None:
                ret['result'] = False
                msg = 'Error occurred while updating distribution `{}`.'.format(Name)
                log.error(msg)
                ret['comment'] = msg
                return ret
            old['DistributionConfig'] = copyOne
            new['DistributionConfig'] = res['Distribution']['DistributionConfig']
            comments += ['CloudFront distribution `{}` config updated.'.format(Name)]
        if not tags_correct:
            tagged = __salt__['boto_cloudfront.enforce_tags'](Resource=currentARN, Tags=Tags,
                    **authargs)
            if tagged is False:
                ret['result'] = False
                msg = 'Error occurred while updating Tags on distribution `{}`.'.format(Name)
                log.error(msg)
                comments += [msg]
                ret['comment'] = '  '.join(comments)
                return ret
            comments += ['CloudFront distribution `{}` Tags updated.'.format(Name)]
            old['Tags'] = currentTags
            new['Tags'] = Tags
        ret['comment'] = '  '.join(comments)
        ret['changes'] = {'old': old, 'new': new}
        return ret


def route53_alias_present(name, region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Ensure a Route53 Alias exists and is pointing at the given CloudFront distribution.
    An `A` record is always created, and if IPV6 is enabled on the given distribution, an
    `AAAA` record will be created as well.  Also be aware that Alias records for CloudFront
    distributions are only permitted in non-private zones.

    name
        The name of the state definition.

    Distribution
        The name of the CloudFront distribution.  Defaults to the value of `name` if not provided.

    HostedZoneId
        Id of the Route53 hosted zone within which the records should be created.

    DomainName
        The domain name associated with the Hosted Zone.  Exclusive with HostedZoneId.

    ResourceRecordSet
        A Route53 Record Set (with AliasTarget section, suitable for use as an `Alias` record,
        if non-default settings are needed on the Alias) which should be pointed at the provided
        CloudFront distribution.  Note that this MUST correlate with the Aliases set within the
        DistributionConfig section of the distribution.

        Some notes SPECIFICALLY about the `AliasTarget` subsection of the ResourceRecordSet:
        - If not specified, the `DNSName` sub-field will be populated by dereferencing
          `Distribution` above to the value of its `DomainName` attribute.
        - The HostedZoneId sub-field should not be provided -- it will be automatically
          populated with a `magic` AWS value.
        - The EvaluateTargetHealth can only be False on a CloudFront Alias.
        - The above items taken all together imply that, for most use-cases, the AliasTarget
          sub-section can be entirely omitted, as seen in the first code sample below.

        Lastly, note that if you set `name` to the desired ResourceRecordSet Name, you can
        entirely omit this parameter, as shown in the second example below.

    .. code-block:: yaml

        Add a Route53 Alias for my_distribution:
          boto_cloudfront.present:
          - Distribution: my_distribution
          - DomainName: saltstack.org.
          - ResourceRecordSet:
              Name: the-alias.saltstack.org.
        # This is even simpler - it uses the value of `name` for ResourceRecordSet.Name
        another-alias.saltstack.org.:
          boto_cloudfront.present:
          - Distribution: my_distribution
          - DomainName: saltstack.org.
    '''
    MAGIC_CLOUDFRONT_HOSTED_ZONEID = 'Z2FDTNDATAQYW2'
    ret = {'name': name, 'result': True, 'comment': '', 'changes': {}}
    Distribution = kwargs['Distribution'] if 'Distribution' in kwargs else name
    ResourceRecordSet = kwargs.get('ResourceRecordSet', {})
    Name = ResourceRecordSet.get('Name', name)
    ResourceRecordSet['Name'] = Name

    res = __salt__['boto_cloudfront.get_distributions_by_comment'](Comment=Distribution,
            region=region, key=key, keyid=keyid, profile=profile)
    if res is None:
        msg = 'Error resolving CloudFront distribution `{}` to a Resource ID.'.format(Distribution)
        log.error(msg)
        ret['comment'] = msg
        ret['result'] = False
        return ret
    if len(res) > 1:
        msg = 'Multiple CloudFront distibutions matched `{}`.'.format(Distribution)
        log.error(msg)
        ret['comment'] = msg
        ret['result'] = False
        return ret
    if len(res) < 1:
        msg = 'No CloudFront distibutions matching `{}` found.'.format(Distribution)
        log.error(msg)
        ret['comment'] = msg
        ret['result'] = False
        return ret
    dist = res[0]

    Types = ('A', 'AAAA') if dist.get('IsIPV6Enabled', False) else ('A',)
    DNSName = dist.get('DomainName', '')
    Aliases = dist.get('Aliases', {}).get('Items', [])
    # AWS annoyance #437:
    #   Route53 "FQDNs" (correctly!) REQUIRE trailing periods...
    #   while CloudFront "FQDNs" don't PERMIT trailing periods...
    Aliases += [(a if a.endswith('.') else '{}.'.format(a)) for a in Aliases]
    if Name not in Aliases:
        msg = ('Route53 alias `{}` requested which is not mirrored in the `Aliases`'
              ' sub-section of the DistributionConfig.'.format(Name))
        log.error(msg)
        ret['comment'] = msg
        ret['result'] = False
        return ret

    changes = {'old': [], 'new': []}
    comments = []
    # Now mock out a route53 state def, and use the route53 rr_exists state to enforce it...
    AliasTarget = ResourceRecordSet.get('AliasTarget', {})
    AliasTarget['DNSName'] = AliasTarget['DNSName'] if 'DNSName' in AliasTarget else DNSName
    AliasTarget['DNSName'] += '' if AliasTarget['DNSName'].endswith('.') else '.'  # GRRRR!
    AliasTarget['HostedZoneId'] = MAGIC_CLOUDFRONT_HOSTED_ZONEID
    AliasTarget['EvaluateTargetHealth'] = False   # Route53 limitation
    ResourceRecordSet['name'] = Name
    ResourceRecordSet['AliasTarget'] = AliasTarget
    ResourceRecordSet['PrivateZone'] = False      # Route53 limitation
    ResourceRecordSet['DomainName'] = kwargs.get('DomainName')
    ResourceRecordSet['HostedZoneId'] = kwargs.get('HostedZoneId')
    ResourceRecordSet.update({'region': region, 'key': key, 'keyid': keyid, 'profile': profile})
    for Type in Types:
        ResourceRecordSet['Type'] = Type
        # Checking for `test=True` will occur in the called state....
        log.debug('Calling state function `boto3_route53.rr_present()` with args:  `%s`',
                ResourceRecordSet)
        res = __states__['boto3_route53.rr_present'](**ResourceRecordSet)
        ret['result'] = res['result']
        comments += [res['comment']]
        if ret['result'] not in (True, None):
            break
        changes['old'] += [res['changes']['old']] if res['changes'].get('old') else []
        changes['new'] += [res['changes']['new']] if res['changes'].get('new') else []
    ret['changes'].update({'old': changes['old']}) if changes.get('old') else None
    ret['changes'].update({'new': changes['new']}) if changes.get('new') else None
    ret['comment'] = '  '.join(comments)
    return ret


def distribution_absent(name, region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Ensure a distribution with the given Name tag does not exist.

    Note that CloudFront does not allow directly deleting an enabled Distribution.  If such
    is requested, Salt will attempt to first update the distribution's status to Disabled,
    and once that returns success, to then delete the resource.  THIS CAN TAKE SOME TIME, so
    be patient :)

    name (string)
        Name of the state definition.

    Name (string)
        Name of the CloudFront distribution to be managed.  If not provided, the value of `name`
        will be used as a default.  The purpose of this parameter is only to resolve it to a
        Resource ID, so be aware that an explicit value for `Id` below will override any value
        provided, or defaulted, here.

    Id (string)
        The Resource ID of a CloudFront distribution to be managed.

    region (string)
        Region to connect to

    key (string)
        Secret key to use

    keyid (string)
        Access key to use

    profile (dict or string)
        Dict, or pillar key pointing to a dict, containing AWS region/key/keyid.

    Example:

    .. code-block:: yaml

        Ensure a distribution named my_distribution is gone:
          boto_cloudfront.distribution_absent:
          - Name: my_distribution
    '''
    Name = kwargs['Name'] if 'Name' in kwargs else name
    Id = kwargs.get('Id')
    ref = kwargs['Id'] if 'Id' in kwargs else Name
    ret = {'name': Id if Id else Name, 'comment': '', 'changes': {}, 'result': True}
    authargs = {'region': region, 'key': key, 'keyid': keyid, 'profile': profile}
    if not Id:
        res = __salt__['boto_cloudfront.get_distributions_by_comment'](Comment=Name, **authargs)
        if res is None:
            msg = 'Error dereferencing CloudFront distribution `{}` to a Resource ID.'.format(Name)
            log.error(msg)
            ret['comment'] = msg
            ret['result'] = False
            return ret
        if len(res) > 1:
            msg = ('Multiple CloudFront distibutions matched `{}`, no way to know which to'
                   ' delete.`.'.format(Name))
            log.error(msg)
            ret['comment'] = msg
            ret['result'] = False
            return ret
        if len(res) < 1:
            msg = 'CloudFront Distribution `{}` already absent.'.format(Name)
            log.info(msg)
            ret['comment'] = msg
            ret['result'] = True
            return ret
        Id = res[0]['Id']

    if not __salt__['boto_cloudfront.distribution_exists'](Id=Id, **authargs):
        msg = 'CloudFront distribution `{}` already absent.'.format(ref)
        log.info(msg)
        ret['comment'] = msg
        return ret

    old = __salt__['boto_cloudfront.get_distribution_v2'](Id=Id, **authargs)
    if old is None:
        ret['result'] = False
        msg = 'Error getting state of CloudFront distribution `{}`.'.format(ref)
        log.error(msg)
        ret['comment'] = msg
        return ret
    currETag = old['ETag']

    Enabled = old['DistributionConfig']['Enabled']
    if __opts__['test']:
        ret['result'] = None
        ret['comment'] = 'CloudFront distribution `{}` would be {}deleted.'.format(ref,
                ('disabled and ' if Enabled else ''))
        ret['pchanges'] = {'old': old, 'new': None}
        return ret

    comments = []
    if Enabled:
        disabled = __salt__['boto_cloudfront.disable_distribution'](Id=Id, **authargs)
        if disabled is None:
            ret['result'] = False
            msg = 'Error disabling CloudFront distribution `{}`'.format(ref)
            log.error(msg)
            ret['comment'] = msg
            return ret
        comments += ['CloudFront distribution `{}` disabled.'.format(ref)]
        currETag = disabled['ETag']
    deleted = __salt__['boto_cloudfront.delete_distribution'](Id=Id, IfMatch=currETag, **authargs)
    if deleted is False:
        ret['result'] = False
        msg = 'Error deleting CloudFront distribution `{}`'.format(ref)
        comments += [msg]
        log.error(msg)
        ret['comment'] = '  '.join(comments)
        return ret
    msg = 'CloudFront distribution `{}` deleted.'.format(ref)
    comments += [msg]
    log.info(msg)
    ret['comment'] = '  '.join(comments)
    ret['changes'] = {'old': old, 'new': None}
    return ret


def origin_access_identity_present(name, region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Ensure a given CloudFront Origin Access Identity exists.

    Implementation Note:  Due to the unavailibity of ANY other way to store stateful idempotency
    information about Origin Access Identities (including resource tags), the Comment attribute (as
    the only user-settable attribute without weird self-blocking semantics) is necessarily utilized
    to store the Salt `name` value, which is used to determine resource existence and state.  That
    said, to enable SOME usability of this field, only the value up to the first colon character
    is taken as the `name` attribute, while anything afterward is free-form and ignored by Salt.

    name (string)
        Name of the state definition.

    Name (string)
        Name of the resource (for purposes of Salt's idempotency).  If not provided, the value of
        `name` will be used.

    Comment
        Free-form text description of the origin access identity.

    region (string)
        Region to connect to

    key (string)
        Secret key to use

    keyid (string)
        Access key to use

    profile (dict or string)
        Dict, or pillar key pointing to a dict, containing AWS region/key/keyid.

    Example:

    .. code-block:: yaml

        my_OAI:
          boto_cloudfront.origin_access_identity_present:
          - Comment: Simply ensures an OAI named my_OAI exists
    '''
    ret = {'name': name, 'result': True, 'comment': '', 'changes': {}}
    kwargs = {k:v for k, v in kwargs.items() if not k.startswith('_')}
    authargs = {'region': region, 'key': key, 'keyid': keyid, 'profile': profile}
    Name = kwargs.get('Name', name)
    # Munge Name into the Comment field...
    Comment = '{}:{}'.format(Name, Comment) if kwargs.get('Comment') else Name

    # Current state of the thing?
    res = __salt__['boto_cloudfront.get_cloud_front_origin_access_identities_by_comment'](
            Comment=Name, region=region, key=key, keyid=keyid, profile=profile)
    if res is None:
        msg = 'Error determining current state of origin access identity `{}`.'.format(Name)
        log.error(msg)
        ret['comment'] = msg
        ret['result'] = False
        return ret
    if len(res) > 1:
        msg = 'Multiple CloudFront origin access identities matched `{}`.'.format(Name)
        log.error(msg)
        ret['comment'] = msg
        ret['result'] = False
        return ret

    exists = bool(res)
    if not exists:
        CloudFrontOriginAccessIdentityConfig = {'Comment': Comment,
                                                'CallerReference': str(uuid.uuid4())}
        if __opts__['test']:
            ret['result'] = None
            ret['comment'] = 'CloudFront origin access identity `{}` would be created.'.format(Name)
            new = {'CloudFrontOriginAccessIdentityConfig': CloudFrontOriginAccessIdentityConfig}
            ret['pchanges'] = {'old': None, 'new': new}
            return ret
        kwargs = {'CloudFrontOriginAccessIdentityConfig': CloudFrontOriginAccessIdentityConfig}
        kwargs.update(authargs)
        res = __salt__['boto_cloudfront.create_cloud_front_origin_access_identity'](**kwargs)
        if res is None:
            ret['result'] = False
            msg = 'Failed to create CloudFront origin access identity `{}`.'.format(Name)
            log.error(msg)
            ret['comment'] = msg
            return ret
        ret['comment'] = 'Created CloudFrong origin access identity`{}`.'.format(Name)
        ret['changes'] = {'old': None, 'new': res}
        return ret
    else:
        currentId = res[0]['Id']
        current = __salt__['boto_cloudfront.get_cloud_front_origin_access_identity'](Id=currentId,
                **authargs)
        currentETag = current['ETag']
        currentOAIC = current['CloudFrontOriginAccessIdentity']['CloudFrontOriginAccessIdentityConfig']
        new = copy.deepcopy(currentOAIC)
        new.update({'Comment': Comment})  ## Currently the only updatable element :-/
        if currentOAIC == new:
            msg = 'CloudFront origin access identity `{}` is in the correct state.'.format(Name)
            log.info(msg)
            ret['comment'] = msg
            return ret
        if __opts__['test']:
            ret['result'] = None
            ret['comment'] = 'CloudFront origin access identity `{}` would be updated.'.format(Name)
            ret['pchanges'] = {'old': currentOAIC, 'new': new}
            return ret
        kwargs = {'CloudFrontOriginAccessIdentityConfig': new,
                  'Id': currentId, 'IfMatch': currentETag}
        kwargs.update(authargs)
        res = __salt__['boto_cloudfront.update_cloud_front_origin_access_identity'](**kwargs)
        if res is None:
            ret['result'] = False
            msg = 'Error occurred while updating origin access identity `{}`.'.format(Name)
            log.error(msg)
            ret['comment'] = msg
            return ret
        ret['comment'] = 'CloudFront origin access identity `{}` config updated.'.format(Name)
        ret['changes'] = {'old': currentOAIC, 'new': new}
        return ret


def origin_access_identity_absent(name, region=None, key=None, keyid=None, profile=None, **kwargs):
    '''
    Ensure a given CloudFront Origin Access Identity is absent.

    Implementation Note:  Due to the unavailibity of ANY other way to store stateful idempotency
    information about Origin Access Identities (including resource tags), the Comment field (as
    the only user-settable attribute without weird self-blocking semantics) is necessarily utilized
    to store the Salt `Name` value, used to determine resource existence and state.  That said,
    to enable SOME usability of this field, only the value up to the first colon character
    is taken as the `Name` attribute, while anything afterward is free-form and ignored by Salt.

    name
        The name of the state definition.

    Name (string)
        Name of the resource (for purposes of Salt's idempotency).  If not provided, the value of
        `name` will be used.

    Id (string)
        The Resource ID of a CloudFront origin access identity to be managed.

    region (string)
        Region to connect to

    key (string)
        Secret key to use

    keyid (string)
        Access key to use

    profile (dict or string)
        Dict, or pillar key pointing to a dict, containing AWS region/key/keyid.

    Example:

    .. code-block:: yaml

        Ensure an origin access identity named my_OAI is gone:
          boto_cloudfront.origin_access_identity_absent:
          - Name: my_distribution
    '''
    Name = kwargs['Name'] if 'Name' in kwargs else name
    Id = kwargs.get('Id')
    ref = kwargs['Id'] if 'Id' in kwargs else Name
    ret = {'name': Id if Id else Name, 'comment': '', 'changes': {}, 'result': True}
    authargs = {'region': region, 'key': key, 'keyid': keyid, 'profile': profile}
    current = None
    if not Id:
        current = __salt__['boto_cloudfront.get_cloud_front_origin_access_identities_by_comment'](
                Comment=Name, **authargs)
        if res is None:
            msg = 'Error dereferencing origin access identity `{}` to a Resource ID.'.format(Name)
            log.error(msg)
            ret['comment'] = msg
            ret['result'] = False
            return ret
        if len(res) > 1:
            msg = ('Multiple CloudFront origin access identities matched `{}`, no way to know'
                   ' which to delete.`.'.format(Name))
            log.error(msg)
            ret['comment'] = msg
            ret['result'] = False
            return ret
        if len(res) < 1:
            msg = 'CloudFront origin access identity `{}` already absent.'.format(Name)
            log.info(msg)
            ret['comment'] = msg
            ret['result'] = True
            return ret
        Id = res[0]['Id']

    if not __salt__['boto_cloudfront.cloud_front_origin_access_identity_exists'](Id=Id, **authargs):
        msg = 'CloudFront origin access identity `{}` already absent.'.format(ref)
        log.info(msg)
        ret['comment'] = msg
        return ret

    old = __salt__['boto_cloudfront.get_cloud_front_origin_access_identity'](Id=Id, **authargs)
    if old is None:
        ret['result'] = False
        msg = 'Error getting state of CloudFront origin access identity `{}`.'.format(ref)
        log.error(msg)
        ret['comment'] = msg
        return ret

    if __opts__['test']:
        ret['result'] = None
        ret['comment'] = 'CloudFront origin access identity `{}` would be deleted.'.format(ref)
        ret['pchanges'] = {'old': old, 'new': None}
        return ret

    deleted = __salt__['boto_cloudfront.delete_cloud_front_origin_access_identity'](Id=Id,
            IfMatch=old['ETag'], **authargs)
    if deleted is False:
        ret['result'] = False
        msg = 'Error deleting CloudFront origin access identity `{}`'.format(ref)
        log.error(msg)
        ret['comment'] = msg
        return ret
    msg = 'CloudFront origin access identity `{}` deleted.'.format(ref)
    log.info(msg)
    ret['comment'] = msg
    ret['changes'] = {'old': old, 'new': None}
    return ret
