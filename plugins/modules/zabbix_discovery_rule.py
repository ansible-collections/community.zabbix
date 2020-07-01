#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Tobias Birkefeld (@tcraxs) <t@craxs.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: zabbix_discovery_rule
short_description: Create/delete/update Zabbix discovery rules
description:
   - Create discovery rule.
   - Delete existing discovery rule.
   - Update existing discovery rule with new options.
author:
    - "Tobias Birkefeld (@tcraxs)"
requirements:
    - "zabbix-api >= 0.5.4"
options:
    state:
        description:
            - Create or delete user group.
        type: str
        default: "present"
        choices: [ "present", "absent" ]
    name:
        description:
            - Name of the discovery rule.
        required: true
        type: str
    iprange:
        description:
            - One or several IP ranges to check separated by commas.
        type: list
        elements: str
    dchecks:
        description:
            - List of dictionaries of discovery check objects.
            - For more information, review discovery check object documentation at
              U(https://www.zabbix.com/documentation/current/manual/api/reference/dcheck/object)
        suboptions:
            type:
                description:
                    - Type of check.
                type: str
                choices: ['SSH',
                          'LDAP',
                          'SMTP',
                          'FTP',
                          'HTTP',
                          'POP',
                          'NNTP',
                          'IMAP',
                          'TCP',
                          'Zabbix',
                          'SNMPv1',
                          'SNMPv2',
                          'ICMP',
                          'SNMPv3',
                          'HTTPS',
                          'Telnet']
            ports:
                description:
                    - One or several port ranges to check separated by commas. Used for all checks except for ICMP.
                type: str
            key:
                description:
                    - "The value of this property differs depending on the type of the check:"
                    - "- key to query for Zabbix agent checks"
                    - "- SNMP OID for SNMPv1, SNMPv2 and SNMPv3 checks"
                type: str
            snmp_community:
                description:
                    - SNMP community.
                    - Required for SNMPv1 and SNMPv2 agent checks.
                type: str
            snmpv3_authpassphrase:
                description:
                    - Authentication passphrase used for SNMPv3 agent checks with security level set to authNoPriv or authPriv.
                type: str
            snmpv3_authprotocol:
                description:
                    - Authentication protocol used for SNMPv3 agent checks with security level set to authNoPriv or authPriv.
                    - "Possible values:"
                    - MD5
                    - SHA
                type: str
                choices: ["MD5", "SHA"]
            snmpv3_contextname:
                description:
                    - SNMPv3 context name. Used only by SNMPv3 checks.
                type: str
            snmpv3_privpassphrase:
                description:
                    - Privacy passphrase used for SNMPv3 agent checks with security level set to authPriv.
                type: str
            snmpv3_privprotocol:
                description:
                    - Privacy protocol used for SNMPv3 agent checks with security level set to authPriv.
                    - "Possible values:"
                    - DES
                    - AES
                type: str
                choices: ["DES", "AES"]
            snmpv3_securitylevel:
                description:
                    - Security level used for SNMPv3 agent checks.
                    - "Possible values:"
                    - noAuthNoPriv
                    - authNoPriv
                    - authPriv
                type: str
                choices: ["noAuthNoPriv", "authNoPriv", "authPriv"]
            snmpv3_securityname:
                description:
                    - Security name used for SNMPv3 agent checks.
                type: str
            uniq:
                description:
                    - Whether to use this check as a device uniqueness criteria.
                    - Only a single unique check can be configured for a discovery rule.
                    - Used for Zabbix agent, SNMPv1, SNMPv2 and SNMPv3 agent checks.
                    - "Possible values:"
                    - "no - (default) do not use this check as a uniqueness criteria"
                    - "yes - use this check as a uniqueness criteria"
                type: bool
                default: no
            host_source:
                description:
                    - Source for host name.
                    - "Possible values:"
                    - "DNS (default)"
                    - "IP"
                    - "discovery - discovery value of this check"
                    - Options is available since Zabbix 4.4
                type: str
                default: "DNS"
                choices: ["DNS", "IP", "discovery"]
            name_source:
                description:
                    - Source for visible name.
                    - "Possible values:"
                    - "none - (default) not specified"
                    - "DNS"
                    - "IP"
                    - "discovery - discovery value of this check"
                    - Options is available since Zabbix 4.4
                type: str
                default: "None"
                choices: ["None", "DNS", "IP", "discovery"]
        type: list
        elements: dict
        aliases: [ "dcheck" ]
    delay:
        description:
            - Execution interval of the discovery rule.
            - Accepts seconds, time unit with suffix and user macro.
        type: str
        default: "1h"
    proxy:
        description:
            - Name of the proxy used for discovery.
        type: str
    status:
        description:
            - Whether the discovery rule is enabled.
            - "Possible values:"
            - enabled (default)
            - disabled
        type: str
        default: "enabled"
        choices: ["enabled", "disabled"]
notes:
    - Only Zabbix >= 4.0 is supported.
extends_documentation_fragment:
    - community.zabbix.zabbix
'''

EXAMPLES = r'''
# Base create discovery rule example
- name: Create discovery rule with ICMP and zabbix agent checks
  zabbix_discovery_rule:
    server_url: "http://zabbix.example.com/zabbix/"
    login_user: admin
    login_password: secret
    name: ACME
    state: present
    iprange: 192.168.1.1-255
    dchecks:
        - type: ICMP
        - type: Zabbix
          key: "system.hostname"
          ports: 10050
          uniq: yes
          host_source: "discovery"

# Base update (add new dcheck) discovery rule example
- name: Create discovery rule with ICMP and zabbix agent checks
  zabbix_discovery_rule:
    server_url: "http://zabbix.example.com/zabbix/"
    login_user: admin
    login_password: secret
    name: ACME
    state: present
    iprange: 192.168.1.1-255
    dchecks:
        - type: SNMPv3
          snmp_community: CUSTOMER@snmp3-readonly
          ports: "161"
          key: iso.3.6.1.2.1.1.1.0
          snmpv3_contextname: "ContextName"
          snmpv3_securityname: "SecurityName"
          snmpv3_securitylevel: "authPriv"
          snmpv3_authprotocol: "SHA"
          snmpv3_authpassphrase: "SeCrEt"
          snmpv3_privprotocol: "AES"
          snmpv3_privpassphrase: "TopSecret"
          uniq: no
          host_source: "DNS"
          name_source: "None"

# Base delete discovery rule example
- name: Delete discovery rule
  zabbix_discovery_rule:
    server_url: "http://zabbix.example.com/zabbix/"
    login_user: admin
    login_password: secret
    name: ACME
    state: absent
'''


import atexit
import traceback

try:
    from zabbix_api import ZabbixAPI
    from zabbix_api import Already_Exists

    HAS_ZABBIX_API = True
except ImportError:
    ZBX_IMP_ERR = traceback.format_exc()
    HAS_ZABBIX_API = False

from distutils.version import LooseVersion
from ansible.module_utils.basic import AnsibleModule, missing_required_lib


class Zapi(object):
    """
    A simple wrapper over the Zabbix API
    """
    def __init__(self, module, zbx):
        self._module = module
        self._zapi = zbx
        self._zbx_api_version = zbx.api_version()[:5]

    def check_if_drule_exists(self, name):
        """Check if discovery rule exists.
        Args:
            name: Name of the discovery rule.
        Returns:
            The return value. True for success, False otherwise.
        """
        try:
            _drule = self._zapi.drule.get({
                'output': 'extend',
                'selectDChecks': 'extend',
                'filter': {'name': [name]}
            })
            if len(_drule) > 0:
                return _drule
        except Exception as e:
            self._module.fail_json(msg="Failed to check if discovery rule '%s' exists: %s"
                                       % (name, e))

    def get_drule_by_drule_name(self, name):
        """Get discovery rule by discovery rule name
        Args:
            name: discovery rule name.
        Returns:
            discovery rule matching discovery rule name
        """
        try:
            drule_list = self._zapi.drule.get({
                'output': 'extend',
                'selectDChecks': 'extend',
                'filter': {'name': [name]}
            })
            if len(drule_list) < 1:
                self._module.fail_json(msg="Discovery rule not found: %s" % name)
            else:
                return drule_list[0]
        except Exception as e:
            self._module.fail_json(msg="Failed to get discovery rule '%s': %s" % (name, e))

    def get_proxy_by_proxy_name(self, proxy_name):
        """Get proxy by proxy name
        Args:
            proxy_name: proxy name.
        Returns:
            proxy matching proxy name
        """
        try:
            proxy_list = self._zapi.proxy.get({
                'output': 'extend',
                'selectInterface': 'extend',
                'filter': {'host': [proxy_name]}
            })
            if len(proxy_list) < 1:
                self._module.fail_json(msg="Proxy not found: %s" % proxy_name)
            else:
                return proxy_list[0]
        except Exception as e:
            self._module.fail_json(msg="Failed to get proxy '%s': %s" % (proxy_name, e))


class Dchecks(object):
    """
    Restructures the user defined discovery checks to fit the Zabbix API requirements
    """
    def __init__(self, module, zbx):
        self._module = module
        self._zapi = zbx
        self._zbx_api_version = zbx.api_version()[:5]

    def construct_the_data(self, _dchecks):
        """Construct the user defined discovery check to fit the Zabbix API
        requirements
        Args:
            _dchecks: discovery checks to construct
        Returns:
            dict: user defined discovery checks
        """
        if _dchecks is None:
            return None
        constructed_data = []
        for check in _dchecks:
            constructed_check = {
                'type': to_numeric_value([
                    'SSH',
                    'LDAP',
                    'SMTP',
                    'FTP',
                    'HTTP',
                    'POP',
                    'NNTP',
                    'IMAP',
                    'TCP',
                    'Zabbix',
                    'SNMPv1',
                    'SNMPv2',
                    'ICMP',
                    'SNMPv3',
                    'HTTPS',
                    'Telnet'], check.get('type')
                ),
                'uniq': int(check.get('uniq'))
            }
            if LooseVersion(self._zbx_api_version) >= LooseVersion('4.4'):
                constructed_check.update({
                    'host_source': to_numeric_value([
                        'None',
                        'DNS',
                        'IP',
                        'discovery'], check.get('host_source')
                    ),
                    'name_source': to_numeric_value([
                        'None',
                        'DNS',
                        'IP',
                        'discovery'], check.get('name_source')
                    )
                })
            if constructed_check['type'] in (0, 1, 2, 3, 4, 5, 6, 7, 8, 14, 15):
                constructed_check['ports'] = check.get('ports')
            if constructed_check['type'] == 9:
                constructed_check['ports'] = check.get('ports')
                constructed_check['key_'] = check.get('key')
            if constructed_check['type'] in (10, 11):
                constructed_check['ports'] = check.get('ports')
                constructed_check['snmp_community'] = check.get('snmp_community')
                constructed_check['key_'] = check.get('key')
            if constructed_check['type'] == 13:
                constructed_check['ports'] = check.get('ports')
                constructed_check['key_'] = check.get('key')
                constructed_check['snmpv3_contextname'] = check.get('snmpv3_contextname')
                constructed_check['snmpv3_securityname'] = check.get('snmpv3_securityname')
                constructed_check['snmpv3_securitylevel'] = to_numeric_value([
                    'noAuthNoPriv',
                    'authNoPriv',
                    'authPriv'], check.get('snmpv3_securitylevel')
                )
                if constructed_check['snmpv3_securitylevel'] in (1, 2):
                    constructed_check['snmpv3_authprotocol'] = to_numeric_value([
                        'MD5',
                        'SHA'], check.get('snmpv3_authprotocol')
                    )
                    constructed_check['snmpv3_authpassphrase'] = check.get('snmpv3_authpassphrase')
                if constructed_check['snmpv3_securitylevel'] == 2:
                    constructed_check['snmpv3_privprotocol'] = to_numeric_value([
                        'DES',
                        'AES'], check.get('snmpv3_privprotocol')
                    )
                    constructed_check['snmpv3_privpassphrase'] = check.get('snmpv3_privpassphrase')
            constructed_data.append(constructed_check)
        return cleanup_data(constructed_data)


class DiscoveryRule(object):
    def __init__(self, module, zbx, zapi_wrapper):
        self._module = module
        self._zapi = zbx
        self._zapi_wrapper = zapi_wrapper

    def _construct_parameters(self, **kwargs):
        """Construct parameters.
        Args:
            **kwargs: Arbitrary keyword parameters.
        Returns:
            dict: dictionary of specified parameters
        """
        _params = {
            'name': kwargs['name'],
            'iprange': ','.join(kwargs['iprange']),
            'delay': kwargs['delay'],
            'status': to_numeric_value([
                'enabled',
                'disabled'], kwargs['status']
            ),
            'dchecks': kwargs['dchecks']
        }
        if kwargs['proxy']:
            _params['proxy_hostid'] = self._zapi_wrapper.get_proxy_by_proxy_name(kwargs['proxy'])['proxyid']
        return _params

    def check_difference(self, **kwargs):
        """Check difference between discovery rule and user specified parameters.
        Args:
            **kwargs: Arbitrary keyword parameters.
        Returns:
            dict: dictionary of differences
        """
        existing_drule = convert_unicode_to_str(self._zapi_wrapper.check_if_drule_exists(kwargs['name'])[0])
        parameters = convert_unicode_to_str(self._construct_parameters(**kwargs))
        change_parameters = {}
        if existing_drule['nextcheck']:
            existing_drule.pop('nextcheck')
        _diff = cleanup_data(compare_dictionaries(parameters, existing_drule, change_parameters))
        return _diff

    def update_drule(self, **kwargs):
        """Update discovery rule.
        Args:
            **kwargs: Arbitrary keyword parameters.
        Returns:
            drule: updated discovery rule
        """
        try:
            if self._module.check_mode:
                self._module.exit_json(msg="Discovery rule would be updated if check mode was not specified: %s" % kwargs['name'], changed=True)
            kwargs['druleid'] = kwargs.pop('drule_id')
            return self._zapi.drule.update(kwargs)
        except Exception as e:
            self._module.fail_json(msg="Failed to update discovery rule '%s': %s" % (kwargs['druleid'], e))

    def add_drule(self, **kwargs):
        """Add discovery rule
        Args:
            **kwargs: Arbitrary keyword parameters
        Returns:
            drule: created discovery rule
        """
        try:
            if self._module.check_mode:
                self._module.exit_json(msg="Discovery rule would be added if check mode was not specified", changed=True)
            parameters = self._construct_parameters(**kwargs)
            drule_list = self._zapi.drule.create(parameters)
            return drule_list['druleids'][0]
        except Exception as e:
            self._module.fail_json(msg="Failed to create discovery rule %s: %s" % (kwargs['name'], e))

    def delete_drule(self, drule_id):
        """Delete discovery rule.
        Args:
            drule_id: Discovery rule id
        Returns:
            drule: deleted discovery rule
        """
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True, msg="Discovery rule would be deleted if check mode was not specified")
            return self._zapi.drule.delete([drule_id])
        except Exception as e:
            self._module.fail_json(msg="Failed to delete discovery rule '%s': %s" % (drule_id, e))


def convert_unicode_to_str(data):
    """Converts unicode objects to strings in dictionary
    args:
        data: unicode object
    Returns:
        dict: strings in dictionary
    """
    if isinstance(data, dict):
        return dict(map(convert_unicode_to_str, data.items()))
    elif isinstance(data, (list, tuple, set)):
        return type(data)(map(convert_unicode_to_str, data))
    elif data is None:
        return data
    else:
        return str(data)


def compare_lists(l1, l2, diff_dict):
    """
    Compares l1 and l2 lists and adds the items that are different
    to the diff_dict dictionary.
    Used in recursion with compare_dictionaries() function.
    Args:
        l1: first list to compare
        l2: second list to compare
        diff_dict: dictionary to store the difference
    Returns:
        dict: items that are different
    """
    if len(l1) != len(l2):
        diff_dict.append(l1)
        return diff_dict
    for i, item in enumerate(l1):
        if isinstance(item, dict):
            diff_dict.insert(i, {})
            diff_dict[i] = compare_dictionaries(item, l2[i], diff_dict[i])
        else:
            if item != l2[i]:
                diff_dict.append(item)
    while {} in diff_dict:
        diff_dict.remove({})
    return diff_dict


def compare_dictionaries(d1, d2, diff_dict):
    """
    Compares d1 and d2 dictionaries and adds the items that are different
    to the diff_dict dictionary.
    Used in recursion with compare_lists() function.
    Args:
        d1: first dictionary to compare
        d2: second dictionary to compare
        diff_dict: dictionary to store the difference
    Returns:
        dict: items that are different
    """
    for k, v in d1.items():
        if k not in d2:
            diff_dict[k] = v
            continue
        if isinstance(v, dict):
            diff_dict[k] = {}
            compare_dictionaries(v, d2[k], diff_dict[k])
            if diff_dict[k] == {}:
                del diff_dict[k]
            else:
                diff_dict[k] = v
        elif isinstance(v, list):
            diff_dict[k] = []
            compare_lists(v, d2[k], diff_dict[k])
            if diff_dict[k] == []:
                del diff_dict[k]
            else:
                diff_dict[k] = v
        else:
            if v != d2[k]:
                diff_dict[k] = v
    return diff_dict


def cleanup_data(obj):
    """Removes the None values from the object and returns the object
    Args:
        obj: object to cleanup
    Returns:
       object: cleaned object
    """
    if isinstance(obj, (list, tuple, set)):
        return type(obj)(cleanup_data(x) for x in obj if x is not None)
    elif isinstance(obj, dict):
        return type(obj)((cleanup_data(k), cleanup_data(v))
                         for k, v in obj.items() if k is not None and v is not None)
    else:
        return obj


def to_numeric_value(strs, value):
    """Converts string values to integers
    Args:
        value: string value
    Returns:
        int: converted integer
    """
    strs = [s.lower() if isinstance(s, str) else s for s in strs]
    value = value.lower()
    tmp_dict = dict(zip(strs, list(range(len(strs)))))
    return tmp_dict[value]


def main():
    module = AnsibleModule(
        argument_spec=dict(
            server_url=dict(type='str', required=True, aliases=['url']),
            login_user=dict(type='str', required=True),
            login_password=dict(type='str', required=True, no_log=True),
            http_login_user=dict(type='str', required=False, default=None),
            http_login_password=dict(type='str', required=False, default=None, no_log=True),
            timeout=dict(type='int', default=10),
            validate_certs=dict(type='bool', required=False, default=True),
            state=dict(type='str', default='present', choices=['present', 'absent']),
            name=dict(type='str', required=True),
            iprange=dict(type='list', required=False, elements='str'),
            dchecks=dict(
                type='list',
                required=False,
                aliases=['dcheck'],
                elements='dict',
                options=dict(
                    type=dict(type='str', choices=[
                        'SSH',
                        'LDAP',
                        'SMTP',
                        'FTP',
                        'HTTP',
                        'POP',
                        'NNTP',
                        'IMAP',
                        'TCP',
                        'Zabbix',
                        'SNMPv1',
                        'SNMPv2',
                        'ICMP',
                        'SNMPv3',
                        'HTTPS',
                        'Telnet']
                    ),
                    ports=dict(type='str'),
                    key=dict(type='str'),
                    snmp_community=dict(type='str'),
                    snmpv3_authpassphrase=dict(type='str'),
                    snmpv3_authprotocol=dict(type='str', choices=['MD5', 'SHA']),
                    snmpv3_contextname=dict(type='str'),
                    snmpv3_privpassphrase=dict(type='str'),
                    snmpv3_privprotocol=dict(type='str', choices=['DES', 'AES']),
                    snmpv3_securitylevel=dict(type='str', choices=['noAuthNoPriv', 'authNoPriv', 'authPriv']),
                    snmpv3_securityname=dict(type='str'),
                    uniq=dict(type='bool', default=False),
                    host_source=dict(type='str', choices=['DNS', 'IP', 'discovery'], default='DNS'),
                    name_source=dict(type='str', choices=['None', 'DNS', 'IP', 'discovery'], default='None')
                ),
                required_if=[
                    ['type', 'SSH', ['ports']],
                    ['type', 'LDAP', ['ports']],
                    ['type', 'SMTP', ['ports']],
                    ['type', 'FTP', ['ports']],
                    ['type', 'HTTP', ['ports']],
                    ['type', 'POP', ['ports']],
                    ['type', 'NNTP', ['ports']],
                    ['type', 'IMAP', ['ports']],
                    ['type', 'TCP', ['ports']],
                    ['type', 'Zabbix', ['ports', 'key']],
                    ['type', 'SNMPv1', ['ports', 'key', 'snmp_community']],
                    ['type', 'SNMPv2', ['ports', 'key', 'snmp_community']],
                    ['type', 'SNMPv3', ['ports', 'key']],
                    ['type', 'HTTPS', ['ports']],
                    ['type', 'Telnet', ['ports']],
                    ['snmpv3_securitylevel', 'authPriv', ['snmpv3_privpassphrase']]
                ]
            ),
            delay=dict(type='str', required=False, default='1h'),
            proxy=dict(type='str', required=False, default=None),
            status=dict(type='str', default="enabled", choices=["enabled", "disabled"])
        ),
        required_if=[
            ['state', 'present', ['name', 'iprange', 'dchecks']],
            ['state', 'absent', ['name']],
        ],
        supports_check_mode=True
    )

    if not HAS_ZABBIX_API:
        module.fail_json(msg=missing_required_lib('zabbix-api', url='https://pypi.org/project/zabbix-api/'), exception=ZBX_IMP_ERR)

    server_url = module.params['server_url']
    login_user = module.params['login_user']
    login_password = module.params['login_password']
    http_login_user = module.params['http_login_user']
    http_login_password = module.params['http_login_password']
    validate_certs = module.params['validate_certs']
    timeout = module.params['timeout']
    state = module.params['state']
    name = module.params['name']
    iprange = module.params['iprange']
    dchecks = module.params['dchecks']
    delay = module.params['delay']
    proxy = module.params['proxy']
    status = module.params['status']

    try:
        zbx = ZabbixAPI(server_url, timeout=timeout, user=http_login_user,
                        passwd=http_login_password, validate_certs=validate_certs)
        zbx.login(login_user, login_password)
        atexit.register(zbx.logout)
    except Exception as e:
        module.fail_json(msg="Failed to connect to Zabbix server: %s" % e)

    zapi_wrapper = Zapi(module, zbx)

    drule = DiscoveryRule(module, zbx, zapi_wrapper)

    drule_exists = zapi_wrapper.check_if_drule_exists(name)
    dcks = Dchecks(module, zbx)

    if drule_exists:
        drule_id = zapi_wrapper.get_drule_by_drule_name(name)['druleid']
        if state == "absent":
            result = drule.delete_drule(drule_id)
            module.exit_json(changed=True, result="Discovery Rule deleted: %s, ID: %s" % (name, result))
        else:
            difference = drule.check_difference(
                drule_id=drule_id,
                name=name,
                iprange=iprange,
                dchecks=dcks.construct_the_data(dchecks),
                delay=delay,
                proxy=proxy,
                status=status
            )

            if difference == {}:
                module.exit_json(changed=False, msg="Discovery Rule is up to date: %s" % name)
            else:
                result = drule.update_drule(
                    drule_id=drule_id,
                    **difference
                )
                module.exit_json(changed=True, msg="Discovery Rule updated: %s, ID: %s" % (name, drule_id))
    else:
        if state == "absent":
            module.exit_json(changed=False, warnings="Discovery rule %s does not exist, nothing to delete" % name)
        else:
            drule_id = drule.add_drule(
                name=name,
                iprange=iprange,
                dchecks=dcks.construct_the_data(dchecks),
                delay=delay,
                proxy=proxy,
                status=status
            )
            module.exit_json(changed=True, msg="Discovery Rule created: %s, ID: %s" % (name, drule_id))


if __name__ == '__main__':
    main()
