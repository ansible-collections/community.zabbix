#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) me@mimiko.me
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


RETURN = r'''
---
hosts:
  description: List of Zabbix hosts. See https://www.zabbix.com/documentation/4.0/manual/api/reference/host/get for list of host values.
  returned: success
  type: dict
  sample: [ { "available": "1", "description": "", "disable_until": "0", "error": "", "flags": "0", "groups": ["1"], "host": "Host A", ... } ]
'''

DOCUMENTATION = r'''
---
module: zabbix_host_info
short_description: Gather information about Zabbix host
description:
   - This module allows you to search for Zabbix host entries.
   - This module was called C(zabbix_host_facts) before Ansible 2.9. The usage did not change.
author:
    - "Michael Miko (@RedWhiteMiko)"
requirements:
    - "python >= 2.6"
options:
    host_name:
        description:
            - Name of the host in Zabbix.
            - host_name is the unique identifier used and cannot be updated using this module.
            - Required when I(host_ip) is not used.
        required: false
        type: str
        default: ''
    host_ip:
        description:
            - Host interface IP of the host in Zabbix.
            - Required when I(host_name) is not used.
        required: false
        type: list
        elements: str
        default: []
    exact_match:
        description:
            - Find the exact match
        type: bool
        default: no
    remove_duplicate:
        description:
            - Remove duplicate host from host result
        type: bool
        default: yes
    host_inventory:
        description:
            - List of host inventory keys to display in result.
            - Whole host inventory is retrieved if keys are not specified.
        type: list
        elements: str
        required: false
        default: []
extends_documentation_fragment:
- community.zabbix.zabbix

'''

EXAMPLES = r'''
# If you want to use Username and Password to be authenticated by Zabbix Server
- name: Set credentials to access Zabbix Server API
  set_fact:
    ansible_user: Admin
    ansible_httpapi_pass: zabbix

# If you want to use API token to be authenticated by Zabbix Server
# https://www.zabbix.com/documentation/current/en/manual/web_interface/frontend_sections/administration/general#api-tokens
- name: Set API token
  set_fact:
    ansible_zabbix_auth_key: 8ec0d52432c15c91fcafe9888500cf9a607f44091ab554dbee860f6b44fac895

- name: Get host info
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_host_info:
    host_name: ExampleHost
    host_ip: 127.0.0.1
    timeout: 10
    exact_match: no
    remove_duplicate: yes

- name: Reduce host inventory information to provided keys
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_host_info:
    host_name: ExampleHost
    host_inventory:
      - os
      - tag
    host_ip: 127.0.0.1
    timeout: 10
    exact_match: no
    remove_duplicate: yes
'''


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class Host(ZabbixBase):
    def get_hosts_by_host_name(self, host_name, exact_match, host_inventory):
        """ Get host by host name """
        search_key = 'search'
        if exact_match:
            search_key = 'filter'
        host_list = self._zapi.host.get({
            'output': 'extend',
            'selectParentTemplates': ['name'],
            search_key: {'host': [host_name]},
            'selectInventory': host_inventory,
            'selectGroups': 'extend',
            'selectTags': 'extend',
            'selectMacros': 'extend'
        })
        if len(host_list) < 1:
            self._module.fail_json(msg="Host not found: %s" % host_name)
        else:
            return host_list

    def get_hosts_by_ip(self, host_ips, host_inventory):
        """ Get host by host ip(s) """
        hostinterfaces = self._zapi.hostinterface.get({
            'output': 'extend',
            'filter': {
                'ip': host_ips
            }
        })
        if len(hostinterfaces) < 1:
            self._module.fail_json(msg="Host not found: %s" % host_ips)
        host_list = []
        for hostinterface in hostinterfaces:
            host = self._zapi.host.get({
                'output': 'extend',
                'selectGroups': 'extend',
                'selectParentTemplates': ['name'],
                'hostids': hostinterface['hostid'],
                'selectInventory': host_inventory,
                'selectTags': 'extend',
                'selectMacros': 'extend'
            })
            host[0]['hostinterfaces'] = hostinterface
            host_list.append(host[0])
        return host_list

    def delete_duplicate_hosts(self, hosts):
        """ Delete duplicated hosts """
        unique_hosts = []
        listed_hostnames = []
        for zabbix_host in hosts:
            if zabbix_host['name'] in listed_hostnames:
                continue
            unique_hosts.append(zabbix_host)
            listed_hostnames.append(zabbix_host['name'])
        return unique_hosts


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        host_name=dict(type='str', default='', required=False),
        host_ip=dict(type='list', default=[], required=False),
        exact_match=dict(type='bool', required=False, default=False),
        remove_duplicate=dict(type='bool', required=False, default=True),
        host_inventory=dict(type='list', default=[], required=False)
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )
    if module._name == 'zabbix_host_facts':
        module.deprecate("The 'zabbix_host_facts' module has been renamed to 'zabbix_host_info'",
                         collection_name="community.zabbix", version='2.0.0')  # was 2.13

    zabbix_utils.require_creds_params(module)

    host_name = module.params['host_name']
    host_ips = module.params['host_ip']
    exact_match = module.params['exact_match']
    is_remove_duplicate = module.params['remove_duplicate']
    host_inventory = module.params['host_inventory']

    if not host_inventory:
        host_inventory = 'extend'

    host = Host(module)

    if host_name:
        hosts = host.get_hosts_by_host_name(host_name, exact_match, host_inventory)
        if is_remove_duplicate:
            hosts = host.delete_duplicate_hosts(hosts)
        extended_hosts = []
        for zabbix_host in hosts:
            zabbix_host['hostinterfaces'] = host._zapi.hostinterface.get({
                'output': 'extend', 'hostids': zabbix_host['hostid']
            })
            extended_hosts.append(zabbix_host)
        module.exit_json(ok=True, hosts=extended_hosts)

    elif host_ips:
        extended_hosts = host.get_hosts_by_ip(host_ips, host_inventory)
        if is_remove_duplicate:
            hosts = host.delete_duplicate_hosts(extended_hosts)
        module.exit_json(ok=True, hosts=extended_hosts)
    else:
        module.exit_json(ok=False, hosts=[], result="No Host present")


if __name__ == '__main__':
    main()
