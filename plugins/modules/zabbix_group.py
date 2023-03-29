#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2013-2014, Epic Games, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: zabbix_group
short_description: Create/delete Zabbix host groups
description:
   - Create host groups if they do not exist.
   - Delete existing host groups if they exist.
author:
    - "Cove (@cove)"
    - "Tony Minfei Ding (!UNKNOWN)"
    - "Harrison Gu (@harrisongu)"
requirements:
    - "python >= 2.6"
options:
    state:
        description:
            - Create or delete host group.
        required: false
        type: str
        default: "present"
        choices: [ "present", "absent" ]
    host_groups:
        description:
            - List of host groups to create or delete.
        required: true
        type: list
        elements: str
        aliases: [ "host_group" ]

extends_documentation_fragment:
- community.zabbix.zabbix

notes:
    - Too many concurrent updates to the same group may cause Zabbix to return errors, see examples for a workaround if needed.
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

# Base create host groups example
- name: Create host groups
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_group:
    state: present
    host_groups:
      - Example group1
      - Example group2

# Limit the Zabbix group creations to one host since Zabbix can return an error when doing concurrent updates
- name: Create host groups
  # set task level variables as we change ansible_connection plugin here
  vars:
      ansible_network_os: community.zabbix.zabbix
      ansible_connection: httpapi
      ansible_httpapi_port: 443
      ansible_httpapi_use_ssl: true
      ansible_httpapi_validate_certs: false
      ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
      ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_group:
    state: present
    host_groups:
      - Example group1
      - Example group2
  when: inventory_hostname==groups['group_name'][0]
'''


import traceback

try:
    from zabbix_api import Already_Exists

    HAS_ZABBIX_API = True
    ZBX_IMP_ERR = Exception()
except ImportError:
    ZBX_IMP_ERR = traceback.format_exc()
    HAS_ZABBIX_API = False

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class HostGroup(ZabbixBase):
    # create host group(s) if not exists
    def create_host_group(self, group_names):
        try:
            group_add_list = []
            for group_name in group_names:
                result = self._zapi.hostgroup.get({'filter': {'name': group_name}})
                if not result:
                    try:
                        if self._module.check_mode:
                            self._module.exit_json(changed=True)
                        self._zapi.hostgroup.create({'name': group_name})
                        group_add_list.append(group_name)
                    except Already_Exists:
                        return group_add_list
            return group_add_list
        except Exception as e:
            self._module.fail_json(msg="Failed to create host group(s): %s" % e)

    # delete host group(s)
    def delete_host_group(self, group_ids):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            self._zapi.hostgroup.delete(group_ids)
        except Exception as e:
            self._module.fail_json(msg="Failed to delete host group(s), Exception: %s" % e)

    # get group ids by name
    def get_group_ids(self, host_groups):
        group_ids = []

        group_list = self._zapi.hostgroup.get({'output': 'extend', 'filter': {'name': host_groups}})
        for group in group_list:
            group_id = group['groupid']
            group_ids.append(group_id)
        return group_ids, group_list


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        host_groups=dict(type='list', required=True, aliases=['host_group']),
        state=dict(type='str', default="present", choices=['present', 'absent']),
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    zabbix_utils.require_creds_params(module)

    for p in ['server_url', 'login_user', 'login_password']:
        if p in module.params and module.params[p] and module.params[p]:
            module.warn('Option "%s" is deprecated with the move to httpapi connection and will be removed in the next release' % p)

    host_groups = module.params['host_groups']
    state = module.params['state']

    hostGroup = HostGroup(module)

    group_ids = []
    group_list = []
    if host_groups:
        group_ids, group_list = hostGroup.get_group_ids(host_groups)

    if state == "absent":
        # delete host groups
        if group_ids:
            delete_group_names = []
            hostGroup.delete_host_group(group_ids)
            for group in group_list:
                delete_group_names.append(group['name'])
            module.exit_json(changed=True,
                             result="Successfully deleted host group(s): %s." % ",".join(delete_group_names))
        else:
            module.exit_json(changed=False, result="No host group(s) to delete.")
    else:
        # create host groups
        group_add_list = hostGroup.create_host_group(host_groups)
        if len(group_add_list) > 0:
            module.exit_json(changed=True, result="Successfully created host group(s): %s" % group_add_list)
        else:
            module.exit_json(changed=False)


if __name__ == '__main__':
    main()
