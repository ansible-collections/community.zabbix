#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) me@mimiko.me
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


RETURN = r'''
---
host_groups:
  description: List of Zabbix groups.
  returned: success
  type: dict
  sample: [ { "flags": "0", "groupid": "33", "internal": "0", "name": "Hostgruup A" } ]
'''

DOCUMENTATION = r'''
---
module: zabbix_group_info
short_description: Gather information about Zabbix hostgroup
description:
   - This module allows you to search for Zabbix hostgroup entries.
   - This module was called C(zabbix_group_facts) before Ansible 2.9. The usage did not change.
author:
    - "Michael Miko (@RedWhiteMiko)"
requirements:
    - "python >= 2.6"
    - "zabbix-api >= 0.5.4"
options:
    hostgroup_name:
        description:
            - Name of the hostgroup in Zabbix.
            - hostgroup is the unique identifier used and cannot be updated using this module.
        required: true
        type: list
        elements: str

extends_documentation_fragment:
- community.zabbix.zabbix
'''

EXAMPLES = r'''
- name: Get hostgroup info
  local_action:
    module: community.zabbix.zabbix_group_info
    server_url: http://monitor.example.com
    login_user: username
    login_password: password
    hostgroup_name:
      - ExampleHostgroup
    timeout: 10
'''

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class Host(ZabbixBase):
    def get_group_ids_by_group_names(self, group_names):
        group_list = self._zapi.hostgroup.get({'output': 'extend', 'filter': {'name': group_names}})
        if len(group_list) < 1:
            self._module.fail_json(msg="Hostgroup not found: %s" % group_names)
        return group_list


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        hostgroup_name=dict(type='list', required=True),
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    if module._name == 'zabbix_group_facts':
        module.deprecate("The 'zabbix_group_facts' module has been renamed to 'zabbix_group_info'",
                         collection_name="community.zabbix", version='2.0.0')  # was 2.13

    hostgroup_name = module.params['hostgroup_name']

    host = Host(module)
    host_groups = host.get_group_ids_by_group_names(hostgroup_name)
    module.exit_json(host_groups=host_groups)


if __name__ == '__main__':
    main()
