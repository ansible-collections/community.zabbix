#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: zabbix_templategroup
short_description: Create/delete Zabbix template groups
description:
   - Create template groups if they do not exist.
   - Delete existing template groups if they exist.
author:
    - "Cove (@cove)"
    - "Tony Minfei Ding (!UNKNOWN)"
    - "Harrison Gu (@harrisongu)"
requirements:
    - "python >= 2.6"
options:
    state:
        description:
            - Create or delete template group.
        required: false
        type: str
        default: "present"
        choices: [ "present", "absent" ]
    template_groups:
        description:
            - List of template groups to create or delete.
        required: true
        type: list
        elements: str
        aliases: [ "template_group" ]

extends_documentation_fragment:
- community.zabbix.zabbix

notes:
    - Too many concurrent updates to the same group may cause Zabbix to return errors, see examples for a workaround if needed.
'''

EXAMPLES = r'''
# If you want to use Username and Password to be authenticated by Zabbix Server
- name: Set credentials to access Zabbix Server API
  ansible.builtin.set_fact:
    ansible_user: Admin
    ansible_httpapi_pass: zabbix

# If you want to use API token to be authenticated by Zabbix Server
# https://www.zabbix.com/documentation/current/en/manual/web_interface/frontend_sections/administration/general#api-tokens
- name: Set API token
  ansible.builtin.set_fact:
    ansible_zabbix_auth_key: 8ec0d52432c15c91fcafe9888500cf9a607f44091ab554dbee860f6b44fac895

# Base create template groups example
- name: Create template groups
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_templategroup:
    state: present
    template_groups:
      - Example group1
      - Example group2

# Limit the Zabbix group creations to one template since Zabbix can return an error when doing concurrent updates
- name: Create template groups
  # set task level variables as we change ansible_connection plugin here
  vars:
      ansible_network_os: community.zabbix.zabbix
      ansible_connection: httpapi
      ansible_httpapi_port: 443
      ansible_httpapi_use_ssl: true
      ansible_httpapi_validate_certs: false
      ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
      ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_templategroup:
    state: present
    template_groups:
      - Example group1
      - Example group2
  when: inventory_hostname==groups['group_name'][0]
'''


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class TemplateGroup(ZabbixBase):
    # create template group(s) if not exists
    def create_template_group(self, group_names):
        try:
            group_add_list = []
            for group_name in group_names:
                result = self._zapi.templategroup.get({'filter': {'name': group_name}})
                if not result:
                    if self._module.check_mode:
                        self._module.exit_json(changed=True)
                    self._zapi.templategroup.create({'name': group_name})
                    group_add_list.append(group_name)
            return group_add_list
        except Exception as e:
            self._module.fail_json(msg="Failed to create template group(s): %s" % e)

    # delete template group(s)
    def delete_template_group(self, group_ids):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            self._zapi.templategroup.delete(group_ids)
        except Exception as e:
            self._module.fail_json(msg="Failed to delete template group(s), Exception: %s" % e)

    # get group ids by name
    def get_group_ids(self, template_groups):
        group_ids = []

        group_list = self._zapi.templategroup.get({'output': 'extend', 'filter': {'name': template_groups}})
        for group in group_list:
            group_id = group['groupid']
            group_ids.append(group_id)
        return group_ids, group_list


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        template_groups=dict(type='list', required=True, aliases=['template_group'], elements='str'),
        state=dict(type='str', default="present", choices=['present', 'absent']),
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    template_groups = module.params['template_groups']
    state = module.params['state']

    templateGroup = TemplateGroup(module)

    group_ids = []
    group_list = []
    if template_groups:
        group_ids, group_list = templateGroup.get_group_ids(template_groups)

    if state == "absent":
        # delete template groups
        if group_ids:
            delete_group_names = []
            templateGroup.delete_template_group(group_ids)
            for group in group_list:
                delete_group_names.append(group['name'])
            module.exit_json(changed=True,
                             result="Successfully deleted template group(s): %s." % ",".join(delete_group_names))
        else:
            module.exit_json(changed=False, result="No template group(s) to delete.")
    else:
        # create template groups
        group_add_list = templateGroup.create_template_group(template_groups)
        if len(group_add_list) > 0:
            module.exit_json(changed=True, result="Successfully created template group(s): %s" % group_add_list)
        else:
            module.exit_json(changed=False)


if __name__ == '__main__':
    main()
