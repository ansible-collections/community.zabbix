#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, mrvanes
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


DOCUMENTATION = r'''
---
module: zabbix_role
https://www.zabbix.com/documentation/current/en/manual/api/reference/role
https://www.zabbix.com/documentation/current/en/manual/api/reference/role/create

short_description: Adds or removes zabbix roles

description: This module adds or removes zabbix roles

options:
    server_url: http://localhost/zabbix
    login_user: username
    login_password: password
    state: exact
    name: Operators
      The name of the role
    type: 1
      https://www.zabbix.com/documentation/current/en/manual/api/reference/role/object#role
    rules:
      https://www.zabbix.com/documentation/current/en/manual/api/reference/role/object#role-rules

author:
    - Martin van Es
'''

EXAMPLES = r'''
# Creat role Operators with ui elements monitoring.hosts
# disabled and monitoring.maps enabled

- name: Create Zabbix role
  local_action:
    module: zabbix_role
    server_url: http://zabbix.scz-vm.net/
    login_user: username
    login_password: login_password
    state: present
    name: Operators
    type: 1
    rules:
      ui.default_access: 0
      ui:
        - name: "monitoring.hosts"
          status: 0
        - name: "monitoring.maps"
          status: 1
'''

RETURN = r'''
# Return values
msg:
    description: The result of the action
    type: str
    returned: always
    sample: 'No action'
changed:
    description: The consequence of the action
    type: bool
    returned: always
    sample: False
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.zabbix.plugins.module_utils.version import LooseVersion

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class UserRole(ZabbixBase):
    def __find_val(self, outval, inval):
        if outval == str(inval):
            return True
        return False

    def __find_list(self, outval, inval):
        if set(outval) == set(inval):
            return True
        return False

    def __find_dict(self, outval, inval):
        for out in outval:
            m = True
            for k, v in inval.items():
                if out[k] == str(v):
                    continue
                else:
                    m = False
            if m:
                break
        return m

    def is_part_of(self, inp, out):
        verdict = True
        for rule, value in inp.items():
            if not isinstance(value, list):
                verdict = verdict and self.__find_val(out.get(rule, ''), value)
            else:
                if len(value):
                    if not isinstance(value[0], dict):
                        verdict = verdict and self.__find_list(out.get(rule, []), value)
                    else:
                        for v in value:
                            verdict = verdict and self.__find_dict(out.get(rule, {}), v)
                else:
                    verdict = verdict and self.__find_list(rule, value)
        return verdict

    def get_user_role(self, name):
        result = self._zapi.role.get({
            "output": "extend",
            "selectRules": "extend",
            "filter": {"name": name}
        })
        return result


def main():
    msg = "No action"
    changed = False

    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        server_url=dict(type='str', required=True),
        login_user=dict(type='str', required=True),
        login_password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', required=False, default='present'),
        name=dict(type='str', required=True),
        type=dict(type='int', required=False, default=1),
        rules=dict(type='dict', required=True),
    ))

    # the AnsibleModule object
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    state = module.params['state']
    name = module.params['name']
    type = module.params['type']
    rules = module.params['rules']

    user_role = UserRole(module)

    result = user_role.get_user_role(name)
    if result:
        if len(result) == 1:
            role = result[0]
            if role['readonly'] != 1:
                roleid = role['roleid']
                if state == 'absent':
                    result = user_role._zapi.role.delete([f"{roleid}"])
                    changed = True
                    msg = "Role deleted"
                else:
                    if not user_role.is_part_of(rules, role['rules']):
                        result = user_role._zapi.role.update({"roleid": roleid, "rules": rules})
                        changed = True
                        msg = "Role updated"
        else:
            module.fail_json(msg='Too many role matches')
    else:
        user_role._zapi.role.create({
            "name": name,
            "type": type,
            "rules": rules
        })
        changed = True
        msg = "Role created"

    module.exit_json(msg=msg, changed=changed)


if __name__ == '__main__':
    main()
