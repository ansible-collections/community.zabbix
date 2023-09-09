#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, mrvanes
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: zabbix_user_role
short_description: Adds or removes zabbix roles
author:
    - Martin van Es (@mrvanes)
description:
    - This module adds or removes zabbix roles
requirements:
    - "python >= 3.9"
options:
    state:
        description:
            - State of the user_role.
            - On C(present), it will create if user_role does not exist or update the user_role if the associated data is different.
            - On C(absent) will remove a user_role if it exists.
        default: "present"
        choices: ["present", "absent"]
        type: str
        required: false
    name:
        description:
            - Name of the role to be processed
        type: str
        required: true
    type:
        description:
            - User type.
        choices: ["User", "Admin", "Super Admin"]
        default: "User"
        type: str
        required: false
    rules:
        description:
            - Rules set as defined in https://www.zabbix.com/documentation/current/en/manual/api/reference/role/object#role-rules
        default: {}
        type: dict
        required: false
extends_documentation_fragment:
- community.zabbix.zabbix
"""

EXAMPLES = r"""
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

# Create user role Operators with ui elements monitoring.hosts
# disabled and monitoring.maps enabled

- name: Create Zabbix user role
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_user_role:
    state: present
    name: Operators
    type: User
    rules:
      ui.default_access: 0
      ui:
        - name: "monitoring.hosts"
          status: 0
        - name: "monitoring.maps"
          status: 1
"""

RETURN = r"""
# Return values
msg:
    description: The result of the action
    type: str
    returned: always
    sample: "No action"
changed:
    description: The consequence of the action
    type: bool
    returned: always
    sample: false
"""

from ansible.module_utils.basic import AnsibleModule

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
                verdict = verdict and self.__find_val(out.get(rule, ""), value)
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
        state=dict(type="str", required=False, default="present", choices=["present", "absent"]),
        name=dict(type="str", required=True),
        type=dict(type="str", required=False, choices=["User", "Admin", "Super Admin"], default="User"),
        rules=dict(type="dict", required=False, default={}),
    ))

    # the AnsibleModule object
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False
    )

    state = module.params["state"]
    name = module.params["name"]
    type = zabbix_utils.helper_to_numeric_value(
        ["", "user", "admin", "super admin"], module.params["type"].lower()
    )
    rules = module.params["rules"]

    user_role = UserRole(module)

    result = user_role.get_user_role(name)
    if result:
        if len(result) == 1:
            role = result[0]
            if role["readonly"] != 1:
                roleid = role["roleid"]
                if state == "absent":
                    result = user_role._zapi.role.delete([f"{roleid}"])
                    changed = True
                    msg = "Role deleted"
                else:
                    if not user_role.is_part_of(rules, role["rules"]):
                        result = user_role._zapi.role.update({"roleid": roleid, "rules": rules})
                        changed = True
                        msg = "Role updated"
        else:
            module.fail_json(msg="Too many role matches")
    else:
        user_role._zapi.role.create({
            "name": name,
            "type": type,
            "rules": rules
        })
        changed = True
        msg = "Role created"

    module.exit_json(msg=msg, changed=changed)


if __name__ == "__main__":
    main()
