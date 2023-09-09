#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2013-2014, Epic Games, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
---
module: zabbix_globalmacro
short_description: Create/update/delete Zabbix Global macros
version_added: 1.4.0
description:
   - manages Zabbix Global macros, it can create, update or delete them.
   - For macro_type Secret the value field cannot be validated and will always be overwritten due to the secret nature of the Text.
author:
    - "Cove (@cove)"
    - Dean Hailin Song (!UNKNOWN)
    - Timothy Test (@ttestscripting)
requirements:
    - "python >= 3.9"
options:
    macro_name:
        description:
            - Name of the global macro in zabbix native format C({$MACRO}) or simple format C(MACRO).
        required: true
        type: str
    macro_value:
        description:
            - Value of the global macro.
            - Required if I(state=present).
        type: str
    macro_type:
        description:
            - Type of the global macro Text or Secret Text.
            - Required if I(state=present).
            - text
            - secret - Secret Text Works only with Zabbix >= 5.0 and will default to Text in lower versions
            - vault - Vault Secret Works only with Zabbix >= 5.2 and will default to Text in lower versions
        type: str
        choices: [text, secret, vault]
        default: text
    macro_description:
        description:
            - Text Description of the global macro.
        type: str
        default: ""
    state:
        description:
            - State of the macro.
            - On C(present), it will create if macro does not exist or update the macro if the associated data is different.
            - On C(absent) will remove a macro if it exists.
        required: false
        choices: ["present", "absent"]
        type: str
        default: "present"
    force:
        description:
            - Only updates an existing macro if set to C(yes).
        default: "yes"
        type: bool

notes:
    - This module returns changed=true when I(macro_type=secret).

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

- name: Create new global macro or update an existing macro's value
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_globalmacro:
    macro_name: EXAMPLE.MACRO
    macro_value: Example value
    macro_type: 0
    macro_description: Example description
    state: present
# Values with curly brackets need to be quoted otherwise they will be interpreted as a dictionary
- name: Create new global macro in Zabbix native format with Secret Type
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_globalmacro:
    macro_name: "{$EXAMPLE.MACRO}"
    macro_value: Example value
    macro_type: 1
    macro_description: Example description
    state: present
- name: Delete existing global macro
  community.zabbix.zabbix_globalmacro:
    macro_name: "{$EXAMPLE.MACRO}"
    state: absent
"""

RETURN = r"""
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase

import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class GlobalMacro(ZabbixBase):
    # get global macro
    def get_global_macro(self, macro_name):
        try:
            all_global_macro_list = self._zapi.usermacro.get({"globalmacro": "true"})
            global_macro_list = [d for d in all_global_macro_list if d["macro"] == macro_name]
            if len(global_macro_list) > 0:
                return global_macro_list[0]
            return None
        except Exception as e:
            self._module.fail_json(msg="Failed to get global macro %s: %s" % (macro_name, e))

    # create global macro
    def create_global_macro(self, macro_name, macro_value, macro_type, macro_description):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            self._zapi.usermacro.createglobal({"macro": macro_name, "value": macro_value, "type": macro_type, "description": macro_description})
            self._module.exit_json(changed=True, result="Successfully added global macro %s" % macro_name)
        except Exception as e:
            self._module.fail_json(msg="Failed to create global macro %s: %s" % (macro_name, e))

    # update global macro
    def update_global_macro(self, global_macro_obj, macro_name, macro_value, macro_type, macro_description):
        global_macro_id = global_macro_obj["globalmacroid"]
        try:
            if global_macro_obj["type"] == "0" or global_macro_obj["type"] == "2":
                if (global_macro_obj["macro"] == macro_name and global_macro_obj["value"] == macro_value
                        and global_macro_obj["type"] == macro_type and global_macro_obj["description"] == macro_description):
                    self._module.exit_json(changed=False, result="Global macro %s already up to date" % macro_name)
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            self._zapi.usermacro.updateglobal({"globalmacroid": global_macro_id, "macro": macro_name,
                                               "value": macro_value, "type": macro_type, "description": macro_description})
            self._module.exit_json(changed=True, result="Successfully updated global macro %s" % macro_name)
        except Exception as e:
            self._module.fail_json(msg="Failed to update global macro %s: %s" % (macro_name, e))

    # delete global macro
    def delete_global_macro(self, global_macro_obj, macro_name):
        global_macro_id = global_macro_obj["globalmacroid"]
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            self._zapi.usermacro.deleteglobal([global_macro_id])
            self._module.exit_json(changed=True, result="Successfully deleted global macro %s" % macro_name)
        except Exception as e:
            self._module.fail_json(msg="Failed to delete global macro %s: %s" % (macro_name, e))


def normalize_macro_name(macro_name):
    # Zabbix handles macro names in upper case characters
    if ":" in macro_name:
        macro_name = ":".join([macro_name.split(":")[0].upper(), ":".join(macro_name.split(":")[1:])])
    else:
        macro_name = macro_name.upper()

    # Valid format for macro is {$MACRO}
    if not macro_name.startswith("{$"):
        macro_name = "{$" + macro_name
    if not macro_name.endswith("}"):
        macro_name = macro_name + "}"

    return macro_name


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        macro_name=dict(type="str", required=True),
        macro_value=dict(type="str", required=False, no_log=True),
        macro_type=dict(type="str", default="text", choices=["text", "secret", "vault"]),
        macro_description=dict(type="str", default=""),
        state=dict(type="str", default="present", choices=["present", "absent"]),
        force=dict(type="bool", default=True)
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=[
            ["state", "present", ["macro_value"]]
        ],
        supports_check_mode=True
    )

    macro_name = normalize_macro_name(module.params["macro_name"])
    macro_value = module.params["macro_value"]
    macro_type = module.params["macro_type"]
    macro_value = module.params["macro_value"]
    macro_description = module.params["macro_description"]
    state = module.params["state"]
    force = module.params["force"]

    if macro_type == "text":
        macro_type = "0"
    elif macro_type == "secret":
        macro_type = "1"
    elif macro_type == "vault":
        macro_type = "2"

    global_macro_class_obj = GlobalMacro(module)

    if macro_name:
        global_macro_obj = global_macro_class_obj.get_global_macro(macro_name)

    if state == "absent":
        if not global_macro_obj:
            module.exit_json(changed=False, msg="Global Macro %s does not exist" % macro_name)
        else:
            # delete a macro
            global_macro_class_obj.delete_global_macro(global_macro_obj, macro_name)
    else:
        if not global_macro_obj:
            # create global macro
            global_macro_class_obj.create_global_macro(macro_name, macro_value, macro_type, macro_description)
        elif force:
            # update global macro
            global_macro_class_obj.update_global_macro(global_macro_obj, macro_name, macro_value, macro_type, macro_description)
        else:
            module.exit_json(changed=False, result="Global macro %s already exists and force is set to no" % macro_name)


if __name__ == "__main__":
    main()
