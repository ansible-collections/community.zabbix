#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2013-2014, Epic Games, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
---
module: zabbix_hostmacro
short_description: Create/update/delete Zabbix host macros
description:
   - manages Zabbix host macros, it can create, update or delete them.
author:
    - "Cove (@cove)"
    - Dean Hailin Song (!UNKNOWN)
requirements:
    - "python >= 3.9"
options:
    host_name:
        description:
            - Name of the host.
        required: true
        type: str
    macro_name:
        description:
            - Name of the host macro in zabbix native format C({$MACRO}) or simple format C(MACRO).
        required: true
        type: str
    macro_value:
        description:
            - Value of the host macro.
            - Required if I(state=present).
        type: str
    macro_type:
        type: str
        description:
            - Type of the host macro.
            - text (default)
        required: false
        choices: ["text", "secret", "vault"]
        default: "text"
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

- name: Create new host macro or update an existing macro's value
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_hostmacro:
    host_name: ExampleHost
    macro_name: EXAMPLE.MACRO
    macro_value: Example value
    macro_description: Example description
    state: present

# Values with curly brackets need to be quoted otherwise they will be interpreted as a dictionary
- name: Create new host macro in Zabbix native format
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_hostmacro:
    host_name: ExampleHost
    macro_name: "{$EXAMPLE.MACRO}"
    macro_value: Example value
    macro_description: Example description
    state: present

- name: Delete existing host macro
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_hostmacro:
    host_name: ExampleHost
    macro_name: "{$EXAMPLE.MACRO}"
    state: absent
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase

import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class HostMacro(ZabbixBase):
    # get host id by host name
    def get_host_id(self, host_name):
        try:
            host_list = self._zapi.host.get({"output": "extend", "filter": {"host": host_name}})
            if len(host_list) < 1:
                self._module.fail_json(msg="Host not found: %s" % host_name)
            else:
                host_id = host_list[0]["hostid"]
                return host_id
        except Exception as e:
            self._module.fail_json(msg="Failed to get the host %s id: %s." % (host_name, e))

    # get host macro
    def get_host_macro(self, macro_name, host_id):
        try:
            host_macro_list = self._zapi.usermacro.get(
                {"output": "extend", "selectSteps": "extend", "hostids": [host_id], "filter": {"macro": macro_name}})
            if len(host_macro_list) > 0:
                return host_macro_list[0]
            return None
        except Exception as e:
            self._module.fail_json(msg="Failed to get host macro %s: %s" % (macro_name, e))

    # create host macro
    def create_host_macro(self, macro_name, macro_value, macro_type, macro_description, host_id):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            self._zapi.usermacro.create({"hostid": host_id, "macro": macro_name, "value": macro_value, "type": macro_type, "description": macro_description})
            self._module.exit_json(changed=True, result="Successfully added host macro %s" % macro_name)
        except Exception as e:
            self._module.fail_json(msg="Failed to create host macro %s: %s" % (macro_name, e))

    # update host macro
    def update_host_macro(self, host_macro_obj, macro_name, macro_value, macro_type, macro_description):
        host_macro_id = host_macro_obj["hostmacroid"]
        if host_macro_obj["macro"] == macro_name:
            # no change only when macro type == 0. when type = 1 or 2 zabbix will not output value of it.
            if (host_macro_obj["type"] == "0" and macro_type == "0" and host_macro_obj["value"] == macro_value
                    and host_macro_obj["description"] == macro_description):
                self._module.exit_json(changed=False, result="Host macro %s already up to date" % macro_name)
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            self._zapi.usermacro.update({"hostmacroid": host_macro_id, "value": macro_value, "type": macro_type, "description": macro_description})
            self._module.exit_json(changed=True, result="Successfully updated host macro %s" % macro_name)
        except Exception as e:
            self._module.fail_json(msg="Failed to update host macro %s: %s" % (macro_name, e))

    # delete host macro
    def delete_host_macro(self, host_macro_obj, macro_name):
        host_macro_id = host_macro_obj["hostmacroid"]
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            self._zapi.usermacro.delete([host_macro_id])
            self._module.exit_json(changed=True, result="Successfully deleted host macro %s" % macro_name)
        except Exception as e:
            self._module.fail_json(msg="Failed to delete host macro %s: %s" % (macro_name, e))


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
        host_name=dict(type="str", required=True),
        macro_name=dict(type="str", required=True),
        macro_value=dict(type="str", required=False),
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

    host_name = module.params["host_name"]
    macro_name = normalize_macro_name(module.params["macro_name"])
    macro_value = module.params["macro_value"]
    macro_description = module.params["macro_description"]
    state = module.params["state"]
    force = module.params["force"]
    if module.params["macro_type"] == "secret":
        macro_type = "1"
    elif module.params["macro_type"] == "vault":
        macro_type = "2"
    else:
        macro_type = "0"

    host_macro_class_obj = HostMacro(module)

    if host_name:
        host_id = host_macro_class_obj.get_host_id(host_name)
        host_macro_obj = host_macro_class_obj.get_host_macro(macro_name, host_id)

    if state == "absent":
        if not host_macro_obj:
            module.exit_json(changed=False, msg="Host Macro %s does not exist" % macro_name)
        else:
            # delete a macro
            host_macro_class_obj.delete_host_macro(host_macro_obj, macro_name)
    else:
        if not host_macro_obj:
            # create host macro
            host_macro_class_obj.create_host_macro(macro_name, macro_value, macro_type, macro_description, host_id)
        elif force:
            # update host macro
            host_macro_class_obj.update_host_macro(host_macro_obj, macro_name, macro_value, macro_type, macro_description)
        else:
            module.exit_json(changed=False, result="Host macro %s already exists and force is set to no" % macro_name)


if __name__ == "__main__":
    main()
