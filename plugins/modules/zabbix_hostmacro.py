#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2013-2014, Epic Games, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: zabbix_hostmacro
short_description: Create/update/delete Zabbix host macros
description:
   - manages Zabbix host macros, it can create, update or delete them.
author:
    - "Cove (@cove)"
    - Dean Hailin Song (!UNKNOWN)
requirements:
    - "python >= 2.6"
    - "zabbix-api >= 0.5.4"
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
            - secret (Works only with Zabbix >= 5.0)
            - vault (Works only with Zabbix >= 5.2)
        required: false
        choices: ['text', 'secret', 'vault']
        default: 'text'
    state:
        description:
            - State of the macro.
            - On C(present), it will create if macro does not exist or update the macro if the associated data is different.
            - On C(absent) will remove a macro if it exists.
        required: false
        choices: ['present', 'absent']
        type: str
        default: "present"
    force:
        description:
            - Only updates an existing macro if set to C(yes).
        default: 'yes'
        type: bool

extends_documentation_fragment:
- community.zabbix.zabbix

'''

EXAMPLES = r'''
- name: Create new host macro or update an existing macro's value
  local_action:
    module: community.zabbix.zabbix_hostmacro
    server_url: http://monitor.example.com
    login_user: username
    login_password: password
    host_name: ExampleHost
    macro_name: EXAMPLE.MACRO
    macro_value: Example value
    state: present

# Values with curly brackets need to be quoted otherwise they will be interpreted as a dictionary
- name: Create new host macro in Zabbix native format
  local_action:
    module: community.zabbix.zabbix_hostmacro
    server_url: http://monitor.example.com
    login_user: username
    login_password: password
    host_name: ExampleHost
    macro_name: "{$EXAMPLE.MACRO}"
    macro_value: Example value
    state: present

- name: Delete existing host macro
  local_action:
    module: community.zabbix.zabbix_hostmacro
    server_url: http://monitor.example.com
    login_user: username
    login_password: password
    host_name: ExampleHost
    macro_name: "{$EXAMPLE.MACRO}"
    state: absent
'''


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
from ansible_collections.community.zabbix.plugins.module_utils.version import LooseVersion

import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class HostMacro(ZabbixBase):
    # get host id by host name
    def get_host_id(self, host_name):
        try:
            host_list = self._zapi.host.get({'output': 'extend', 'filter': {'host': host_name}})
            if len(host_list) < 1:
                self._module.fail_json(msg="Host not found: %s" % host_name)
            else:
                host_id = host_list[0]['hostid']
                return host_id
        except Exception as e:
            self._module.fail_json(msg="Failed to get the host %s id: %s." % (host_name, e))

    # get host macro
    def get_host_macro(self, macro_name, host_id):
        try:
            host_macro_list = self._zapi.usermacro.get(
                {"output": "extend", "selectSteps": "extend", 'hostids': [host_id], 'filter': {'macro': macro_name}})
            if len(host_macro_list) > 0:
                return host_macro_list[0]
            return None
        except Exception as e:
            self._module.fail_json(msg="Failed to get host macro %s: %s" % (macro_name, e))

    # create host macro
    def create_host_macro(self, macro_name, macro_value, macro_type, host_id):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            if LooseVersion(self._zbx_api_version) >= LooseVersion('5.0'):
                self._zapi.usermacro.create({'hostid': host_id, 'macro': macro_name, 'value': macro_value, 'type': macro_type})
            else:
                self._zapi.usermacro.create({'hostid': host_id, 'macro': macro_name, 'value': macro_value})
            self._module.exit_json(changed=True, result="Successfully added host macro %s" % macro_name)
        except Exception as e:
            self._module.fail_json(msg="Failed to create host macro %s: %s" % (macro_name, e))

    # update host macro
    def update_host_macro(self, host_macro_obj, macro_name, macro_value, macro_type):
        host_macro_id = host_macro_obj['hostmacroid']
        if host_macro_obj['macro'] == macro_name:
            if LooseVersion(self._zbx_api_version) >= LooseVersion('5.0'):
                # no change only when macro type == 0. when type = 1 or 2 zabbix will not output value of it.
                if host_macro_obj['type'] == '0' and macro_type == '0' and host_macro_obj['value'] == macro_value:
                    self._module.exit_json(changed=False, result="Host macro %s already up to date" % macro_name)
            else:
                if host_macro_obj['value'] == macro_value:
                    self._module.exit_json(changed=False, result="Host macro %s already up to date" % macro_name)
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            if LooseVersion(self._zbx_api_version) >= LooseVersion('5.0'):
                self._zapi.usermacro.update({'hostmacroid': host_macro_id, 'value': macro_value, 'type': macro_type})
            else:
                self._zapi.usermacro.update({'hostmacroid': host_macro_id, 'value': macro_value})
            self._module.exit_json(changed=True, result="Successfully updated host macro %s" % macro_name)
        except Exception as e:
            self._module.fail_json(msg="Failed to update host macro %s: %s" % (macro_name, e))

    # delete host macro
    def delete_host_macro(self, host_macro_obj, macro_name):
        host_macro_id = host_macro_obj['hostmacroid']
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            self._zapi.usermacro.delete([host_macro_id])
            self._module.exit_json(changed=True, result="Successfully deleted host macro %s" % macro_name)
        except Exception as e:
            self._module.fail_json(msg="Failed to delete host macro %s: %s" % (macro_name, e))


def normalize_macro_name(macro_name):
    # Zabbix handles macro names in upper case characters
    if ':' in macro_name:
        macro_name = ':'.join([macro_name.split(':')[0].upper(), ':'.join(macro_name.split(':')[1:])])
    else:
        macro_name = macro_name.upper()

    # Valid format for macro is {$MACRO}
    if not macro_name.startswith('{$'):
        macro_name = '{$' + macro_name
    if not macro_name.endswith('}'):
        macro_name = macro_name + '}'

    return macro_name


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        host_name=dict(type='str', required=True),
        macro_name=dict(type='str', required=True),
        macro_value=dict(type='str', required=False),
        macro_type=dict(type='str', default='text', choices=['text', 'secret', 'vault']),
        state=dict(type='str', default='present', choices=['present', 'absent']),
        force=dict(type='bool', default=True)
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=[
            ['state', 'present', ['macro_value']]
        ],
        supports_check_mode=True
    )

    host_name = module.params['host_name']
    macro_name = normalize_macro_name(module.params['macro_name'])
    macro_value = module.params['macro_value']
    state = module.params['state']
    force = module.params['force']
    if module.params['macro_type'] == 'secret':
        macro_type = '1'
    elif module.params['macro_type'] == 'vault':
        macro_type = '2'
    else:
        macro_type = '0'

    host_macro_class_obj = HostMacro(module)

    if host_name:
        host_id = host_macro_class_obj.get_host_id(host_name)
        host_macro_obj = host_macro_class_obj.get_host_macro(macro_name, host_id)

    if state == 'absent':
        if not host_macro_obj:
            module.exit_json(changed=False, msg="Host Macro %s does not exist" % macro_name)
        else:
            # delete a macro
            host_macro_class_obj.delete_host_macro(host_macro_obj, macro_name)
    else:
        if not host_macro_obj:
            # create host macro
            host_macro_class_obj.create_host_macro(macro_name, macro_value, macro_type, host_id)
        elif force:
            # update host macro
            host_macro_class_obj.update_host_macro(host_macro_obj, macro_name, macro_value, macro_type)
        else:
            module.exit_json(changed=False, result="Host macro %s already exists and force is set to no" % macro_name)


if __name__ == '__main__':
    main()
