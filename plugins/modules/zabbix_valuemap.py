#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2019, Ruben Tsirunyan <rubentsirunyan@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: zabbix_valuemap
short_description: Create/update/delete Zabbix value maps
description:
    - This module allows you to create, modify and delete Zabbix value maps.
author:
    - "Ruben Tsirunyan (@rubentsirunyan)"
requirements:
    - "python >= 2.6"
options:
    name:
        type: 'str'
        description:
            - Name of the value map.
        required: true
    state:
        type: 'str'
        description:
            - State of the value map.
            - On C(present), it will create a value map if it does not exist or update the value map if the associated data is different.
            - On C(absent), it will remove the value map if it exists.
        choices: ['present', 'absent']
        default: 'present'
    mappings:
        type: 'list'
        elements: dict
        description:
            - List of value mappings for the value map.
            - Required when I(state=present).
        suboptions:
            value:
                type: 'str'
                description: Original value.
                required: true
            map_to:
                type: 'str'
                description: Value to which the original value is mapped to.
                required: true

extends_documentation_fragment:
- community.zabbix.zabbix

'''

RETURN = r'''
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

- name: Create a value map
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_valuemap:
    name: Numbers
    mappings:
      - value: 1
        map_to: one
      - value: 2
        map_to: two
    state: present
'''

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


def construct_parameters(**kwargs):
    """Translates data to a format suitable for Zabbix API

    Args:
        **kwargs: Arguments passed to the module.

    Returns:
        A dictionary of arguments in a format that is understandable by Zabbix API.
    """
    if kwargs['mappings'] is None:
        return dict(
            name=kwargs['name']
        )

    return dict(
        name=kwargs['name'],
        mappings=[
            dict(
                value=mapping['value'],
                newvalue=mapping['map_to']
            ) for mapping in kwargs['mappings']
        ]
    )


def diff(existing, new):
    """Constructs the diff for Ansible's --diff option.

    Args:
        existing (dict): Existing valuemap data.
        new (dict): New valuemap data.

    Returns:
        A dictionary like {'before': existing, 'after': new}
        with filtered empty values.
    """
    before = {}
    after = {}
    for key in new:
        before[key] = existing[key]
        if new[key] is None:
            after[key] = ''
        else:
            after[key] = new[key]

    return {'before': before, 'after': after}


def get_update_params(existing_valuemap, **kwargs):
    """Filters only the parameters that are different and need to be updated.

    Args:
        existing_valuemap (dict): Existing valuemap.
        **kwargs: Parameters for the new valuemap.

    Returns:
        A tuple where the first element is a dictionary of parameters
        that need to be updated and the second one is a dictionary
        returned by diff() function with
        existing valuemap data and new params passed to it.
    """

    params_to_update = {}
    if sorted(existing_valuemap['mappings'], key=lambda k: k['value']) != sorted(kwargs['mappings'], key=lambda k: k['value']):
        params_to_update['mappings'] = kwargs['mappings']
    return params_to_update, diff(existing_valuemap, kwargs)


class ValuemapModule(ZabbixBase):
    def check_if_valuemap_exists(self, name):
        """Checks if value map exists.

        Args:
            name: Zabbix valuemap name

        Returns:
            tuple: First element is True if valuemap exists and False otherwise.
                Second element is a dictionary of valuemap object if it exists.
        """
        try:
            valuemap_list = self._zapi.valuemap.get({
                'output': 'extend',
                'selectMappings': 'extend',
                'filter': {'name': [name]}
            })
            if len(valuemap_list) < 1:
                return False, None
            else:
                return True, valuemap_list[0]
        except Exception as e:
            self._module.fail_json(msg="Failed to get ID of the valuemap '{name}': {e}".format(name=name, e=e))

    def delete(self, valuemap_id):
        try:
            return self._zapi.valuemap.delete([valuemap_id])
        except Exception as e:
            self._module.fail_json(msg="Failed to delete valuemap '{_id}': {e}".format(_id=valuemap_id, e=e))

    def update(self, **kwargs):
        try:
            self._zapi.valuemap.update(kwargs)
        except Exception as e:
            self._module.fail_json(msg="Failed to update valuemap '{_id}': {e}".format(_id=kwargs['valuemapid'], e=e))

    def create(self, **kwargs):
        try:
            self._zapi.valuemap.create(kwargs)
        except Exception as e:
            self._module.fail_json(msg="Failed to create valuemap '{name}': {e}".format(name=kwargs['description'], e=e))


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        name=dict(type='str', required=True),
        state=dict(type='str', default='present', choices=['present', 'absent']),
        mappings=dict(
            type='list',
            elements='dict',
            options=dict(
                value=dict(type='str', required=True),
                map_to=dict(type='str', required=True)
            )
        )
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ['state', 'present', ['mappings']],
        ]
    )

    zabbix_utils.require_creds_params(module)

    for p in ['server_url', 'login_user', 'login_password', 'timeout', 'validate_certs']:
        if p in module.params and not module.params[p] is None:
            module.warn('Option "%s" is deprecated with the move to httpapi connection and will be removed in the next release' % p)
    vm = ValuemapModule(module)

    name = module.params['name']
    state = module.params['state']
    mappings = module.params['mappings']

    valuemap_exists, valuemap_object = vm.check_if_valuemap_exists(name)

    parameters = construct_parameters(
        name=name,
        mappings=mappings
    )

    if valuemap_exists:
        valuemap_id = valuemap_object['valuemapid']
        if state == 'absent':
            if module.check_mode:
                module.exit_json(
                    changed=True,
                    msg="Value map would have been deleted. Name: {name}, ID: {_id}".format(
                        name=name,
                        _id=valuemap_id
                    )
                )
            valuemap_id = vm.delete(valuemap_id)
            module.exit_json(
                changed=True,
                msg="Value map deleted. Name: {name}, ID: {_id}".format(
                    name=name,
                    _id=valuemap_id
                )
            )
        else:
            params_to_update, diff = get_update_params(valuemap_object, **parameters)
            if params_to_update == {}:
                module.exit_json(
                    changed=False,
                    msg="Value map is up to date: {name}".format(name=name)
                )
            else:
                if module.check_mode:
                    module.exit_json(
                        changed=True,
                        diff=diff,
                        msg="Value map would have been updated. Name: {name}, ID: {_id}".format(
                            name=name,
                            _id=valuemap_id
                        )
                    )
                valuemap_id = vm.update(valuemapid=valuemap_id, **params_to_update)
                module.exit_json(
                    changed=True,
                    diff=diff,
                    msg="Value map updated. Name: {name}, ID: {_id}".format(
                        name=name,
                        _id=valuemap_id
                    )
                )
    else:
        if state == "absent":
            module.exit_json(changed=False)
        else:
            if module.check_mode:
                module.exit_json(
                    changed=True,
                    msg="Value map would have been created. Name: {name}, ID: {_id}".format(
                        name=name,
                        _id=valuemap_id
                    )
                )
            valuemap_id = vm.create(**parameters)
            module.exit_json(
                changed=True,
                msg="Value map created: {name}, ID: {_id}".format(
                    name=name,
                    _id=valuemap_id
                )
            )


if __name__ == '__main__':
    main()
