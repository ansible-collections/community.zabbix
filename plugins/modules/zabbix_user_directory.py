#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: zabbix_user_directory
short_description: Create/update/delete Zabbix user directories
description:
   - This module allows you to create, modify and delete Zabbix user directories.
author:
    - Evgeny Yurchenko (@BGmot)
requirements:
    - python >= 3.9
    - zabbix-api >= 0.5.4
options:
    name:
        description:
            - Unique name of the user directory.
        required: true
        type: str
    host:
        description:
            - LDAP server host name, IP or URI. URI should contain schema, host and port (optional).
        required: false
        type: str
    port:
        description:
            - LDAP server port.
        required: false
        type: int
    base_dn:
        description:
            - LDAP base distinguished name string.
        required: false
        type: str
    search_attribute:
        description:
            - LDAP attribute name to identify user by username in Zabbix database.
        required: false
        type: str
    bind_dn:
        description:
            - LDAP bind distinguished name string. Can be empty for anonymous binding.
        required: false
        type: str
    bind_password:
        description:
            - LDAP bind password. Can be empty for anonymous binding.
            - Available only for I(present) C(state).
        required: false
        type: str
    description:
        description:
            - User directory description.
        required: false
        type: str
    search_filter:
        description:
            - LDAP custom filter string when authenticating user in LDAP.
        default: (%{attr}=%{user})
        required: false
        type: str
    start_tls:
        description:
            - LDAP startTLS option. It cannot be used with ldaps:// protocol hosts.
        required: false
        type: int
        choices: [0, 1]
        default: 0
    state:
        description:
            - State of the user directory.
            - On C(present), it will create if user directory does not exist or update it if the associated data is different.
            - On C(absent) will remove the user directory if it exists.
        choices: ['present', 'absent']
        default: 'present'
        type: str

extends_documentation_fragment:
- community.zabbix.zabbix

'''

EXAMPLES = r'''
---
- name: Create new user directory or update existing info
  community.zabbix.zabbix_user_directory:
    server_url: http://monitor.example.com
    login_user: username
    login_password: password
    state: present
    name: TestUserDirectory
    host: 'test.com'
    port: 389
    base_dn: 'ou=Users,dc=example,dc=org'
    search_attribute: 'uid'
    bind_dn: 'cn=ldap_search,dc=example,dc=org'
    description: 'Test user directory'
    search_filter: '(%{attr}=test_user)'
    start_tls: 0
'''


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
from ansible_collections.community.zabbix.plugins.module_utils.version import LooseVersion
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        name=dict(type='str', required=True),
        host=dict(type='str', required=False),
        port=dict(type='int', required=False),
        base_dn=dict(type='str', required=False),
        search_attribute=dict(type='str', required=False),
        bind_dn=dict(type='str', required=False, default=''),
        bind_password=dict(type='str', required=False, no_log=True),
        description=dict(type='str', required=False, default=''),
        search_filter=dict(type='str', default='(%{attr}=%{user})', required=False),
        start_tls=dict(type='int', required=False, choices=[0, 1], default=0),
        state=dict(type='str', default='present', choices=['present', 'absent']),
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    parameters = {
        'name': module.params['name'],
        'search_filter': module.params['search_filter']
    }
    for p in ['host', 'port', 'base_dn', 'search_attribute', 'bind_dn', 'bind_password', 'description', 'start_tls']:
        if module.params[p]:
            if p in ['port', 'start_tls']:
                parameters[p] = str(module.params[p])
            else:
                parameters[p] = module.params[p]

    state = module.params['state']

    user_directory = ZabbixBase(module)
    if LooseVersion(user_directory._zbx_api_version) < LooseVersion('6.2'):
        module.fail_json(msg='Zabbix < 6.2 does not support user directories.')

    directory = user_directory._zapi.userdirectory.get({'filter': {'name': parameters['name']}})

    if not directory:
        # No User Directory found with given name
        if state == 'absent':
            module.exit_json(changed=False, msg='User directory not found. Not changed: %s' % parameters['name'])

        elif state == 'present':
            if module.check_mode:
                module.exit_json(changed=True)
            else:
                for p in ['host', 'port', 'base_dn', 'search_attribute']:
                    if p not in parameters:
                        module.fail_json(msg='host, port, base_dn and search_attribute are mandatory parameters to create a user directory')
                user_directory._zapi.userdirectory.create(parameters)
                module.exit_json(changed=True, result='Successfully added user directory %s' % parameters['name'])
    else:
        # User Directory with given name exists
        if state == 'absent':
            user_directory._zapi.userdirectory.delete([directory[0]['userdirectoryid']])
            module.exit_json(changed=True, result='Successfully deleted user directory %s' % parameters['name'])
        elif state == 'present':
            diff_dict = {}
            if zabbix_utils.helper_compare_dictionaries(parameters, directory[0], diff_dict):
                parameters['userdirectoryid'] = directory[0]['userdirectoryid']
                user_directory._zapi.userdirectory.update(parameters)
                module.exit_json(changed=True, result='Successfully updated user directory %s' % parameters['name'])
            else:
                module.exit_json(changed=False, result='User directory %s is up-to date' % parameters['name'])

            module.exit_json(changed=False, result='User directory %s is up-to date' % parameters['name'])


if __name__ == '__main__':
    main()
