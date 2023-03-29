#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, BGmot
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
module: zabbix_script
short_description: Create/update/delete Zabbix scripts
version_added: 1.7.0
author:
    - Evgeny Yurchenko (@BGmot)
description:
    - This module allows you to create, update and delete scripts.
requirements:
    - "python >= 2.6"
options:
    name:
        description:
            - Name of the script.
        required: true
        type: str
    script_type:
        description:
            - Script type.
            - Types C(ssh), C(telnet) and C(webhook) works only with Zabbix >= 5.4.
        type: str
        required: true
        choices: ['script', 'ipmi', 'ssh', 'telnet', 'webhook']
    command:
        description:
            - Command to run.
        type: str
        required: true
    scope:
        description:
            - Script scope.
            - Works only with Zabbix >= 5.4. For lower versions is silently ignored which is equivalent of C(manual_host_action).
        type: str
        required: false
        choices: ['action_operation', 'manual_host_action', 'manual_event_action']
        default: 'action_operation'
    execute_on:
        description:
            - Where to run the script.
            - Used if type is C(script).
        type: str
        required: false
        choices: ['zabbix_agent', 'zabbix_server', 'zabbix_server_proxy']
        default: 'zabbix_server_proxy'
    menu_path:
        description:
            - Folders separated by slash that form a menu like navigation in frontend when clicked on host or event.
            - Used if scope is C(manual_host_action) or C(manual_event_action).
            - Works only with Zabbix >= 5.4. For lower versions is silently ignored. Prepend menu path to name instead.
        type: str
        required: false
    authtype:
        description:
            - Authentication method used for SSH script type.
            - Used if type is C(ssh).
        type: str
        required: false
        choices: ['password', 'public_key']
    username:
        description:
            - User name used for authentication.
            - Used if type is C(ssh) or C(telnet)
        type: str
        required: false
    password:
        description:
            - Password used for SSH scripts with password authentication and Telnet scripts.
            - Used if type is C(ssh) and authtype is C(password) or type is C(telnet).
        type: str
        required: false
    publickey:
        description:
            - Name of the public key file used for SSH scripts with public key authentication.
            - Used if type is C(ssh) and authtype is C(public_key).
        type: str
        required: false
    privatekey:
        description:
            - Name of the private key file used for SSH scripts with public key authentication.
            - Used if type is C(ssh) and authtype is C(public_key).
        type: str
        required: false
    port:
        description:
            - Port number used for SSH and Telnet scripts.
            - Used if type is C(ssh) or C(telnet).
        type: str
        required: false
    host_group:
        description:
            - host group name that the script can be run on. If set to 'all', the script will be available on all host groups.
        type: str
        required: false
        default: 'all'
    user_group:
        description:
            - user group name that will be allowed to run the script. If set to 'all', the script will be available for all user groups.
            - Used if scope is C(manual_host_action) or C(manual_event_action).
        type: str
        required: false
        default: 'all'
    host_access:
        description:
            - Host permissions needed to run the script.
            - Used if scope is C(manual_host_action) or C(manual_event_action).
        type: str
        required: false
        choices: ['read', 'write']
        default: 'read'
    confirmation:
        description:
            - Confirmation pop up text. The pop up will appear when trying to run the script from the Zabbix frontend.
            - Used if scope is C(manual_host_action) or C(manual_event_action).
        type: str
        required: false
    script_timeout:
        description:
            - Webhook script execution timeout in seconds. Time suffixes are supported, e.g. 30s, 1m.
            - Required if type is C(webhook).
            - 'Possible values: 1-60s.'
        type: str
        default: '30s'
        required: false
    parameters:
        description:
            - Array of webhook input parameters.
            - Used if type is C(webhook).
        type: list
        elements: dict
        suboptions:
            name:
                description:
                    - Parameter name.
                type: str
                required: true
            value:
                description:
                    - Parameter value. Supports macros.
                type: str
                required: false
                default: ''
    description:
        description:
            - Description of the script.
        type: str
        required: false
    state:
        description:
            - State of the script.
        type: str
        required: false
        choices: ['present', 'absent']
        default: 'present'
extends_documentation_fragment:
- community.zabbix.zabbix

'''

EXAMPLES = '''
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

- name: test - Create new action operation script to execute webhook
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  zabbix_script:
    name: Test action operation script
    scope: action_operation
    script_type: webhook
    command: 'return 0'
    description: "Test action operation script"
    state: present
'''

RETURN = '''
'''


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
from ansible.module_utils.compat.version import LooseVersion
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class Script(ZabbixBase):
    def get_script_ids(self, script_name):
        script_ids = []
        scripts = self._zapi.script.get({'filter': {'name': script_name}})
        for script in scripts:
            script_ids.append(script['scriptid'])
        return script_ids

    def create_script(self, name, script_type, command, scope, execute_on, menu_path, authtype, username, password,
                      publickey, privatekey, port, host_group, user_group, host_access, confirmation, script_timeout, parameters, description):
        if self._module.check_mode:
            self._module.exit_json(changed=True)

        self._zapi.script.create(self.generate_script_config(name, script_type, command, scope, execute_on, menu_path,
                                 authtype, username, password, publickey, privatekey, port, host_group, user_group, host_access, confirmation,
                                 script_timeout, parameters, description))

    def delete_script(self, script_ids):
        if self._module.check_mode:
            self._module.exit_json(changed=True)
        self._zapi.script.delete(script_ids)

    def generate_script_config(self, name, script_type, command, scope, execute_on, menu_path, authtype, username, password,
                               publickey, privatekey, port, host_group, user_group, host_access, confirmation, script_timeout, parameters, description):
        if host_group == 'all':
            groupid = '0'
        else:
            groups = self._zapi.hostgroup.get({'filter': {'name': host_group}})
            if not groups:
                self._module.fail_json(changed=False, msg='Host group "%s" not found' % host_group)
            groupid = groups[0]['groupid']

        if user_group == 'all':
            usrgrpid = '0'
        else:
            user_groups = self._zapi.usergroup.get({'filter': {'name': user_group}})
            if not user_groups:
                self._module.fail_json(changed=False, msg='User group "%s" not found' % user_group)
            usrgrpid = user_groups[0]['usrgrpid']

        request = {
            'name': name,
            'type': str(zabbix_utils.helper_to_numeric_value([
                'script',
                'ipmi',
                'ssh',
                'telnet',
                '',
                'webhook'], script_type)),
            'command': command,
            'scope': str(zabbix_utils.helper_to_numeric_value([
                '',
                'action_operation',
                'manual_host_action',
                '',
                'manual_event_action'], scope)),
            'groupid': groupid
        }

        if description is not None:
            request['description'] = description

        if script_type == 'script':
            if execute_on is None:
                execute_on = 'zabbix_server_proxy'
            request['execute_on'] = str(zabbix_utils.helper_to_numeric_value([
                'zabbix_agent',
                'zabbix_server',
                'zabbix_server_proxy'], execute_on))

        if scope in ['manual_host_action', 'manual_event_action']:
            if menu_path is None:
                request['menu_path'] = ''
            else:
                request['menu_path'] = menu_path
            request['usrgrpid'] = usrgrpid
            request['host_access'] = str(zabbix_utils.helper_to_numeric_value([
                '',
                '',
                'read',
                'write'], host_access))
            if confirmation is None:
                request['confirmation'] = ''
            else:
                request['confirmation'] = confirmation

        if script_type == 'ssh':
            if authtype is None:
                self._module.fail_json(changed=False, msg='authtype must be provided for ssh script type')
            request['authtype'] = str(zabbix_utils.helper_to_numeric_value([
                'password',
                'public_key'], authtype))
            if authtype == 'public_key':
                if publickey is None or privatekey is None:
                    self._module.fail_json(changed=False, msg='publickey and privatekey must be provided for ssh script type with publickey authtype')
                request['publickey'] = publickey
                request['privatekey'] = privatekey

        if script_type in ['ssh', 'telnet']:
            if username is None:
                self._module.fail_json(changed=False, msg='username must be provided for "ssh" and "telnet" script types')
            request['username'] = username
            if (script_type == 'ssh' and authtype == 'password') or script_type == 'telnet':
                if password is None:
                    self._module.fail_json(changed=False, msg='password must be provided for telnet script type or ssh script type with password autheype')
                request['password'] = password
            if port is not None:
                request['port'] = port

        if script_type == 'webhook':
            request['timeout'] = script_timeout
            if parameters:
                request['parameters'] = parameters

        if LooseVersion(self._zbx_api_version) < LooseVersion('5.4'):
            if script_type not in ['script', 'ipmi']:
                self._module.fail_json(changed=False, msg='script_type must be script or ipmi in version <5.4')
            if 'scope' in request:
                del request['scope']
            if 'menu_path' in request:
                del request['menu_path']

        return request

    def update_script(self, script_id, name, script_type, command, scope, execute_on, menu_path, authtype, username, password,
                      publickey, privatekey, port, host_group, user_group, host_access, confirmation, script_timeout, parameters, description):
        generated_config = self.generate_script_config(name, script_type, command, scope, execute_on, menu_path, authtype, username,
                                                       password, publickey, privatekey, port, host_group, user_group, host_access,
                                                       confirmation, script_timeout, parameters, description)
        live_config = self._zapi.script.get({'filter': {'name': name}})[0]

        change_parameters = {}
        difference = zabbix_utils.helper_cleanup_data(zabbix_utils.helper_compare_dictionaries(generated_config, live_config, change_parameters))

        if not difference:
            self._module.exit_json(changed=False, msg="Script %s up to date" % name)

        if self._module.check_mode:
            self._module.exit_json(changed=True)
        generated_config['scriptid'] = live_config['scriptid']
        self._zapi.script.update(generated_config)
        self._module.exit_json(changed=True, msg="Script %s updated" % name)


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        name=dict(type='str', required=True),
        script_type=dict(
            type='str',
            required=True,
            choices=['script', 'ipmi', 'ssh', 'telnet', 'webhook']),
        command=dict(type='str', required=True),
        scope=dict(
            type='str',
            required=False,
            choices=['action_operation', 'manual_host_action', 'manual_event_action'],
            default='action_operation'),
        execute_on=dict(
            type='str',
            required=False,
            choices=['zabbix_agent', 'zabbix_server', 'zabbix_server_proxy'],
            default='zabbix_server_proxy'),
        menu_path=dict(type='str', required=False),
        authtype=dict(
            type='str',
            required=False,
            choices=['password', 'public_key']),
        username=dict(type='str', required=False),
        password=dict(type='str', required=False, no_log=True),
        publickey=dict(type='str', required=False),
        privatekey=dict(type='str', required=False, no_log=True),
        port=dict(type='str', required=False),
        host_group=dict(type='str', required=False, default='all'),
        user_group=dict(type='str', required=False, default='all'),
        host_access=dict(
            type='str',
            required=False,
            choices=['read', 'write'],
            default='read'),
        confirmation=dict(type='str', required=False),
        script_timeout=dict(type='str', default='30s', required=False),
        parameters=dict(
            type='list',
            elements='dict',
            options=dict(
                name=dict(type='str', required=True),
                value=dict(type='str', required=False, default='')
            )
        ),
        description=dict(type='str', required=False),
        state=dict(
            type='str',
            required=False,
            default='present',
            choices=['present', 'absent'])
    ))

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    zabbix_utils.require_creds_params(module)

    for p in ['server_url', 'login_user', 'login_password', 'timeout', 'validate_certs']:
        if p in module.params and not module.params[p] is None:
            module.warn('Option "%s" is deprecated with the move to httpapi connection and will be removed in the next release' % p)

    name = module.params['name']
    script_type = module.params['script_type']
    command = module.params['command']
    scope = module.params['scope']
    execute_on = module.params['execute_on']
    menu_path = module.params['menu_path']
    authtype = module.params['authtype']
    username = module.params['username']
    password = module.params['password']
    publickey = module.params['publickey']
    privatekey = module.params['privatekey']
    port = module.params['port']
    host_group = module.params['host_group']
    user_group = module.params['user_group']
    host_access = module.params['host_access']
    confirmation = module.params['confirmation']
    script_timeout = module.params['script_timeout']
    parameters = module.params['parameters']
    description = module.params['description']
    state = module.params['state']

    script = Script(module)
    script_ids = script.get_script_ids(name)

    # Delete script
    if state == "absent":
        if not script_ids:
            module.exit_json(changed=False, msg="Script not found, no change: %s" % name)
        script.delete_script(script_ids)
        module.exit_json(changed=True, result="Successfully deleted script(s) %s" % name)

    elif state == "present":
        if not script_ids:
            script.create_script(name, script_type, command, scope, execute_on, menu_path, authtype, username, password,
                                 publickey, privatekey, port, host_group, user_group, host_access, confirmation, script_timeout, parameters, description)
            module.exit_json(changed=True, msg="Script %s created" % name)
        else:
            script.update_script(script_ids[0], name, script_type, command, scope, execute_on, menu_path, authtype, username,
                                 password, publickey, privatekey, port, host_group, user_group, host_access, confirmation,
                                 script_timeout, parameters, description)


if __name__ == "__main__":
    main()
