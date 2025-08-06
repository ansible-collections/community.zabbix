#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, BGmot
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
module: zabbix_script
short_description: Create/update/delete Zabbix scripts
version_added: 1.7.0
author:
    - Evgeny Yurchenko (@BGmot)
description:
    - This module allows you to create, update and delete scripts.
requirements:
    - "python >= 3.9"
options:
    name:
        description:
            - Name of the script.
        required: true
        type: str
    script_type:
        description:
            - Script type. Required when state is 'present'.
            - A value of 'url' is only available in 7.0 or later
        type: str
        required: false
        choices: ["script", "ipmi", "ssh", "telnet", "webhook", "url"]
    url:
        description:
            - The URL for quick access
            - Required if script_type is C(url)
            - Only available if script_type is C(url)
        type: str
    new_window:
        description:
            - Should URL be opened in a new window?
            - Only available if script_type is C(url)
        type: bool
        default: true
    command:
        description:
            - Command to run. Required when state is 'present'
        type: str
        required: false
    scope:
        description:
            - Script scope.
        type: str
        required: false
        choices: ["action_operation", "manual_host_action", "manual_event_action"]
        default: "action_operation"
    execute_on:
        description:
            - Where to run the script.
            - Used if type is C(script).
        type: str
        required: false
        choices: ["zabbix_agent", "zabbix_server", "zabbix_server_proxy"]
        default: "zabbix_server_proxy"
    menu_path:
        description:
            - Folders separated by slash that form a menu like navigation in frontend when clicked on host or event.
            - Used if scope is C(manual_host_action) or C(manual_event_action).
        type: str
        required: false
    authtype:
        description:
            - Authentication method used for SSH script type.
            - Used if type is C(ssh).
        type: str
        required: false
        choices: ["password", "public_key"]
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
            - host group name that the script can be run on. If set to "all", the script will be available on all host groups.
        type: str
        required: false
        default: "all"
    user_group:
        description:
            - user group name that will be allowed to run the script. If set to "all", the script will be available for all user groups.
            - Used if scope is C(manual_host_action) or C(manual_event_action).
        type: str
        required: false
        default: "all"
    host_access:
        description:
            - Host permissions needed to run the script.
            - Used if scope is C(manual_host_action) or C(manual_event_action).
        type: str
        required: false
        choices: ["read", "write"]
        default: "read"
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
            - "Possible values: 1-60s."
        type: str
        default: "30s"
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
                    - Parameter name. Required when 'parameters' is specified for a 'webhook' script.
                type: str
                required: false
            value:
                description:
                    - Parameter value. Supports macros.
                type: str
                required: false
                default: ""
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
        choices: ["present", "absent"]
        default: "present"
    user_input_enabled:
        description:
            - Allow advanced user input configuration
            - Available for Zabbix >= 7.0.
        type: bool
        default: false
    user_input_prompt:
        description:
            - Prompt to display when user input is enabled
            - Required when user_input_enabled is C(True)
            - Available for Zabbix >= 7.0.
        type: str
    user_input_type:
        description:
            - Choosing 'regex' allows the use of a regular expression
            - Choosing 'dropdown' allows a pre-defined list of choices
            - Required if user_input_enabled is C(true)
            - Available for Zabbix >= 7.0.
        type: str
        choices: ["regex", "dropdown"]
    user_input_regex:
        description:
            - A regular expression to validate user input
            - Required if user_input_type is C(regex)
            - Available for Zabbix >= 7.0.
        type: str
    user_input_list:
        description:
            - A list of possible choices for the user.
            - Required if user_input_type is C(dropdown).
            - NOTE the first option will be the default.
            - Available for Zabbix >= 7.0.
        type: list
        elements: str
    user_input_default_input:
        description:
            - Default user input
            - Available if user_input_type is C(regex)
            - Available for Zabbix >= 7.0.
        type: str
extends_documentation_fragment:
- community.zabbix.zabbix

"""

EXAMPLES = """
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

- name: test - Create new action operation script to execute webhook
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_script:
    name: Test action operation script
    scope: action_operation
    script_type: webhook
    command: "return 0"
    description: "Test action operation script"
    state: present
"""

RETURN = """
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils
from ansible.module_utils.compat.version import LooseVersion


class Script(ZabbixBase):
    def get_script_ids(self, script_name):
        script_ids = []
        scripts = self._zapi.script.get({"filter": {"name": script_name}})
        for script in scripts:
            script_ids.append(script["scriptid"])
        return script_ids

    def create_script(self, name, script_type, command, scope, execute_on, menu_path, authtype, username, password,
                      publickey, privatekey, port, host_group, user_group, host_access, confirmation, script_timeout,
                      parameters, description, url, new_window, user_input_enabled, user_input_type, user_input_regex,
                      user_input_list, user_input_default_input, user_input_prompt):
        if self._module.check_mode:
            self._module.exit_json(changed=True)

        self._zapi.script.create(self.generate_script_config(name, script_type, command, scope, execute_on, menu_path,
                                 authtype, username, password, publickey, privatekey, port, host_group, user_group,
                                 host_access, confirmation, script_timeout, parameters, description, url, new_window,
                                 user_input_enabled, user_input_type, user_input_regex, user_input_list,
                                 user_input_default_input, user_input_prompt))

    def delete_script(self, script_ids):
        if self._module.check_mode:
            self._module.exit_json(changed=True)
        self._zapi.script.delete(script_ids)

    def generate_script_config(self, name, script_type, command, scope, execute_on, menu_path, authtype, username, password,
                               publickey, privatekey, port, host_group, user_group, host_access, confirmation, script_timeout,
                               parameters, description, url, new_window, user_input_enabled, user_input_type, user_input_regex,
                               user_input_list, user_input_default_input, user_input_prompt):
        if host_group == "all":
            groupid = "0"
        else:
            groups = self._zapi.hostgroup.get({"filter": {"name": host_group}})
            if not groups:
                self._module.fail_json(changed=False, msg="Host group '%s' not found" % host_group)
            groupid = groups[0]["groupid"]

        if user_group == "all":
            usrgrpid = "0"
        else:
            user_groups = self._zapi.usergroup.get({"filter": {"name": user_group}})
            if not user_groups:
                self._module.fail_json(changed=False, msg="User group '%s' not found" % user_group)
            usrgrpid = user_groups[0]["usrgrpid"]

        request = {
            "name": name,
            "type": str(zabbix_utils.helper_to_numeric_value([
                "script",
                "ipmi",
                "ssh",
                "telnet",
                "",
                "webhook",
                "url"], script_type)),
            "scope": str(zabbix_utils.helper_to_numeric_value([
                "",
                "action_operation",
                "manual_host_action",
                "",
                "manual_event_action"], scope)),
            "groupid": groupid
        }

        if command:
            request["command"] = command

        if description is not None:
            request["description"] = description

        if script_type == "script":
            if execute_on is None:
                execute_on = "zabbix_server_proxy"
            request["execute_on"] = str(zabbix_utils.helper_to_numeric_value([
                "zabbix_agent",
                "zabbix_server",
                "zabbix_server_proxy"], execute_on))

        if scope in ["manual_host_action", "manual_event_action"]:
            if menu_path is None:
                request["menu_path"] = ""
            else:
                request["menu_path"] = menu_path
            request["usrgrpid"] = usrgrpid
            request["host_access"] = str(zabbix_utils.helper_to_numeric_value([
                "",
                "",
                "read",
                "write"], host_access))
            if confirmation is None:
                request["confirmation"] = ""
            else:
                request["confirmation"] = confirmation

        if script_type == "url":
            request["url"] = url
            if new_window:
                request["new_window"] = "1"
            else:
                request["new_window"] = "0"

        if script_type == "ssh":
            request["authtype"] = str(zabbix_utils.helper_to_numeric_value([
                "password",
                "public_key"], authtype))
            if authtype == "public_key":
                request["publickey"] = publickey
                request["privatekey"] = privatekey

        if script_type in ["ssh", "telnet"]:
            request["username"] = username
            if (script_type == "ssh" and authtype == "password") or script_type == "telnet":
                request["password"] = password
            if port is not None:
                request["port"] = port

        if script_type == "webhook":
            request["timeout"] = script_timeout
            if parameters:
                for parameter in parameters:
                    if "name" not in parameter.keys() or parameter["name"] is None:
                        self._module.fail_json(msg="When providing parameters to a webhook script, the 'name' option is required.")
                request["parameters"] = parameters

        if user_input_enabled:
            request["manualinput_prompt"] = user_input_prompt
            request["manualinput"] = "1"
            if user_input_type == "regex":
                request["manualinput_validator_type"] = "0"
                request["manualinput_validator"] = user_input_regex
                if user_input_default_input:
                    request["manualinput_default_value"] = user_input_default_input

            else:
                request["manualinput_validator_type"] = "1"
                request["manualinput_validator"] = ",".join(user_input_list)

        return request

    def update_script(self, script_id, name, script_type, command, scope, execute_on, menu_path, authtype, username, password,
                      publickey, privatekey, port, host_group, user_group, host_access, confirmation, script_timeout, parameters,
                      description, url, new_window, user_input_enabled, user_input_type, user_input_regex, user_input_list,
                      user_input_default_input, user_input_prompt):
        generated_config = self.generate_script_config(name, script_type, command, scope, execute_on, menu_path, authtype, username,
                                                       password, publickey, privatekey, port, host_group, user_group, host_access,
                                                       confirmation, script_timeout, parameters, description, url, new_window,
                                                       user_input_enabled, user_input_type, user_input_regex, user_input_list,
                                                       user_input_default_input, user_input_prompt)
        live_config = self._zapi.script.get({"filter": {"name": name}})[0]

        change_parameters = {}
        difference = zabbix_utils.helper_cleanup_data(zabbix_utils.helper_compare_dictionaries(generated_config, live_config, change_parameters))

        if not difference:
            self._module.exit_json(changed=False, msg="Script %s up to date" % name)

        if self._module.check_mode:
            self._module.exit_json(changed=True)
        generated_config["scriptid"] = live_config["scriptid"]
        self._zapi.script.update(generated_config)
        self._module.exit_json(changed=True, msg="Script %s updated" % name)


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        name=dict(type="str", required=True),
        script_type=dict(
            type="str",
            choices=["script", "ipmi", "ssh", "telnet", "webhook", "url"]),
        command=dict(type="str"),
        url=dict(type="str"),
        new_window=dict(type="bool", default=True),
        scope=dict(
            type="str",
            choices=["action_operation", "manual_host_action", "manual_event_action"],
            default="action_operation"),
        execute_on=dict(
            type="str",
            choices=["zabbix_agent", "zabbix_server", "zabbix_server_proxy"],
            default="zabbix_server_proxy"),
        menu_path=dict(type="str"),
        authtype=dict(
            type="str",
            choices=["password", "public_key"]),
        username=dict(type="str"),
        password=dict(type="str", no_log=True),
        publickey=dict(type="str"),
        privatekey=dict(type="str", no_log=True),
        port=dict(type="str"),
        host_group=dict(type="str", default="all"),
        user_group=dict(type="str", default="all"),
        host_access=dict(
            type="str",
            choices=["read", "write"],
            default="read"),
        confirmation=dict(type="str"),
        script_timeout=dict(type="str", default="30s"),
        parameters=dict(
            type="list",
            elements="dict",
            options=dict(
                name=dict(type="str"),
                value=dict(type="str", default="")
            )
        ),
        description=dict(type="str"),
        user_input_enabled=dict(type="bool", default=False),
        user_input_prompt=dict(type="str"),
        user_input_type=dict(type="str", choices=["regex", "dropdown"]),
        user_input_regex=dict(type="str"),
        user_input_list=dict(type="list", elements="str"),
        user_input_default_input=dict(type="str"),
        state=dict(
            type="str",
            default="present",
            choices=["present", "absent"])
    ))

    required_if = [
        ("state", "present", ("script_type",)),
        ("script_type", "ssh", ("authtype", "username", "command",)),
        ("script_type", "url", ("new_window", "url",)),
        ("authtype", "password", ("password",)),
        ("authtype", "public_key", ("publickey", "privatekey",)),
        ("script_type", "telnet", ("username", "password", "command",)),
        ("script_type", "script", ("command",)),
        ("script_type", "ipmi", ("command",)),
        ("script_type", "webhook", ("command",)),
        ("user_input_enabled", True, ("user_input_type", "user_input_prompt",)),
        ("user_input_type", "regex", ("user_input_regex",)),
        ("user_input_type", "dropdown", ("user_input_list",))
    ]

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=required_if,
        supports_check_mode=True
    )

    name = module.params["name"]
    script_type = module.params["script_type"]
    command = module.params["command"]
    scope = module.params["scope"]
    execute_on = module.params["execute_on"]
    menu_path = module.params["menu_path"]
    authtype = module.params["authtype"]
    username = module.params["username"]
    password = module.params["password"]
    publickey = module.params["publickey"]
    privatekey = module.params["privatekey"]
    port = module.params["port"]
    host_group = module.params["host_group"]
    user_group = module.params["user_group"]
    host_access = module.params["host_access"]
    confirmation = module.params["confirmation"]
    script_timeout = module.params["script_timeout"]
    parameters = module.params["parameters"]
    description = module.params["description"]
    state = module.params["state"]
    url = module.params["url"]
    new_window = module.params["new_window"]
    user_input_enabled = module.params["user_input_enabled"]
    user_input_prompt = module.params["user_input_prompt"]
    user_input_type = module.params["user_input_type"]
    user_input_regex = module.params["user_input_regex"]
    user_input_list = module.params["user_input_list"]
    user_input_default_input = module.params["user_input_default_input"]

    script = Script(module)
    script_ids = script.get_script_ids(name)

    # Delete script
    if state == "absent":
        if not script_ids:
            module.exit_json(changed=False, msg="Script not found, no change: %s" % name)
        script.delete_script(script_ids)
        module.exit_json(changed=True, result="Successfully deleted script(s) %s" % name)

    elif state == "present":
        if script_type == "url":
            if LooseVersion(script._zbx_api_version) < LooseVersion('7.0'):
                module.fail_json(changed=False, msg="A type of 'url' is only available for Zabbix >= 7.0")
            if scope not in ["manual_host_action", "manual_event_action"]:
                module.fail_json(changed=False, msg="A scope of '%s' is not valid for type of 'url'" % scope)
        else:
            if url:
                module.fail_json(changed=False, msg="A url can only be set for a type of 'url'")

        if not user_input_enabled:
            FIELDS = {
                "user_input_prompt": user_input_prompt,
                "user_input_type": user_input_type,
                "user_input_regex": user_input_regex,
                "user_input_list": user_input_list,
                "user_input_default_input": user_input_default_input
            }
            for f, v in FIELDS.items():
                if v:
                    module.fail_json(changed=False, msg=f"The attribute '{f}' can't be assigned unless user_input_enabled is 'True'")
        else:
            if LooseVersion(script._zbx_api_version) < LooseVersion('7.0'):
                module.fail_json(changed=False, msg="user_input options are only available for Zabbix >= 7.0")
            if len(user_input_prompt) < 1:
                module.fail_json(changed=False, msg="The attribute 'user_input_prompt' is required when user_input_enabled is 'True'")
            if user_input_type == "dropdown":
                if len(user_input_list) < 1:
                    module.fail_json(changed=False, msg="The attribute 'user_input_list' cannot be empty when user_input_type is 'dropdown'")
                if user_input_regex:
                    module.fail_json(changed=False, msg="The attribute 'user_input_regex' can't be assigned unless user_input_type is 'regex'")
                elif user_input_default_input:
                    module.fail_json(changed=False, msg="The attribute 'user_input_default_input' can't be assigned unless user_input_type is 'regex'")
            elif user_input_list:
                module.fail_json(changed=False, msg="The attribute 'user_input_list' can't be assigned unless user_input_type is 'dropdown'")

        if not script_ids:
            script.create_script(name, script_type, command, scope, execute_on, menu_path, authtype, username, password,
                                 publickey, privatekey, port, host_group, user_group, host_access, confirmation, script_timeout,
                                 parameters, description, url, new_window, user_input_enabled, user_input_type, user_input_regex,
                                 user_input_list, user_input_default_input, user_input_prompt)
            module.exit_json(changed=True, msg="Script %s created" % name)
        else:
            script.update_script(script_ids[0], name, script_type, command, scope, execute_on, menu_path, authtype, username,
                                 password, publickey, privatekey, port, host_group, user_group, host_access, confirmation,
                                 script_timeout, parameters, description, url, new_window, user_input_enabled,
                                 user_input_type, user_input_regex, user_input_list, user_input_default_input, user_input_prompt)


if __name__ == "__main__":
    main()
