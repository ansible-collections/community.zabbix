#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, ONODERA Masaru <masaru-onodera@ieee.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: zabbix_token

short_description: Create/Update/Generate/Delete Zabbix token.

description:
    - This module allows you to create, update, generate and delete Zabbix token.

author:
    - ONODERA Masaru(@masa-orca)

requirements:
    - "python >= 3.9"

version_added: 2.1.0

options:
    name:
        description:
            - Name of the token.
        required: true
        type: str
    description:
        description:
            - Description of the token.
        required: false
        type: str
    username:
        description:
            - Name of user who is the token assinged to.
        required: true
        type: str
    status:
        description:
            - Status of the token.
        required: false
        type: bool
    expires_at:
        description:
            - A timestamp of the token will be expired.
            - The token will never expire if C(0)
        required: false
        type: int
    generate_token:
        description:
            - New token string will be generated if C(true).
        required: false
        type: bool
        default: false
    state:
        description:
            - Create or delete token.
        type: str
        default: present
        choices:
            - present
            - absent

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

- name: Create Zabbix token and generate token string
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_token:
    name: test token
    description: Admin test token
    username: Admin
    status: true
    expires_at: 1700000000
    generate_token: true
    state: present
"""

RETURN = """
msg:
    description: The result of the operation
    returned: success
    type: str
    sample: "Successfully created token"
token:
    description: Generated token string
    returned: I(generate_token=true)
    type: str
    sample: "8ec0d52432c15c91fcafe9888500cf9a607f44091ab554dbee860f6b44fac895"
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class Token(ZabbixBase):
    def get_userid_from_name(self, username):
        try:
            userids = self._zapi.user.get(
                {"output": "userid", "filter": {"username": username}}
            )
            if not userids or len(userids) > 1:
                self._module.fail_json("User '%s' cannot be found" % username)
            return userids[0]["userid"]
        except Exception as e:
            self._module.fail_json(msg="Failed to get userid: %s" % e)

    # get token
    def get_token(self, name, userid):
        try:
            return self._zapi.token.get(
                {"output": "extend", "userids": [userid], "filter": {"name": name}}
            )
        except Exception as e:
            self._module.fail_json(msg="Failed to get token: %s" % e)

    def create_token(
        self, name, description, userid, status, expires_at, generate_token
    ):
        try:
            params = {}
            params["name"] = name
            if isinstance(description, str):
                params["description"] = description

            params["userid"] = userid

            if isinstance(status, bool):
                if status:
                    params["status"] = "1"
                else:
                    params["status"] = "0"

            if isinstance(expires_at, str):
                params["expires_at"] = str(expires_at)

            if self._module.check_mode:
                self._module.exit_json(changed=True)
            result = self._zapi.token.create(params)

            if generate_token:
                generated_tokens = self._zapi.token.generate(result["tokenids"])
                self._module.exit_json(
                    changed=True,
                    msg="Successfully created token.",
                    token=generated_tokens[0]["token"],
                )
            else:
                self._module.exit_json(changed=True, msg="Successfully created token.")

        except Exception as e:
            self._module.fail_json(msg="Failed to create token: %s" % e)

    def update_token(
        self, token, name, description, status, expires_at, generate_token
    ):
        try:
            params = {}
            params["tokenid"] = token["tokenid"]
            params["name"] = name
            if isinstance(description, str) and description != token["description"]:
                params["description"] = description

            if isinstance(status, bool):
                if status:
                    if token["status"] != "0":
                        params["status"] = "0"
                else:
                    if token["status"] != "1":
                        params["status"] = "1"

            if isinstance(expires_at, int) and str(expires_at) != token["expires_at"]:
                params["expires_at"] = str(expires_at)

            # If params does not have any parameter except tokenid and name, no need to update.
            if len(params.keys()) == 2:
                if not generate_token:
                    self._module.exit_json(changed=False)
                elif self._module.check_mode:
                    self._module.exit_json(changed=True)
            else:
                if self._module.check_mode:
                    self._module.exit_json(changed=True)
                self._zapi.token.update(params)

            if generate_token:
                generated_tokens = self._zapi.token.generate([token["tokenid"]])
                self._module.exit_json(
                    changed=True,
                    msg="Successfully updated token.",
                    token=generated_tokens[0]["token"],
                )
            else:
                self._module.exit_json(changed=True, msg="Successfully updated token.")

        except Exception as e:
            self._module.fail_json(msg="Failed to update token: %s" % e)

    # delete token
    def delete_token(self, token):
        try:
            tokenid = token["tokenid"]
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            self._zapi.token.delete([tokenid])
            self._module.exit_json(changed=True, msg="Successfully deleted token.")
        except Exception as e:
            self._module.fail_json(msg="Failed to delete token: %s" % e)


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            description=dict(type="str"),
            username=dict(type="str", required=True),
            status=dict(type="bool"),
            expires_at=dict(type="int"),
            generate_token=dict(type="bool", default=False),
            state=dict(type="str", choices=["present", "absent"], default="present"),
        )
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    name = module.params["name"]
    description = module.params["description"]
    username = module.params["username"]
    status = module.params["status"]
    expires_at = module.params["expires_at"]
    generate_token = module.params["generate_token"]
    state = module.params["state"]

    token_class_obj = Token(module)
    userid = token_class_obj.get_userid_from_name(username)
    tokens = token_class_obj.get_token(name, userid)
    if state == "absent":
        if len(tokens) == 1:
            token_class_obj.delete_token(tokens[0])
        else:
            module.exit_json(changed=False)
    else:
        if len(tokens) == 1:
            token_class_obj.update_token(
                tokens[0], name, description, status, expires_at, generate_token
            )
        else:
            token_class_obj.create_token(
                name, description, userid, status, expires_at, generate_token
            )


if __name__ == "__main__":
    main()
