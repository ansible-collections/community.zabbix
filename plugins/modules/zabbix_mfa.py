#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2024, ONODERA Masaru <masaru-onodera@ieee.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: zabbix_mfa

short_description: Create/update/delete Zabbix MFA method


description:
    - This module allows you to create, update and delete Zabbix MFA method.

author:
    - ONODERA Masaru(@masa-orca)

requirements:
    - "python >= 3.11"

version_added: 3.1.0

options:
    name:
        description:
            - Name of this MFA method
        type: str
        required: true
    method_type:
        description:
            - A type of this MFA method
        type: str
        choices:
            - "totp"
            - "duo_universal_prompt"
    hash_function:
        description:
            - Type of the hash function for generating TOTP codes.
            - Required when C(method_type=totp).
        type: str
        choices:
            - "sha-1"
            - "sha-256"
            - "sha-512"
    code_length:
        description:
            - Verification code length.
            - Required when C(method_type=totp).
        type: int
        choices:
            - 6
            - 8
    api_hostname:
        description:
            - API hostname provided by the Duo authentication service.
            - Required when C(method_type=duo_universal_prompt).
        type: str
    clientid:
        description:
            - Client ID provided by the Duo authentication service.
            - Required when C(method_type=duo_universal_prompt).
        type: str
    client_secret:
        description:
            - Client secret provided by the Duo authentication service.
            - Required when C(method_type=duo_universal_prompt).
        type: str
    state:
        description:
            - State of this MFA.
        type: str
        choices: ['present', 'absent']
        default: 'present'


notes:
    - Only Zabbix >= 7.0 is supported.
    - This module returns changed=true when I(method_type) is C(duo_universal_prompt) as Zabbix API
      will not return any sensitive information back for module to compare.

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

- name: Create a 'Zabbix TOTP' MFA method
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_mfa:
    name: Zabbix TOTP
    method_type: totp
    hash_function: sha-1
    code_length: 6
"""

RETURN = """
msg:
    description: The result of the creating operation
    returned: success
    type: str
    sample: 'Successfully created MFA method'
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
from ansible.module_utils.compat.version import LooseVersion

import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class MFA(ZabbixBase):
    def __init__(self, module, zbx=None, zapi_wrapper=None):
        super(MFA, self).__init__(module, zbx, zapi_wrapper)
        if LooseVersion(self._zbx_api_version) < LooseVersion("7.0"):
            module.fail_json(
                msg="This module doesn't support Zabbix versions lower than 7.0"
            )

    def get_mfa(self, mfa_name):
        try:
            mfas = self._zapi.mfa.get(
                {
                    "output": "extend",
                    "search": {"name": mfa_name},
                }
            )
            mfa = None
            for _mfa in mfas:
                if (_mfa["name"] == mfa_name):
                    mfa = _mfa
            return mfa
        except Exception as e:
            self._module.fail_json(
                msg="Failed to get MFA method: %s" % e
            )

    def delete_mfa(self, mfa):
        try:
            parameter = [mfa["mfaid"]]
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            self._zapi.mfa.delete(parameter)
            self._module.exit_json(
                changed=True, msg="Successfully deleted MFA method."
            )
        except Exception as e:
            self._module.fail_json(
                msg="Failed to delete MFA method: %s" % e
            )

    def _convert_to_parameter(self, name, method_type, hash_function, code_length, api_hostname, clientid, client_secret):
        parameter = {}
        parameter['name'] = name
        parameter['type'] = str(zabbix_utils.helper_to_numeric_value(
            [
                None,
                "totp",
                "duo_universal_prompt"
            ],
            method_type
        ))
        if (method_type == 'totp'):
            parameter['hash_function'] = str(zabbix_utils.helper_to_numeric_value(
                [
                    None,
                    "sha-1",
                    "sha-256",
                    "sha-512"
                ],
                hash_function
            ))
            parameter['code_length'] = str(code_length)
        else:
            parameter['api_hostname'] = str(api_hostname)
            parameter['clientid'] = str(clientid)
            parameter['client_secret'] = str(client_secret)
        return parameter

    def create_mfa(self, name, method_type, hash_function, code_length, api_hostname, clientid, client_secret):
        parameter = self._convert_to_parameter(name, method_type, hash_function, code_length, api_hostname, clientid, client_secret)
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            self._zapi.mfa.create(parameter)
            self._module.exit_json(
                changed=True, msg="Successfully created MFA method."
            )
        except Exception as e:
            self._module.fail_json(
                msg="Failed to create MFA method: %s" % e
            )

    def update_mfa(self, current_mfa, name, method_type, hash_function, code_length, api_hostname, clientid, client_secret):
        try:
            parameter = self._convert_to_parameter(name, method_type, hash_function, code_length, api_hostname, clientid, client_secret)
            parameter.update({'mfaid': current_mfa['mfaid']})
            if (method_type == 'totp'):
                current_mfa = zabbix_utils.helper_normalize_data(
                    current_mfa, del_keys=["api_hostname", "clientid"]
                )[0]
                difference = {}
                zabbix_utils.helper_compare_dictionaries(parameter, current_mfa, difference)
                if (difference == {}):
                    self._module.exit_json(changed=False)

            if self._module.check_mode:
                self._module.exit_json(changed=True)
            self._zapi.mfa.update(parameter)
            self._module.exit_json(
                changed=True, msg="Successfully updated MFA method."
            )
        except Exception as e:
            self._module.fail_json(
                msg="Failed to update MFA method: %s" % e
            )


def main():
    """Main ansible module function"""

    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            method_type=dict(
                type="str",
                choices=[
                    "totp",
                    "duo_universal_prompt"
                ],
            ),
            hash_function=dict(
                type="str",
                choices=[
                    "sha-1",
                    "sha-256",
                    "sha-512"
                ],
            ),
            code_length=dict(
                type="int",
                choices=[6, 8],
            ),
            api_hostname=dict(type="str"),
            clientid=dict(type="str"),
            client_secret=dict(type="str", no_log=True),
            state=dict(
                type="str",
                default="present",
                choices=["present", "absent"]
            )
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=[
            [
                "method_type",
                "totp",
                [
                    "hash_function",
                    "code_length"
                ]
            ],
            [
                "method_type",
                "duo_universal_prompt",
                [
                    "api_hostname",
                    "clientid",
                    "client_secret"
                ]
            ]
        ],
        mutually_exclusive=[
            ('hash_function', 'api_hostname')
        ],
        required_by={
            'hash_function': 'method_type',
            'code_length': 'method_type',
            'api_hostname': 'method_type',
            'clientid': 'method_type',
            'client_secret': 'method_type'
        },
        supports_check_mode=True,
    )

    name = module.params["name"]
    method_type = module.params["method_type"]
    hash_function = module.params["hash_function"]
    code_length = module.params["code_length"]
    api_hostname = module.params["api_hostname"]
    clientid = module.params["clientid"]
    client_secret = module.params["client_secret"]
    state = module.params["state"]

    mfa_class_obj = MFA(module)
    mfa = mfa_class_obj.get_mfa(name)

    if state == "absent":
        if mfa:
            mfa_class_obj.delete_mfa(mfa)
        else:
            module.exit_json(changed=False)
    else:
        if mfa:
            mfa_class_obj.update_mfa(mfa, name, method_type, hash_function, code_length, api_hostname, clientid, client_secret)
        else:
            mfa_class_obj.create_mfa(name, method_type, hash_function, code_length, api_hostname, clientid, client_secret)


if __name__ == "__main__":
    main()
