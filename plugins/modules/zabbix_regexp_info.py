#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2024, ONODERA Masaru <masaru-onodera@ieee.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: zabbix_regexp_info

short_description: Retrieve Zabbix regular expression


description:
    - This module allows you to retrieve Zabbix regular expression.

author:
    - ONODERA Masaru(@masa-orca)

requirements:
    - "python >= 3.9"

version_added: 3.3.0

options:
    name:
        description:
            - Name of this regular expression
        type: str
        required: true

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

- name: Retrieve regexp of 'File systems for discovery'
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_regexp_info:
    name: File systems for discovery
"""

RETURN = """
regexp:
    description: A Zabbix regular expression which is converted value to be used in community.zabbix.zabbix_regexp module.
    returned: success
    type: dict
    contains:
        name:
            description: Name of the regular expression
            type: str
            sample: File systems for discovery
        expressions:
            description: Expressions of the regular expression
            type: list
            sample: [{"case_sensitive": false, "expression_type": "result_is_true", ...}]
        test_string:
            description: Test string of the regular expression
            type: str
            sample: ext3
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase

import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class RegularExpression(ZabbixBase):
    expression_type_values = [
        "character_string_included",
        "any_character_string_included",
        "character_string_not_included",
        "result_is_true",
        "result_is_false",
    ]

    exp_delimiter_values = [",", ".", "/"]

    def __init__(self, module, zbx=None, zapi_wrapper=None):
        super(RegularExpression, self).__init__(module, zbx, zapi_wrapper)

    def get_regexp(self, regexp_name):
        try:
            regexps = self._zapi.regexp.get(
                {
                    "output": "extend",
                    "selectExpressions": [
                        "expression",
                        "expression_type",
                        "exp_delimiter",
                        "case_sensitive",
                    ],
                    "filter": {"name": regexp_name},
                }
            )
            if len(regexps) >= 2:
                self._module.fail_json("Too many regexps are matched.")
        except Exception as e:
            self._module.fail_json(
                msg="Failed to get regular expression setting: %s" % e
            )
        regexp_json = regexps[0]

        expressions = []

        for _expression in regexp_json['expressions']:
            case_sensitive = True
            if _expression['case_sensitive'] == '0':
                case_sensitive = False

            expression = {
                'expression': _expression['expression'],
                'expression_type': self.expression_type_values[int(_expression['expression_type'])],
                'case_sensitive': case_sensitive
            }

            if _expression['expression_type'] == '1':
                expression['exp_delimiter'] = _expression['exp_delimiter']

            expressions.append(expression)

        regexp = {
            'name': regexp_name,
            'test_string': regexp_json['test_string'],
            'expressions': expressions
        }

        self._module.exit_json(regexp=regexp)


def main():
    """Main ansible module function"""

    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(
        dict(name=dict(type="str", required=True))
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    name = module.params["name"]

    regexp_class_obj = RegularExpression(module)
    regexp_class_obj.get_regexp(name)


if __name__ == "__main__":
    main()
