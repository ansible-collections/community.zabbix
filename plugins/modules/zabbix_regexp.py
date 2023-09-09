#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, ONODERA Masaru <masaru-onodera@ieee.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: zabbix_regexp

short_description: Create/update/delete Zabbix regular expression


description:
    - This module allows you to create, update and delete Zabbix regular expression.

author:
    - ONODERA Masaru(@masa-orca)

requirements:
    - "python >= 3.9"

version_added: 2.1.0

options:
    name:
        description:
            - Name of this regular expression
        type: str
        required: true
    test_string:
        description:
            - A test string for this regular expression
        type: str
    expressions:
        description:
            - List of expressions.
            - The regular expression returns true when all expressions return true.
            - Required when C(state=present).
        type: list
        elements: dict
        suboptions:
            expression:
                description:
                    - A expression string
                type: str
                required: true
            expression_type:
                description:
                    - A expression string
                type: str
                required: true
                choices:
                    - "character_string_included"
                    - "any_character_string_included"
                    - "character_string_not_included"
                    - "result_is_true"
                    - "result_is_false"
            exp_delimiter:
                description:
                    - Delimiter for expression.
                    - Used if expression_type is C(any_character_string_included).
                    - Default values is C(,)
                type: str
                choices: [",", ".", "/"]
            case_sensitive:
                description:
                    - If true, the expression will be case sensitive.
                type: bool
                default: false
    state:
        description:
            - State of the regular expression.
        type: str
        choices: ['present', 'absent']
        default: 'present'


notes:
    - Only Zabbix >= 6.0 is supported.

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

- name: Update regexp of 'File systems for discovery'
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_regexp:
    name: File systems for discovery
    test_string: ext2
    expressions:
      - expression: "^(btrfs|ext2|ext3|ext4|reiser|xfs|ffs|ufs|jfs|jfs2|vxfs|hfs|apfs|refs|ntfs|fat32|zfs)$"
        expression_type: result_is_true
"""

RETURN = """
msg:
    description: The result of the operation
    returned: success
    type: str
    sample: 'Successfully updated regular expression setting'
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
from ansible.module_utils.compat.version import LooseVersion

import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class RegularExpression(ZabbixBase):
    def __init__(self, module, zbx=None, zapi_wrapper=None):
        super(RegularExpression, self).__init__(module, zbx, zapi_wrapper)
        if LooseVersion(self._zbx_api_version) < LooseVersion("6.0"):
            module.fail_json(
                msg="This module doesn't support Zabbix versions lower than 6.0"
            )

    def get_regexps(self, regexp_name):
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
            return regexps
        except Exception as e:
            self._module.fail_json(
                msg="Failed to get regular expression setting: %s" % e
            )

    def delete_regexp(self, regexp):
        try:
            parameter = [regexp["regexpid"]]
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            self._zapi.regexp.delete(parameter)
            self._module.exit_json(
                changed=True, msg="Successfully deleted regular expression setting."
            )
        except Exception as e:
            self._module.fail_json(
                msg="Failed to delete regular expression setting: %s" % e
            )

    def _convert_expressions_to_json(self, expressions):
        expression_type_values = [
            "character_string_included",
            "any_character_string_included",
            "character_string_not_included",
            "result_is_true",
            "result_is_false",
        ]

        expression_jsons = []
        for expression in expressions:
            expression_json = {}

            expression_json["expression"] = expression["expression"]
            expression_type = zabbix_utils.helper_to_numeric_value(
                expression_type_values, expression["expression_type"]
            )
            expression_json["expression_type"] = str(expression_type)
            if expression["expression_type"] == "any_character_string_included":
                if expression["exp_delimiter"]:
                    expression_json["exp_delimiter"] = expression["exp_delimiter"]
                else:
                    expression_json["exp_delimiter"] = ","
            elif expression["exp_delimiter"]:
                self._module.warn(
                    "A value of exp_delimiter will be ignored because expression_type is not 'any_character_string_included'."
                )
            case_sensitive = "0"
            if expression["case_sensitive"]:
                case_sensitive = "1"
            expression_json["case_sensitive"] = case_sensitive

            expression_jsons.append(expression_json)
        return expression_jsons

    def create_regexp(self, name, test_string, expressions):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            self._zapi.regexp.create(
                {
                    "name": name,
                    "test_string": test_string,
                    "expressions": self._convert_expressions_to_json(expressions),
                }
            )
            self._module.exit_json(
                changed=True, msg="Successfully created regular expression setting."
            )
        except Exception as e:
            self._module.fail_json(
                msg="Failed to create regular expression setting: %s" % e
            )

    def update_regexp(self, current_regexp, name, test_string, expressions):
        try:
            current_expressions = []
            for expression in current_regexp["expressions"]:
                if expression["expression_type"] != "1":
                    expression = zabbix_utils.helper_normalize_data(
                        expression, del_keys=["exp_delimiter"]
                    )[0]
                current_expressions.append(expression)
            future_expressions = self._convert_expressions_to_json(expressions)
            diff_expressions = []
            zabbix_utils.helper_compare_lists(
                current_expressions, future_expressions, diff_expressions
            )
            if (
                current_regexp["name"] == name
                and current_regexp["test_string"] == test_string
                and len(diff_expressions) == 0
            ):
                self._module.exit_json(changed=False)
            else:
                if self._module.check_mode:
                    self._module.exit_json(changed=True)
                self._zapi.regexp.update(
                    {
                        "regexpid": current_regexp["regexpid"],
                        "name": name,
                        "test_string": test_string,
                        "expressions": future_expressions,
                    }
                )
                self._module.exit_json(
                    changed=True, msg="Successfully updated regular expression setting."
                )
        except Exception as e:
            self._module.fail_json(
                msg="Failed to update regular expression setting: %s" % e
            )


def main():
    """Main ansible module function"""

    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            test_string=dict(
                type="str",
            ),
            expressions=dict(
                type="list",
                elements="dict",
                options=dict(
                    expression=dict(type="str", required=True),
                    expression_type=dict(
                        type="str",
                        required=True,
                        choices=[
                            "character_string_included",
                            "any_character_string_included",
                            "character_string_not_included",
                            "result_is_true",
                            "result_is_false",
                        ],
                    ),
                    exp_delimiter=dict(type="str", choices=[",", ".", "/"]),
                    case_sensitive=dict(type="bool", default=False),
                ),
            ),
            state=dict(
                type="str",
                required=False,
                default="present",
                choices=["present", "absent"],
            ),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=[["state", "present", ["expressions"]]],
        supports_check_mode=True,
    )

    name = module.params["name"]
    test_string = module.params["test_string"]
    expressions = module.params["expressions"]
    state = module.params["state"]

    regexp_class_obj = RegularExpression(module)
    regexps = regexp_class_obj.get_regexps(name)

    if state == "absent":
        if len(regexps) == 1:
            regexp_class_obj.delete_regexp(regexps[0])
        else:
            module.exit_json(changed=False)
    else:
        if len(regexps) == 1:
            regexp_class_obj.update_regexp(regexps[0], name, test_string, expressions)
        else:
            regexp_class_obj.create_regexp(name, test_string, expressions)


if __name__ == "__main__":
    main()
