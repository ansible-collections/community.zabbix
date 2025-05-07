#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, ONODERA Masaru <masaru-onodera@ieee.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
---
module: zabbix_configuration
short_description: Import Zabbix configuration
description:
    - This module allows you to import Zabbix configuration data.
    - If the Zabix configuration.importcompare API returns non-empty list, this module returns changed is true.

author:
    - ONODERA Masaru(@masa-orca)
requirements:
    - "python >= 3.11"
version_added: 3.4.0
options:
    content_json:
        description:
            - The content of the JSON file to be imported.
            - Mutually exclusive with I(content_xml) and I(content_yaml).
        required: false
        type: json
    content_xml:
        description:
            - The content of the XML file to be imported.
            - Mutually exclusive with I(content_json) and I(content_yaml).
        required: false
        type: str
    content_yaml:
        description:
            - The content of the YAML file to be imported.
            - Mutually exclusive with I(content_json) and I(content_xml).
        required: false
        type: str
    rules:
        description:
            - The rules for importing the configuration.
            - Please refer to rules of the Zabbix configuration.import API documentation for more details.
            - https://www.zabbix.com/documentation/current/en/manual/api/reference/configuration/import
        required: false
        type: dict

extends_documentation_fragment:
    - community.zabbix.zabbix
"""


EXAMPLES = r"""
---
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

- name: Import Zabbix template from JSON
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_configuration:
    content_json: "{{ lookup('file', 'zbx_export_template.json') }}"
    rules:
      templates:
        createMissing: true
        updateExisting: true
      items:
        createMissing: true
        updateExisting: true
        deleteMissing: true
      triggers:
        createMissing: true
        updateExisting: true
        deleteMissing: true
      valueMaps:
        createMissing: true
        updateExisting: false
"""

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class Configuration(ZabbixBase):
    def import_compare(self, content, fmt, rules):
        """Import Zabbix configuration data"""
        changed = False
        try:
            params = {"format": fmt, "source": content}
            if rules is not None:
                params["rules"] = rules
            compare_result = self._zapi.configuration.importcompare(params)
            if len(compare_result) != 0:
                changed = True
            return changed
        except Exception as e:
            self._module.fail_json(
                msg="Unable to compare configuration",
                details=to_native(e),
                exception=traceback.format_exc(),
            )

    def import_config(self, content, fmt, rules):
        """Import Zabbix configuration data"""
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            params = {
                "format": fmt,
                "source": content,
            }
            if rules is not None:
                params["rules"] = rules
            self._zapi.configuration.import_(params)
        except Exception as e:
            self._module.fail_json(
                msg="Unable to import configuration",
                details=to_native(e),
                exception=traceback.format_exc(),
            )


def main():
    """Main ansible module function"""
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(
        dict(
            content_json=dict(type="json", required=False),
            content_xml=dict(type="str", required=False),
            content_yaml=dict(type="str", required=False),
            rules=dict(type="dict", required=False)
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_one_of=[["content_json", "content_xml", "content_yaml"]],
        mutually_exclusive=[["content_json", "content_xml", "content_yaml"]],
        supports_check_mode=True,
    )

    content_json = module.params["content_json"]
    content_xml = module.params["content_xml"]
    content_yaml = module.params["content_yaml"]
    rules = module.params["rules"]

    configuration = Configuration(module)

    content, format = None, None

    if content_json is not None:
        format = "json"
        content = content_json
    elif content_xml is not None:
        format = "xml"
        content = content_xml
    elif content_yaml is not None:
        format = "yaml"
        content = content_yaml

    changed = configuration.import_compare(content, format, rules)

    if not changed:
        module.exit_json(changed=changed, result="Configuration is up-to date")
    else:
        configuration.import_config(content, format, rules)
        module.exit_json(changed=changed, result="Configuration imported successfully")


if __name__ == "__main__":
    main()
