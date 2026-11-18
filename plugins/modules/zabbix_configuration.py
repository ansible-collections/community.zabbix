#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, ONODERA Masaru <masa-orca>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
---
module: zabbix_configuration
short_description: Import or export Zabbix configuration
description:
    - Import Zabbix configuration data or export objects selected by ID.
    - Imports report changes using the configuration.importcompare API where comparison is supported.
    - Exports do not modify configuration and always report C(changed=false).

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
            - Imports with C(hosts), C(images), C(maps) or C(mediaTypes) rules always report C(changed=true), as comparison is unsupported for these objects.
            - https://www.zabbix.com/documentation/current/en/manual/api/reference/configuration/import
            - Zabbix 8.0 and later support C(dashboards) and C(global_regexes), each with C(createMissing) and C(updateExisting) boolean settings.
            - Updating dashboards replaces their pages and widgets. Updating global regular expressions replaces their subexpressions.
        required: false
        type: dict
    return_missing_objects:
        description:
            - Request information about missing referenced objects from both comparison and import, returned as RV(missing_objects).
            - Maps to the API parameter C(returnMissingObjects). Requires Zabbix 8.0 or later.
            - When omitted, the API parameter is not sent. Zabbix defaults to C(false).
        type: bool
    export_options:
        description:
            - Export the selected objects instead of importing content.
            - Dictionary of API object names and lists of IDs, passed as C(configuration.export) C(options).
            - Supports C(host_groups), C(hosts), C(images), C(maps), C(mediaTypes), C(template_groups) and C(templates), subject to server version support.
            - Zabbix 8.0 and later also support C(dashboards) and C(global_regexes).
            - Mutually exclusive with import content, O(rules) and O(return_missing_objects).
        type: dict
    export_format:
        description:
            - Serialization format for O(export_options). Ignored when importing.
        type: str
        choices: [json, xml, yaml]
        default: json

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

- name: Import dashboards and global regular expressions (Zabbix >= 8.0)
  community.zabbix.zabbix_configuration:
    content_yaml: "{{ lookup('file', 'configuration.yaml') }}"
    return_missing_objects: true
    rules:
      dashboards:
        createMissing: true
        updateExisting: true
      global_regexes:
        createMissing: true
        updateExisting: true
  register: configuration_import

- name: Export global regular expressions (Zabbix >= 8.0)
  community.zabbix.zabbix_configuration:
    export_options:
      global_regexes:
        - "12"
        - "34"
    export_format: yaml
  register: configuration_export

# Example tasks for roles/export_dashboard/tasks/main.yml.
# Configure the Zabbix httpapi connection and credentials in the play or inventory.
# Supply these role variables, for example:
# zabbix_dashboard_id: "12"
# zabbix_dashboard_export_path: /tmp/dashboard.yaml
- name: Export the selected dashboard (Zabbix >= 8.0)
  community.zabbix.zabbix_configuration:
    export_options:
      dashboards:
        - "{{ zabbix_dashboard_id }}"
    export_format: yaml
  register: zabbix_dashboard_export

- name: Save the exported dashboard on the Ansible controller
  ansible.builtin.copy:
    content: "{{ zabbix_dashboard_export.exported_config }}"
    dest: "{{ zabbix_dashboard_export_path }}"
    mode: "0600"
  delegate_to: localhost
  vars:
    ansible_connection: local
"""

RETURN = r"""
result:
    description: Import status message.
    returned: when importing
    type: str
    sample: Configuration imported successfully
missing_objects:
    description:
        - Missing referenced objects reported by the Zabbix API, grouped by object type.
        - In check mode or when no changes are needed, contains comparison metadata; otherwise contains import metadata.
        - An empty API array is normalized to an empty dictionary.
    returned: when importing with return_missing_objects=true
    type: dict
    sample: {"hosts": [{"name": "Missing host"}]}
exported_config:
    description: Serialized configuration in the requested export format.
    returned: when exporting
    type: str
    sample: '{"zabbix_export": {"version": "8.0", "global_regexes": []}}'
"""

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible.module_utils.compat.version import LooseVersion

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class Configuration(ZabbixBase):
    def request(self, method, params):
        """Call a configuration API method with consistent error reporting."""
        try:
            return getattr(self._zapi.configuration, method)(params)
        except Exception as e:
            self._module.fail_json(
                msg="Unable to call configuration.{0}".format(method.rstrip("_")),
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
            rules=dict(type="dict", required=False),
            return_missing_objects=dict(type="bool"),
            export_options=dict(type="dict"),
            export_format=dict(type="str", choices=["json", "xml", "yaml"], default="json"),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_one_of=[["content_json", "content_xml", "content_yaml", "export_options"]],
        mutually_exclusive=[
            ["content_json", "content_xml", "content_yaml", "export_options"],
            ["export_options", "rules"],
            ["export_options", "return_missing_objects"],
        ],
        supports_check_mode=True,
    )

    rules = module.params["rules"] or {}
    return_missing_objects = module.params["return_missing_objects"]
    export_options = module.params["export_options"]

    configuration = Configuration(module)

    if LooseVersion(configuration._zbx_api_version) < LooseVersion("8.0"):
        if return_missing_objects is not None or set(rules).intersection(["dashboards", "global_regexes"]):
            module.fail_json(msg="return_missing_objects and dashboard/global regular expression import rules require Zabbix 8.0 or later")
        if export_options is not None and set(export_options).intersection(["dashboards", "global_regexes"]):
            module.fail_json(msg="Exporting dashboards or global regular expressions requires Zabbix 8.0 or later")

    if export_options is not None:
        exported_config = configuration.request("export", {"format": module.params["export_format"], "options": export_options})
        module.exit_json(changed=False, exported_config=exported_config)

    for fmt in ("json", "xml", "yaml"):
        content = module.params["content_" + fmt]
        if content is not None:
            params = {"format": fmt, "source": content, "rules": rules}
            break
    if return_missing_objects is not None:
        params["returnMissingObjects"] = return_missing_objects

    uncomparable_rules = ["hosts", "images", "maps", "mediaTypes"]
    comparable = set(rules).isdisjoint(uncomparable_rules)
    changed = True
    missing_objects = {}
    if comparable or return_missing_objects:
        comparison = configuration.request("importcompare", params)
        missing_objects = comparison.pop("missingObjects", {}) if isinstance(comparison, dict) else {}
        if comparable:
            changed = bool(comparison)

    if changed and not module.check_mode:
        imported = configuration.request("import_", params)
        missing_objects = imported.get("missingObjects", {}) if isinstance(imported, dict) else {}
    result = {"changed": changed}
    if return_missing_objects:
        result["missing_objects"] = missing_objects or {}
    if not changed:
        result["result"] = "Configuration is up-to date"
    elif module.check_mode:
        result["result"] = "Configuration would be imported"
    else:
        result["result"] = "Configuration imported successfully"
    module.exit_json(**result)


if __name__ == "__main__":
    main()
