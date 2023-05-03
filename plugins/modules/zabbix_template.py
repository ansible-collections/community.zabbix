#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2017, sookido
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
---
module: zabbix_template
short_description: Create/update/delete Zabbix template
description:
    - This module allows you to create, modify and delete Zabbix templates.
    - Multiple templates can be created or modified at once if passing JSON or XML to module.
author:
    - "sookido (@sookido)"
    - "Logan Vig (@logan2211)"
    - "Dusan Matejka (@D3DeFi)"
requirements:
    - "python >= 3.9"
options:
    template_name:
        description:
            - Name of Zabbix template.
            - Required when I(template_json) or I(template_xml) are not used.
            - Mutually exclusive with I(template_json) and I(template_xml).
        required: false
        type: str
    template_json:
        description:
            - JSON dump of templates to import.
            - Multiple templates can be imported this way.
            - Mutually exclusive with I(template_name) and I(template_xml).
        required: false
        type: json
    template_xml:
        description:
            - XML dump of templates to import.
            - Multiple templates can be imported this way.
            - You are advised to pass XML structure matching the structure used by your version of Zabbix server.
            - Custom XML structure can be imported as long as it is valid, but may not yield consistent idempotent
              results on subsequent runs.
            - Mutually exclusive with I(template_name) and I(template_json).
        required: false
        type: str
    template_groups:
        description:
            - List of template groups to add template to when template is created.
            - Replaces the current template groups the template belongs to if the template is already present.
            - Required when creating a new template with C(state=present) and I(template_name) is used.
              Not required when updating an existing template.
        required: false
        type: list
        elements: str
    link_templates:
        description:
            - List of template names to be linked to the template.
            - Templates that are not specified and are linked to the existing template will be only unlinked and not
              cleared from the template.
        required: false
        type: list
        elements: str
    clear_templates:
        description:
            - List of template names to be unlinked and cleared from the template.
            - This option is ignored if template is being created for the first time.
        required: false
        type: list
        elements: str
    macros:
        description:
            - List of user macros to create for the template.
            - Macros that are not specified and are present on the existing template will be replaced.
            - See examples on how to pass macros.
        required: false
        type: list
        elements: dict
        suboptions:
            macro:
                description:
                    - Name of the macro.
                    - Must be specified in {$NAME} format.
                type: str
                required: true
            value:
                description:
                    - Value of the macro.
                type: str
                required: true
    tags:
        description:
            - List of tags to assign to the template.
            - Providing I(tags=[]) with I(force=yes) will clean all of the tags from the template.
        required: false
        type: list
        elements: dict
        suboptions:
            tag:
                description:
                    - Name of the template tag.
                type: str
                required: true
            value:
                description:
                    - Value of the template tag.
                type: str
                default: ""
    state:
        description:
            - Required state of the template.
            - On C(state=present) template will be created/imported or updated depending if it is already present.
            - On C(state=absent) template will be deleted.
        required: false
        choices: [present, absent]
        default: "present"
        type: str

extends_documentation_fragment:
- community.zabbix.zabbix
"""


EXAMPLES = r"""
---
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

- name: Create a new Zabbix template linked to groups, macros and templates
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_template:
    template_name: ExampleHost
    template_groups:
      - Role
      - Role2
    link_templates:
      - Example template1
      - Example template2
    macros:
      - macro: "{$EXAMPLE_MACRO1}"
        value: 30000
      - macro: "{$EXAMPLE_MACRO2}"
        value: 3
      - macro: "{$EXAMPLE_MACRO3}"
        value: "Example"
    state: present

- name: Unlink and clear templates from the existing Zabbix template
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_template:
    template_name: ExampleHost
    clear_templates:
      - Example template3
      - Example template4
    state: present

- name: Import Zabbix templates from JSON
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_template:
    template_json: "{{ lookup('file', 'zabbix_apache2.json') }}"
    state: present

- name: Import Zabbix templates from XML
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_template:
    template_xml: "{{ lookup('file', 'zabbix_apache2.xml') }}"
    state: present

- name: Import Zabbix template from Ansible dict variable
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_template:
    template_json:
      zabbix_export:
        version: "3.2"
        templates:
          - name: Template for Testing
            description: "Testing template import"
            template: Test Template
            groups:
              - name: Templates
    state: present

- name: Configure macros on the existing Zabbix template
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_template:
    template_name: Template
    macros:
      - macro: "{$TEST_MACRO}"
        value: "Example"
    state: present

- name: Add tags to the existing Zabbix template
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_template:
    template_name: Template
    tags:
      - tag: class
        value: application
    state: present

- name: Delete Zabbix template
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_template:
    template_name: Template
    state: absent
"""

RETURN = r"""
---
"""


import json
import traceback
import re
import xml.etree.ElementTree as ET

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible.module_utils.six import PY2

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
from ansible.module_utils.compat.version import LooseVersion

import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class Template(ZabbixBase):
    # get group ids by group names
    def get_group_ids_by_group_names(self, group_names):
        group_ids = []
        for group_name in group_names:
            if LooseVersion(self._zbx_api_version) >= LooseVersion("6.2"):
                group = self._zapi.templategroup.get({"output": ["groupid"], "filter": {"name": group_name}})
            else:
                group = self._zapi.hostgroup.get({"output": ["groupid"], "filter": {"name": group_name}})
            if group:
                group_ids.append({"groupid": group[0]["groupid"]})
            else:
                self._module.fail_json(msg="Template group not found: %s" % group_name)
        return group_ids

    def get_template_ids(self, template_list):
        template_ids = []
        if template_list is None or len(template_list) == 0:
            return template_ids
        for template in template_list:
            template_list = self._zapi.template.get({"output": "extend", "filter": {"host": template}})
            if len(template_list) < 1:
                continue
            else:
                template_id = template_list[0]["templateid"]
                template_ids.append({"templateid": template_id})
        return template_ids

    def add_template(self, template_name, group_ids, link_template_ids, macros, tags):
        if self._module.check_mode:
            self._module.exit_json(changed=True)

        new_template = {"host": template_name, "groups": group_ids, "templates": link_template_ids, "macros": macros, "tags": tags}
        if macros is None:
            new_template.update({"macros": []})
        if tags is None:
            new_template.update({"tags": []})
        if link_template_ids is None:
            new_template.update({"templates": []})

        self._zapi.template.create(new_template)

    def check_template_changed(self, template_ids, template_groups, link_templates, clear_templates,
                               template_macros, template_tags, template_content, template_type):
        """Compares template parameters to already existing values if any are found.

        template_json - JSON structures are compared as deep sorted dictionaries,
        template_xml - XML structures are compared as strings, but filtered and formatted first,
        If none above is used, all the other arguments are compared to their existing counterparts
        retrieved from Zabbix API."""
        changed = False
        # Compare filtered and formatted XMLs strings for any changes. It is expected that provided
        # XML has same structure as Zabbix uses (e.g. it was optimally exported via Zabbix GUI or API)
        if template_content is not None and template_type == "xml":
            existing_template = self.dump_template(template_ids, template_type="xml")

            if self.filter_xml_template(template_content) != self.filter_xml_template(existing_template):
                changed = True

            return changed

        existing_template = self.dump_template(template_ids, template_type="json")
        # Compare JSON objects as deep sorted python dictionaries
        if template_content is not None and template_type == "json":
            parsed_template_json = self.load_json_template(template_content)
            if self.diff_template(parsed_template_json, existing_template):
                changed = True

            return changed

        # If neither template_json or template_xml were used, user provided all parameters via module options
        if template_groups is not None:
            if LooseVersion(self._zbx_api_version) >= LooseVersion("6.2"):
                existing_groups = [g["name"] for g in existing_template["zabbix_export"]["template_groups"]]
            else:
                existing_groups = [g["name"] for g in existing_template["zabbix_export"]["groups"]]

            if set(template_groups) != set(existing_groups):
                changed = True

        if "templates" not in existing_template["zabbix_export"]["templates"][0]:
            existing_template["zabbix_export"]["templates"][0]["templates"] = []

        # Check if any new templates would be linked or any existing would be unlinked
        exist_child_templates = [t["name"] for t in existing_template["zabbix_export"]["templates"][0]["templates"]]
        if link_templates is not None:
            if set(link_templates) != set(exist_child_templates):
                changed = True
        else:
            if set([]) != set(exist_child_templates):
                changed = True

        # Mark that there will be changes when at least one existing template will be unlinked
        if clear_templates is not None:
            for t in clear_templates:
                if t in exist_child_templates:
                    changed = True
                    break

        if "macros" not in existing_template["zabbix_export"]["templates"][0]:
            existing_template["zabbix_export"]["templates"][0]["macros"] = []

        if template_macros is not None:
            existing_macros = existing_template["zabbix_export"]["templates"][0]["macros"]
            if template_macros != existing_macros:
                changed = True

        if "tags" not in existing_template["zabbix_export"]["templates"][0]:
            existing_template["zabbix_export"]["templates"][0]["tags"] = []
        if template_tags is not None:
            existing_tags = existing_template["zabbix_export"]["templates"][0]["tags"]
            if template_tags != existing_tags:
                changed = True

        return changed

    def update_template(self, template_ids, group_ids, link_template_ids, clear_template_ids, template_macros, template_tags):
        template_changes = {}
        if group_ids is not None:
            template_changes.update({"groups": group_ids})

        if link_template_ids is not None:
            template_changes.update({"templates": link_template_ids})
        else:
            template_changes.update({"templates": []})

        if clear_template_ids is not None:
            template_changes.update({"templates_clear": clear_template_ids})

        if template_macros is not None:
            template_changes.update({"macros": template_macros})
        else:
            template_changes.update({"macros": []})

        if template_tags is not None:
            template_changes.update({"tags": template_tags})
        else:
            template_changes.update({"tags": []})

        if template_changes:
            # If we got here we know that only one template was provided via template_name
            template_changes.update(template_ids[0])
            self._zapi.template.update(template_changes)

    def delete_template(self, templateids):
        if self._module.check_mode:
            self._module.exit_json(changed=True)

        templateids_list = [t.get("templateid") for t in templateids]
        self._zapi.template.delete(templateids_list)

    def ordered_json(self, obj):
        # Deep sort json dicts for comparison
        if isinstance(obj, dict):
            return sorted((k, self.ordered_json(v)) for k, v in obj.items())
        if isinstance(obj, list):
            return sorted(self.ordered_json(x) for x in obj)
        else:
            return obj

    def dump_template(self, template_ids, template_type="json"):
        template_ids_list = [t.get("templateid") for t in template_ids]
        try:
            dump = self._zapi.configuration.export({"format": template_type, "options": {"templates": template_ids_list}})
            if template_type == "xml":
                xmlroot = ET.fromstring(dump.encode("utf-8"))
                if PY2:
                    return str(ET.tostring(xmlroot, encoding="utf-8"))
                else:
                    return str(ET.tostring(xmlroot, encoding="utf-8").decode("utf-8"))
            else:
                return self.load_json_template(dump)

        except Exception as e:
            self._module.fail_json(msg="Unable to export template: %s" % e)

    def diff_template(self, template_json_a, template_json_b):
        # Compare 2 zabbix templates and return True if they differ.
        template_json_a = self.filter_template(template_json_a)
        template_json_b = self.filter_template(template_json_b)
        if self.ordered_json(template_json_a) == self.ordered_json(template_json_b):
            return False
        return True

    def filter_template(self, template_json):
        # Filter the template json to contain only the keys we will update
        keep_keys = set(["graphs", "templates", "triggers", "value_maps"])
        unwanted_keys = set(template_json["zabbix_export"]) - keep_keys
        for unwanted_key in unwanted_keys:
            del template_json["zabbix_export"][unwanted_key]

        # Versions older than 2.4 do not support description field within template
        desc_not_supported = False

        # Filter empty attributes from template object to allow accurate comparison
        for template in template_json["zabbix_export"]["templates"]:
            for key in list(template.keys()):
                if not template[key] or (key == "description" and desc_not_supported):
                    template.pop(key)

        return template_json

    def filter_xml_template(self, template_xml):
        """Filters out keys from XML template that may wary between exports (e.g date or version) and
        keys that are not imported via this module.

        It is advised that provided XML template exactly matches XML structure used by Zabbix"""
        # Strip last new line and convert string to ElementTree
        parsed_xml_root = self.load_xml_template(template_xml.strip())
        keep_keys = ["graphs", "templates", "triggers", "value_maps"]

        # Remove unwanted XML nodes
        for node in list(parsed_xml_root):
            if node.tag not in keep_keys:
                parsed_xml_root.remove(node)

        # Filter empty attributes from template objects to allow accurate comparison
        for template in list(parsed_xml_root.find("templates")):
            for element in list(template):
                if element.text is None and len(list(element)) == 0:
                    template.remove(element)

        # Filter new lines and indentation
        xml_root_text = list(line.strip() for line in ET.tostring(parsed_xml_root, encoding="utf8", method="xml").decode().split("\n"))
        return "".join(xml_root_text)

    def load_json_template(self, template_json):
        try:
            jsondoc = json.loads(template_json)
            return jsondoc
        except ValueError as e:
            self._module.fail_json(msg="Invalid JSON provided", details=to_native(e), exception=traceback.format_exc())

    def load_xml_template(self, template_xml):
        try:
            return ET.fromstring(template_xml)
        except ET.ParseError as e:
            self._module.fail_json(msg="Invalid XML provided", details=to_native(e), exception=traceback.format_exc())

    def import_template(self, template_content, template_type="json"):
        if self._module.check_mode:
            self._module.exit_json(changed=True)

        # rules schema latest version
        update_rules = {
            "discoveryRules": {
                "createMissing": True,
                "updateExisting": True,
                "deleteMissing": True
            },
            "graphs": {
                "createMissing": True,
                "updateExisting": True,
                "deleteMissing": True
            },
            "host_groups": {
                "createMissing": True
            },
            "httptests": {
                "createMissing": True,
                "updateExisting": True,
                "deleteMissing": True
            },
            "items": {
                "createMissing": True,
                "updateExisting": True,
                "deleteMissing": True
            },
            "templates": {
                "createMissing": True,
                "updateExisting": True
            },
            "template_groups": {
                "createMissing": True
            },
            "templateLinkage": {
                "createMissing": True
            },
            "templateScreens": {
                "createMissing": True,
                "updateExisting": True,
                "deleteMissing": True
            },
            "triggers": {
                "createMissing": True,
                "updateExisting": True,
                "deleteMissing": True
            },
            "valueMaps": {
                "createMissing": True,
                "updateExisting": True
            }
        }

        try:
            update_rules["templateLinkage"]["deleteMissing"] = True
            update_rules["templateDashboards"] = update_rules.pop("templateScreens")

            # before Zabbix 6.2 host_groups and template_group are joined into groups parameter
            if LooseVersion(self._zbx_api_version) < LooseVersion("6.2"):
                update_rules["groups"] = {"createMissing": True}
                update_rules.pop("host_groups", None)
                update_rules.pop("template_groups", None)

            # The loaded unicode slash of multibyte as a string is escaped when parsing JSON by json.loads in Python2.
            # So, it is imported in the unicode string into Zabbix.
            # The following processing is removing the unnecessary slash in escaped for decoding correctly to the multibyte string.
            # https://github.com/ansible-collections/community.zabbix/issues/314
            if PY2:
                template_content = re.sub(r"\\\\u([0-9a-z]{,4})", r"\\u\1", template_content)

            import_data = {"format": template_type, "source": template_content, "rules": update_rules}
            self._zapi.configuration.import_(import_data)
        except Exception as e:
            self._module.fail_json(msg="Unable to import template", details=to_native(e),
                                   exception=traceback.format_exc())


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        template_name=dict(type="str", required=False),
        template_json=dict(type="json", required=False),
        template_xml=dict(type="str", required=False),
        template_groups=dict(type="list", required=False, elements="str"),
        link_templates=dict(type="list", required=False, elements="str"),
        clear_templates=dict(type="list", required=False, elements="str"),
        macros=dict(
            type="list",
            elements="dict",
            options=dict(
                macro=dict(type="str", required=True),
                value=dict(type="str", required=True)
            )
        ),
        tags=dict(
            type="list",
            elements="dict",
            options=dict(
                tag=dict(type="str", required=True),
                value=dict(type="str", default="")
            )
        ),
        state=dict(type="str", default="present", choices=["present", "absent"]),
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        required_one_of=[
            ["template_name", "template_json", "template_xml"]
        ],
        mutually_exclusive=[
            ["template_name", "template_json", "template_xml"]
        ],
        required_if=[
            ["state", "absent", ["template_name"]]
        ],
        supports_check_mode=True
    )

    template_name = module.params["template_name"]
    template_json = module.params["template_json"]
    template_xml = module.params["template_xml"]
    template_groups = module.params["template_groups"]
    link_templates = module.params["link_templates"]
    clear_templates = module.params["clear_templates"]
    template_macros = module.params["macros"]
    template_tags = module.params["tags"]
    state = module.params["state"]

    template = Template(module)

    # Identify template names for IDs retrieval
    # Template names are expected to reside in ["zabbix_export"]["templates"][*]["template"] for both data types
    template_content, template_type = None, None
    if template_json is not None:
        template_type = "json"
        template_content = template_json
        json_parsed = template.load_json_template(template_content)
        template_names = list(t["template"] for t in json_parsed["zabbix_export"]["templates"])

    elif template_xml is not None:
        template_type = "xml"
        template_content = template_xml
        xml_parsed = template.load_xml_template(template_content)
        template_names = list(t.find("template").text for t in list(xml_parsed.find("templates")))

    else:
        template_names = [template_name]

    template_ids = template.get_template_ids(template_names)

    if state == "absent":
        if not template_ids:
            module.exit_json(changed=False, msg="Template not found. No changed: %s" % template_name)

        template.delete_template(template_ids)
        module.exit_json(changed=True, result="Successfully deleted template %s" % template_name)

    elif state == "present":
        # Load all subelements for template that were provided by user
        group_ids = None
        if template_groups is not None:
            group_ids = template.get_group_ids_by_group_names(template_groups)

        link_template_ids = None
        if link_templates is not None:
            link_template_ids = template.get_template_ids(link_templates)

        clear_template_ids = None
        if clear_templates is not None:
            clear_template_ids = template.get_template_ids(clear_templates)

        if template_macros is not None:
            # Zabbix configuration.export does not differentiate python types (numbers are returned as strings)
            for macroitem in template_macros:
                for key in macroitem:
                    macroitem[key] = str(macroitem[key])

        if template_tags is not None:
            for tagitem in template_tags:
                for key in tagitem:
                    tagitem[key] = str(tagitem[key])

        if not template_ids:
            # Assume new templates are being added when no ID"s were found
            if template_content is not None:
                template.import_template(template_content, template_type)
                module.exit_json(changed=True, result="Template import successful")

            else:
                if group_ids is None:
                    module.fail_json(msg="template_groups are required when creating a new Zabbix template")

                template.add_template(template_name, group_ids, link_template_ids, template_macros, template_tags)
                module.exit_json(changed=True, result="Successfully added template: %s" % template_name)

        else:
            changed = template.check_template_changed(template_ids, template_groups, link_templates, clear_templates,
                                                      template_macros, template_tags, template_content, template_type)

            if module.check_mode:
                module.exit_json(changed=changed)

            if changed:
                if template_type is not None:
                    template.import_template(template_content, template_type)
                else:
                    template.update_template(template_ids, group_ids, link_template_ids, clear_template_ids,
                                             template_macros, template_tags)

            module.exit_json(changed=changed, result="Template successfully updated")


if __name__ == "__main__":
    main()
