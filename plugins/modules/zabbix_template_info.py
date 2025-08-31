#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, sky-joker
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
module: zabbix_template_info
short_description: Gather information about Zabbix template
author:
    - sky-joker (@sky-joker)
description:
    - This module allows you to search for Zabbix template.
requirements:
    - "python >= 3.9"
options:
    template_name:
        description:
            - Name of the template in Zabbix.
        required: false
        type: str
    format:
        description:
            - Format to use when dumping template.
        choices: ["json", "xml", "yaml", "none"]
        default: json
        type: str
    omit_date:
        description:
            - Removes the date field for the dumped template
            - This parameter will be ignored since Zabbix 6.4.
        required: false
        type: bool
        default: false
    all_templategroups:
        description:
            - return info about all templategroups.
        required: false
        type: bool
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

- name: Get Zabbix template as JSON
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_template_info:
    template_name: Template
    format: json
    omit_date: yes
  register: template_json

- name: Get Zabbix template as XML
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_template_info:
    template_name: Template
    format: xml
    omit_date: no
  register: template_json

- name: Get Zabbix template as YAML
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_template_info:
    template_name: Template
    format: yaml
    omit_date: no
  register: template_yaml

- name: Determine if Zabbix template exists
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_template_info:
    template_name: Template
    format: none
  register: template

- name: Get info about all templategroups
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_template_info:
    all_templategroups: true
    register: all_templategroups
"""

RETURN = """
---
template_id:
  description: The ID of the template
  returned: always
  type: str

template_json:
  description: The JSON of the template
  returned: when format is json and omit_date is true
  type: str
  sample: {
        "changed": false,
        "failed": false,
        "template_id": "10529",
        "template_json": {
            "zabbix_export": {
                "groups": [
                    {
                        "name": "Templates",
                        "uuid": "7df96b18c230490a9a0a9e2307226338"
                    }
                ],
                "templates": [
                    {
                        "groups": [
                            {
                                "name": "Templates"
                            }
                        ],
                        "name": "ExampleTemplateForTempleteInfoModule",
                        "template": "ExampleTemplateForTempleteInfoModule",
                        "uuid": "615e9b0662bb4399a2503a9aaa743517"
                    }
                ],
                "version": "6.0"
            }
        }
    }

template_xml:
  description: The XML of the template
  returned: when format is xml and omit_date is false
  type: str
  sample: >-
    <zabbix_export>
        <version>6.0</version>
        <groups>
            <group>
                <uuid>7df96b18c230490a9a0a9e2307226338</uuid>
                <name>Templates</name>
            </group>
        </groups>
        <templates>
            <template>
                <uuid>9a83162273f74032a1005fdb13943038</uuid>
                <template>ExampleTemplateForTempleteInfoModule</template>
                <name>ExampleTemplateForTempleteInfoModule</name>
                <groups>
                    <group>
                        <name>Templates</name>
                    </group>
                </groups>
            </template>
        </templates>
    </zabbix_export>

template_yaml:
  description: The YAML of the template
  returned: when format is yaml and omit_date is false
  type: str
  sample: >-
    zabbix_export:
      version: "6.0"
      groups:
        -
          uuid: 7df96b18c230490a9a0a9e2307226338
          name: Templates
          templates:
            -
              uuid: 67b075276bf047d3aeb8f7d5c2121c6a
              template: ExampleTemplateForTempleteInfoModule
              name: ExampleTemplateForTempleteInfoModule
              groups:
                -
                  name: Templatesn
"""


import traceback
import json
import xml.etree.ElementTree as ET

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.compat.version import LooseVersion
from ansible.module_utils._text import to_native

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class TemplateInfo(ZabbixBase):
    def get_template_id(self, template_name):
        template_id = []
        try:
            template_list = self._zapi.template.get({"output": ["templateid"],
                                                     "filter": {"host": template_name}})
        except Exception as e:
            self._module.fail_json(msg="Failed to get template: %s" % e)

        if template_list:
            template_id.append(template_list[0]["templateid"])

        return template_id

    def load_json_template(self, template_json, omit_date=False):
        try:
            jsondoc = json.loads(template_json)
            # remove date field if requested
            if omit_date and "date" in jsondoc["zabbix_export"]:
                del jsondoc["zabbix_export"]["date"]
            return jsondoc
        except ValueError as e:
            self._module.fail_json(msg="Invalid JSON provided", details=to_native(e), exception=traceback.format_exc())

    def load_yaml_template(self, template_yaml, omit_date=False):
        if omit_date and LooseVersion(self._zbx_api_version) < LooseVersion("7.0"):
            yaml_lines = template_yaml.splitlines(True)
            for index, line in enumerate(yaml_lines):
                if "date:" in line:
                    del yaml_lines[index]
                    return "".join(yaml_lines)
        else:
            return template_yaml

    def dump_template(self, template_id, template_type="json", omit_date=False):
        try:
            dump = self._zapi.configuration.export({"format": template_type, "options": {"templates": template_id}})
            if template_type == "xml":
                xmlroot = ET.fromstring(dump.encode("utf-8"))
                # remove date field if requested
                if omit_date:
                    date = xmlroot.find(".date")
                    if date is not None:
                        xmlroot.remove(date)
                return str(ET.tostring(xmlroot, encoding="utf-8").decode("utf-8"))
            elif template_type == "yaml":
                return self.load_yaml_template(dump, omit_date)
            else:
                return self.load_json_template(dump, omit_date)
        except Exception as e:
            self._module.fail_json(msg="Unable to export template: %s" % e)

    def get_all_groups(self):
        group_list = self._zapi.templategroup.get({"output": "extend"})
        if len(group_list) < 1:
            self._module.fail_json(msg="No Hostgroup can be found")
        return group_list


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        template_name=dict(type="str", required=False),
        omit_date=dict(type="bool", required=False, default=False),
        format=dict(type="str", choices=["json", "xml", "yaml", "none"], default="json"),
        all_templategroups=dict(type="bool", required=False),
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    template_name = module.params["template_name"]
    all_templategroups = module.params["all_templategroups"]
    omit_date = module.params["omit_date"]
    format = module.params["format"]

    template_info = TemplateInfo(module)

    if template_name:
        template_id = template_info.get_template_id(template_name)

        if not template_id:
            module.fail_json(msg="Template not found: %s" % template_name)

        if format == "json":
            module.exit_json(
                changed=False,
                template_id=template_id[0],
                template_json=template_info.dump_template(template_id, template_type="json", omit_date=omit_date)
            )
        elif format == "xml":
            module.exit_json(
                changed=False,
                template_id=template_id[0],
                template_xml=template_info.dump_template(template_id, template_type="xml", omit_date=omit_date)
            )
        elif format == "yaml":
            module.exit_json(
                changed=False,
                template_id=template_id[0],
                template_yaml=template_info.dump_template(template_id, template_type="yaml", omit_date=omit_date)
            )
        elif format == "none":
            module.exit_json(changed=False, template_id=template_id[0])

    if all_templategroups:
        template_groups = template_info.get_all_groups()
        module.exit_json(template_groups=template_groups)


if __name__ == "__main__":
    main()
