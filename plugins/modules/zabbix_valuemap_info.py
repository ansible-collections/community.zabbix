#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, G.J. Doornink
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
module: zabbix_valuemap_info
short_description: Gather information about Zabbix valuemap
author:
    - G.J. Doornink (@gjdoornink)
description:
    - This module allows you to search for Zabbix valuemap entries.
requirements:
    - "python >= 3.9"
options:
    host_name:
        type: str
        description:
            - Name of the Zabbix host.
        required: true
    name:
        type: str
        description:
            - Name of the Zabbix valuemap.
        required: false
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

- name: Get zabbix valuemap info
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_valuemap_info:
    host_name: example_host
    name: Numbers
"""

RETURN = """
zabbix_valuemap:
  description: List of Zabbix valuemaps.
  returned: always
  type: list
  elements: dict
  sample: [
    {
      "hostid": "10771",
      "mappings": [
        {
          "newvalue": "one",
          "type": "0",
          "value": "1"
        },
        {
          "newvalue": "two",
          "type": "0",
          "value": "2"
        }
      ],
      "name": "Numbers",
      "uuid": "",
      "valuemapid": "1467"
    }
  ]
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class Valuemap(ZabbixBase):
    def get_host_id(self, host_name):
        try:
            host_list = self._zapi.host.get({"filter": {"host": host_name}})
        except Exception as e:
            self._module.fail_json(msg="Failed to get host: %s" % e)

        if len(host_list) < 1:
            self._module.fail_json(msg="Host not found: %s" % host_name)
        else:
            return host_list[0]["hostid"]

    def get_valuemaps(self, host_name, valuemap_name):
        valuemap_list = []
        try:
            data = {"output": "extend", "selectMappings": "extend", "filter": {}}
            data["filter"]["hostid"] = self.get_host_id(host_name)
            if valuemap_name is not None:
                data["filter"]["name"] = valuemap_name

            valuemap_list = self._zapi.valuemap.get(data)
        except Exception as e:
            self._module.fail_json(msg="Failed to get valuemaps: %s" % e)

        if len(valuemap_list) > 0:
            valuemap_list = [valuemap for valuemap in valuemap_list if valuemap["uuid"] == ""]
        if valuemap_name is not None and len(valuemap_list) < 1:
            self._module.fail_json(msg="Valuemap not found: %s" % valuemap_name)

        return valuemap_list


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        host_name=dict(type="str", required=True),
        name=dict(type="str", required=False)
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    host_name = module.params["host_name"]
    name = module.params["name"]

    valuemap = Valuemap(module)
    valuemaps = valuemap.get_valuemaps(host_name, name)
    module.exit_json(changed=False, valuemaps=valuemaps)


if __name__ == "__main__":
    main()
