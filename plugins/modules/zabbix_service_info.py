#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, D3DeFi
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
module: zabbix_service_info
short_description: Gather information about Zabbix service
author:
    - Kanstantsin Maksimau (@us3241)
description:
    - This module allows you to obtain detailed information about configured zabbix service.
requirements:
    - "python >= 3.9"
options:
    service_name:
        description:
            - Name of the Zabbix service.
        required: true
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

- name: Get zabbix service info
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_service_info:
    service_name: zbx01.example.com
"""

RETURN = """
zabbix_service:
  description: example
  returned: always
  type: dict
  sample: {
            "algorithm": "2",
            "children": [
                {
                    "algorithm": "0",
                    "created_at": "1712743194",
                    "description": "",
                    "name": "example children",
                    "propagation_rule": "0",
                    "propagation_value": "0",
                    "readonly": false,
                    "serviceid": "81",
                    "sortorder": "0",
                    "status": "-1",
                    "uuid": "ce6e1a3784a547b48ee6707f6e061102",
                    "weight": "0"
                }
            ],
            "created_at": "1709717864",
            "description": "",
            "name": "example service",
            "parents": [],
            "problem_tags": [],
            "propagation_rule": "0",
            "propagation_value": "0",
            "readonly": false,
            "serviceid": "51",
            "sortorder": "0",
            "status": "-1",
            "status_rules": [],
            "tags": [],
            "uuid": "420e48b363fe473c95288c817031447f",
            "weight": "0"
        }
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class Service(ZabbixBase):

    def get_service(self, name):
        result = {}
        params = {
            "filter": {
                "name": name
            },
            "output": "extend",
            "selectParents": "extend",
            "selectTags": "extend",
            "selectProblemTags": "extend",
            "selectChildren": "extend",
            "selectStatusRules": "extend"
        }

        try:
            result = self._zapi.service.get(params)
        except Exception as e:
            self._module.fail_json(msg="Failed to get service information: %s" % e)

        return result[0] if result else {}


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        service_name=dict(type="str", required=True),
    ))

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    name = module.params["service_name"]

    service = Service(module)
    result = service.get_service(name)
    module.exit_json(changed=False, zabbix_service=result)


if __name__ == "__main__":
    main()
