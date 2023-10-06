#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, ONODERA Masaru <masaru-onodera@ieee.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: zabbix_api_info

short_description: Retrieve Zabbix API info

description:
   - This module allows you to retrieve Zabbix api info.

author:
    - ONODERA Masaru(@masa-orca)

requirements:
    - "python >= 3.9"

version_added: 2.1.0

extends_documentation_fragment:
    - community.zabbix.zabbix
'''

EXAMPLES = '''
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

- name: Retrieve API information
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_api_info:
  register: zbx_api_info
'''

RETURN = '''
api:
    description: Summaries of Zabbix API info
    returned: success
    type: dict
    contains:
        version:
            description: API version
            type: str
            sample: 6.0.18
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.compat.version import LooseVersion

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class ApiInfo(ZabbixBase):
    def __init__(self, module, zbx=None, zapi_wrapper=None):
        super(ApiInfo, self).__init__(module, zbx, zapi_wrapper)
        if LooseVersion(self._zbx_api_version) < LooseVersion('2.2.0'):
            module.fail_json(msg="This module doesn't support Zabbix versions lower than 2.2.0")

    def get_api_info(self):
        if self._module.check_mode:
            self._module.exit_json(changed=False)
        try:
            api = {
                'version': self._zbx_api_version
            }
            self._module.exit_json(api=api)
        except Exception as e:
            self._module.fail_json(msg="Failed to retrieve API info: %s" % e)


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    api_info = ApiInfo(module)
    api_info.get_api_info()


if __name__ == '__main__':
    main()
