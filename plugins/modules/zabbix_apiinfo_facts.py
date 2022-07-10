#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, ONODERA Masaru <masaru-onodera@ieee.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: zabbix_apiinfo_facts

short_description: Get Zabbix apiinfo

description:
   - This module allows you to get Zabbix apiinfo.

author:
    - ONODERA Masaru(@masa-orca)

requirements:
    - "zabbix-api >= 0.5.4"

version_added: 1.8.0

extends_documentation_fragment:
    - community.zabbix.zabbix
'''

EXAMPLES = '''
- name: Get apiinfo facts
  zabbix_apiinfo_facts:
    server_url: "http://zabbix.example.com/zabbix/"
    login_user: Admin
    login_password: secret
'''

RETURN = '''
apiinfo:
    description: Zabbix api information
    returned: success
    type: str
    sample: {version: 4.0.42}
'''

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
from ansible_collections.community.zabbix.plugins.module_utils.version import LooseVersion
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class ApiInfo(ZabbixBase):
    def __init__(self, module, zbx=None, zapi_wrapper=None):
        super(ApiInfo, self).__init__(module, zbx, zapi_wrapper)
        if LooseVersion(self._zbx_api_version) < LooseVersion('2.2.0'):
            module.fail_json(msg="This module doesn't support Zabbix versions lower than 2.2.0")

    def get_apiinfo(self):
        try:
            apiinfo = {
                'version': self._zbx_api_version
            }
            self._module.exit_json(apiinfo=apiinfo)
        except Exception as e:
            self._module.fail_json(msg="Failed to get apiinfo version: %s" % e)


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    apiinfo = ApiInfo(module)
    apiinfo.get_apiinfo()


if __name__ == '__main__':
    main()
