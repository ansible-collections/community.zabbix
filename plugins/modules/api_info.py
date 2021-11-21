#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: api_info

short_description: Get info about the Zabbix API

description:
    - This module allows you to fetch the apiinfo endpoints
    - https://www.zabbix.com/documentation/current/manual/api/reference/apiinfo/version

author:
    - Markus Fischbacher (@rockaut)

notes:
    - Uses new httpapi implementation

extends_documentation_fragment:
    - community.zabbix.zabbix

'''

EXAMPLES = '''
- name: Fetch Zabbix API infos
  community.zabbix.api_info:
  register: zabbix_apiinfo
'''

RETURN = '''
response: The returned value of apiinfo.version
'''


from distutils.version import LooseVersion
from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.api_request import ZabbixApiRequest


def main():
    """Main ansible module function
    """

    argument_spec = dict()
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    api_request = ZabbixApiRequest(module)
    v = api_request.api_version()
    #alias = "Admin"
    #v = api_request.user.get({'output': 'extend', 'filter': {'alias': alias},
    #                                           'getAccess': True, 'selectMedias': 'extend',
    #                                           'selectUsrgrps': 'extend'})

    module.exit_json(changed=False, response=v)

if __name__ == '__main__':
    main()
