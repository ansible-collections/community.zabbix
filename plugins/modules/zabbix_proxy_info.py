#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, D3DeFi
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
module: zabbix_proxy_info
short_description: Gather information about Zabbix proxy
version_added: 1.5.0
author:
    - Dusan Matejka (@D3DeFi)
description:
    - This module allows you to obtain detailed information about configured zabbix proxies.
requirements:
    - "python >= 2.6"
    - "zabbix-api >= 0.5.4"
options:
    proxy_name:
        description:
            - Name of the Zabbix proxy.
        required: true
        type: str
    proxy_hosts:
        description:
            - Also return list of hosts monitored by the proxy.
        required: false
        default: false
        type: bool
extends_documentation_fragment:
- community.zabbix.zabbix

'''

EXAMPLES = '''
- name: Get zabbix proxy info alongside the list of hosts monitored by the proxy
  community.zabbix.zabbix_proxy_info:
    server_url: "http://zabbix.example.com/zabbix/"
    login_user: admin
    login_password: secret
    proxy_name: zbx01.example.com
    proxy_hosts: True
'''

RETURN = '''
zabbix_proxy:
  description: example
  returned: always
  type: dict
  sample: {
    "auto_compress": "1",
    "custom_interfaces": "0",
    "description": "ExampleProxy",
    "discover": "0",
    "flags": "0",
    "host": "ExampleProxy",
    "hosts": [
      {
        "host": "ExampleHost",
        "hostid": "10453"
      }
    ],
    "interface": {
      "available": "0",
      "details": [],
      "disable_until": "0",
      "dns": "ExampleProxy.local",
      "error": "",
      "errors_from": "0",
      "hostid": "10452",
      "interfaceid": "10",
      "ip": "10.1.1.2",
      "main": "1",
      "port": "10051",
      "type": "0",
      "useip": "1"
    },
    "ipmi_authtype": "-1",
    "ipmi_password": "",
    "ipmi_privilege": "2",
    "ipmi_username": "",
    "lastaccess": "0",
    "maintenance_from": "0",
    "maintenance_status": "0",
    "maintenance_type": "0",
    "maintenanceid": "0",
    "name": "",
    "proxy_address": "",
    "proxy_hostid": "0",
    "proxyid": "10452",
    "status": "6",
    "templateid": "0",
    "tls_accept": "1",
    "tls_connect": "1",
    "tls_issuer": "",
    "tls_subject": "",
    "uuid": ""
  }
'''


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class Proxy(ZabbixBase):

    def get_proxy(self, name, hosts=False):
        result = {}
        params = {
            'filter': {
                'host': name
            },
            'output': 'extend',
            'selectInterface': 'extend',
        }

        if hosts:
            params['selectHosts'] = ['host', 'hostid']

        try:
            result = self._zapi.proxy.get(params)
        except Exception as e:
            self._module.fail_json(msg="Failed to get proxy information: %s" % e)

        return result[0] if result else {}


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        proxy_name=dict(type='str', required=True),
        proxy_hosts=dict(type='bool', required=False, default=False),
    ))

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    name = module.params['proxy_name']
    hosts = module.params['proxy_hosts']

    proxy = Proxy(module)
    result = proxy.get_proxy(name, hosts)
    module.exit_json(changed=False, zabbix_proxy=result)


if __name__ == "__main__":
    main()
