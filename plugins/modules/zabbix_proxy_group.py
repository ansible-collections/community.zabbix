#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2024, Evgeny Yurchenko
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible. If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


DOCUMENTATION = r"""
---
module: zabbix_proxy_group
short_description: Create/update/delete Zabbix proxy group
description:
   - This module allows you to create, modify and delete Zabbix proxy group.
author:
    - Evgeny Yurchenko (@BGmot)
requirements:
    - python >= 3.9
options:
    name:
        description:
            - Name of the proxy group.
        required: true
        type: str
    description:
        description:
            - Description of the proxy group.
        required: false
        type: str
    failover_delay:
        description:
            - Failover period for each proxy in the group to have online/offline state.
            - Time suffixes are supported, e.g. 30s, 1m.
        required: false
        type: str
        default: 1m
    min_online:
        description:
            - Minimum number of online proxies required for the group to be online.
            - "Possible values range: 1-1000."
        required: false
        type: str
        default: "1"
    state:
        description:
            - State of the proxy group.
            - On C(present), it will create if proxy group does not exist or update it if the associated data is different.
            - On C(absent) will remove the proxy group if it exists.
        choices: ["present", "absent"]
        default: "present"
        type: str

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

- name: Create/update Zabbix proxy group
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_proxy_group:
    name: ProxyGroup01
    description: Example Zabbix Proxy Group
    state: present
    failover_delay: 10s
    min_online: 2

- name: delete Zabbix proxy group
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_proxy_group:
    name: ProxyGroup01
    state: absent
"""

RETURN = r""" # """


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase

import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class ProxyGroup(ZabbixBase):
    def __init__(self, module, zbx=None, zapi_wrapper=None):
        super(ProxyGroup, self).__init__(module, zbx, zapi_wrapper)
        self.existing_data = None

    def proxy_group_exists(self, proxy_group_name):
        result = self._zapi.proxygroup.get({"output": "extend",
                                            "filter": {"name": proxy_group_name}})

        if len(result) > 0 and "proxy_groupid" in result[0]:
            self.existing_data = result[0]
            return result[0]["proxy_groupid"]
        else:
            return result

    def add_proxy_group(self, data):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)

            parameters = {}
            for item in data:
                if data[item]:
                    parameters[item] = data[item]

            proxy_group_ids_list = self._zapi.proxygroup.create(parameters)

            self._module.exit_json(changed=True,
                                   result="Successfully added proxy group %s" % (data["name"]))

            if len(proxy_group_ids_list) >= 1:
                return proxy_group_ids_list["proxy_groupids"][0]

        except Exception as e:
            self._module.fail_json(msg="Failed to create proxy group %s: %s" % (data["name"], e))

    def delete_proxy_group(self, proxy_group_id, proxy_group_name):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)

            self._zapi.proxygroup.delete([proxy_group_id])

            self._module.exit_json(changed=True, result="Successfully deleted proxy group %s" % proxy_group_name)

        except Exception as e:
            self._module.fail_json(msg="Failed to delete proxy group %s: %s" % (proxy_group_name, str(e)))

    def update_proxy_group(self, proxy_group_id, data):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)

            parameters = {}
            for key in data:
                if data[key]:
                    parameters[key] = data[key]

            parameters["proxy_groupid"] = proxy_group_id

            change_parameters = {}
            difference = zabbix_utils.helper_cleanup_data(zabbix_utils.helper_compare_dictionaries(parameters, self.existing_data, change_parameters))

            if difference == {}:
                self._module.exit_json(changed=False)
            else:
                difference["proxy_groupid"] = proxy_group_id
                self._zapi.proxygroup.update(parameters)
                self._module.exit_json(
                    changed=True,
                    result="Successfully updated proxy group %s (%s)" % (data["name"], proxy_group_id)
                )

        except Exception as e:
            self._module.fail_json(msg="Failed to update proxy group %s: %s" % (data["name"], e))


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        name=dict(type="str", required=True),
        description=dict(type="str", required=False),
        failover_delay=dict(type="str", default="1m"),
        state=dict(type="str", default="present", choices=["present", "absent"]),
        min_online=dict(type="str", default="1")
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    proxy_group_name = module.params["name"]
    description = module.params["description"]
    failover_delay = module.params["failover_delay"]
    min_online = module.params["min_online"]
    state = module.params["state"]

    proxy_group = ProxyGroup(module)

    # check if proxy group already exists
    proxy_group_id = proxy_group.proxy_group_exists(proxy_group_name)

    if proxy_group_id:
        if state == "absent":
            # remove proxy group
            proxy_group.delete_proxy_group(proxy_group_id, proxy_group_name)
        else:
            proxy_group.update_proxy_group(proxy_group_id, {
                "name": proxy_group_name,
                "description": description,
                "failover_delay": str(failover_delay),
                "min_online": str(min_online)
            })
    else:
        if state == "absent":
            # the proxy group is already deleted.
            module.exit_json(changed=False)

        proxy_group_id = proxy_group.add_proxy_group(data={
            "name": proxy_group_name,
            "description": description,
            "failover_delay": str(failover_delay),
            "min_online": str(min_online)
        })


if __name__ == "__main__":
    main()
