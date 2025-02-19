#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2017, Alen Komic
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
module: zabbix_proxy
short_description: Create/delete/get/update Zabbix proxies
description:
   - This module allows you to create, modify, get and delete Zabbix proxy entries.
author:
    - "Alen Komic (@akomic)"
requirements:
    - "python >= 3.9"
options:
    proxy_name:
        description:
            - Name of the proxy in Zabbix.
        required: true
        type: str
    proxy_address:
        description:
            - Deprecated for Zabbix version >= 7.0.
            - Comma-delimited list of IP/CIDR addresses or DNS names to accept active proxy requests from.
            - Requires I(status=active).
        required: false
        type: str
    description:
        description:
            - Description of the proxy.
        required: false
        type: str
    status:
        description:
            - Deprecated for Zabbix version >= 7.0.
            - Type of proxy. (4 - active, 5 - passive)
        required: false
        choices: ["active", "passive"]
        default: "active"
        type: str
    tls_connect:
        description:
            - Connections to proxy.
        required: false
        choices: ["no_encryption","PSK","certificate"]
        default: "no_encryption"
        type: str
    tls_accept:
        description:
            - Connections from proxy.
        required: false
        choices: ["no_encryption","PSK","certificate"]
        default: "no_encryption"
        type: str
    ca_cert:
        description:
            - Certificate issuer.
        required: false
        aliases: [ tls_issuer ]
        type: str
    tls_subject:
        description:
            - Certificate subject.
        required: false
        type: str
    tls_psk_identity:
        description:
            - PSK identity. Required if either I(tls_connect) or I(tls_accept) has PSK enabled.
        required: false
        type: str
    tls_psk:
        description:
            - The preshared key, at least 32 hex digits. Required if either I(tls_connect) or I(tls_accept) has PSK enabled.
        required: false
        type: str
    state:
        description:
            - State of the proxy.
            - On C(present), it will create if proxy does not exist or update the proxy if the associated data is different.
            - On C(absent) will remove a proxy if it exists.
        required: false
        choices: ["present", "absent"]
        default: "present"
        type: str
    interface:
        description:
            - Deprecated for Zabbix version >= 7.0.
            - Dictionary with params for the interface when proxy is in passive mode.
            - For more information, review proxy interface documentation at
            - U(https://www.zabbix.com/documentation/current/en/manual/api/reference/proxy/object#proxy-interface).
        required: false
        suboptions:
            useip:
                type: int
                description:
                    - Connect to proxy interface with IP address instead of DNS name.
                    - 0 (don't use ip), 1 (use ip).
                default: 0
                choices: [0, 1]
            ip:
                type: str
                description:
                    - IP address used by proxy interface.
                    - Required if I(useip=1).
                default: ""
            dns:
                type: str
                description:
                    - DNS name of the proxy interface.
                    - Required if I(useip=0).
                default: ""
            port:
                type: str
                description:
                    - Port used by proxy interface.
                default: "10051"
        default: {}
        type: dict
    address:
        description:
            - Parameter introduced in Zabbix 7.0.
            - IP address or DNS name to connect to.
            - Required if the Zabbix proxy operating mode is passive
        required: false
        type: str
    port:
        description:
            - Parameter introduced in Zabbix 7.0.
            - Port number to connect to.
            - supported if the Zabbix proxy operating mode is passive.
        required: false
        type: str
        default: "10051"
    proxy_group:
        description:
            - Parameter introduced in Zabbix 7.0.
            - Proxy group name.
        required: false
        type: str
    local_address:
        description:
            - Parameter introduced in Zabbix 7.0.
            - Address for active agents. IP address or DNS name to connect to.
            - Required if proxy_groupid is not 0
        required: false
        type: str
    local_port:
        description:
            - Parameter introduced in Zabbix 7.0.
            - Local proxy port number to connect to.
            - Supported if proxy_groupid is not 0
        required: false
        type: str
        default: "10051"
    allowed_addresses:
        description:
            - Parameter introduced in Zabbix 7.0.
            - Comma-delimited IP addresses or DNS names of active Zabbix proxy.
        required: false
        type: str
    operating_mode:
        description:
            - Parameter introduced in Zabbix 7.0.
            - Type of proxy.
        required: false
        choices: ["active", "passive"]
        default: "active"
        type: str
    custom_timeouts:
        description:
            - Parameter introduced in Zabbix 7.0.
            - Whether to override global item timeouts on the proxy level.
            - 0 - use global settings; 1 - override timeouts.
        required: false
        type: int
        default: 0
        choices: [0, 1]
    timeout_zabbix_agent:
        description:
            - Parameter introduced in Zabbix 7.0.
            - Spend no more than this number of seconds on Zabbix agent checks processing.
            - Accepts seconds or time unit with suffix (e.g., 30s, 1m).
            - "Possible values range: 1-600s."
            - Rired if if C(custom_timeouts) is set to 1.
        required: false
        type: str
    timeout_simple_check:
        description:
            - Parameter introduced in Zabbix 7.0.
            - Spend no more than this number of seconds on simple checks processing.
            - Accepts seconds or time unit with suffix (e.g., 30s, 1m).
            - "Possible values range: 1-600s."
            - Required if if C(custom_timeouts) is set to 1.
        required: false
        type: str
    timeout_snmp_agent:
        description:
            - Parameter introduced in Zabbix 7.0.
            - Spend no more than this number of seconds on SNMP agent checks processing.
            - Accepts seconds or time unit with suffix (e.g., 30s, 1m).
            - "Possible values range: 1-600s."
            - Required if if C(custom_timeouts) is set to 1.
        required: false
        type: str
    timeout_external_check:
        description:
            - Parameter introduced in Zabbix 7.0.
            - Spend no more than this number of seconds on external checks processing.
            - Accepts seconds or time unit with suffix (e.g., 30s, 1m).
            - "Possible values range: 1-600s."
            - Required if if C(custom_timeouts) is set to 1.
        required: false
        type: str
    timeout_db_monitor:
        description:
            - Parameter introduced in Zabbix 7.0.
            - Spend no more than this number of seconds on DB checks processing.
            - Accepts seconds or time unit with suffix (e.g., 30s, 1m).
            - "Possible values range: 1-600s."
            - Required if if C(custom_timeouts) is set to 1.
        required: false
        type: str
    timeout_http_agent:
        description:
            - Parameter introduced in Zabbix 7.0.
            - Spend no more than this number of seconds on HTTPagent checks processing.
            - Accepts seconds or time unit with suffix (e.g., 30s, 1m).
            - "Possible values range: 1-600s."
            - Required if if C(custom_timeouts) is set to 1.
        required: false
        type: str
    timeout_ssh_agent:
        description:
            - Parameter introduced in Zabbix 7.0.
            - Spend no more than this number of seconds on SSH checks processing.
            - Accepts seconds or time unit with suffix (e.g., 30s, 1m).
            - "Possible values range: 1-600s."
            - Required if if C(custom_timeouts) is set to 1.
        required: false
        type: str
    timeout_telnet_agent:
        description:
            - Parameter introduced in Zabbix 7.0.
            - Spend no more than this number of seconds on Telnet checks processing.
            - Accepts seconds or time unit with suffix (e.g., 30s, 1m).
            - "Possible values range: 1-600s."
            - Required if if C(custom_timeouts) is set to 1.
        required: false
        type: str
    timeout_script:
        description:
            - Parameter introduced in Zabbix 7.0.
            - Spend no more than this number of seconds on script type checks processing.
            - Accepts seconds or time unit with suffix (e.g., 30s, 1m).
            - "Possible values range: 1-600s."
            - Required if if C(custom_timeouts) is set to 1.
        required: false
        type: str
    timeout_browser:
        description:
            - Parameter introduced in Zabbix 7.0.
            - Spend no more than this number of seconds on browser type checks processing.
            - Accepts seconds or time unit with suffix (e.g., 30s, 1m).
            - "Possible values range: 1-600s."
            - Required if if C(custom_timeouts) is set to 1.
        required: false
        type: str

extends_documentation_fragment:
- community.zabbix.zabbix

"""

EXAMPLES = r"""
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

- name: Create or update a proxy with proxy type active (Zabbix version < 7.0)
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_proxy:
    proxy_name: ExampleProxy
    description: ExampleProxy
    status: active
    state: present
    proxy_address: ExampleProxy.local

- name: Create a new passive proxy using only its IP (Zabbix version < 7.0)
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_proxy:
    proxy_name: ExampleProxy
    description: ExampleProxy
    status: passive
    state: present
    interface:
      useip: 1
      ip: 10.1.1.2
      port: 10051

- name: Create a new passive proxy using only its DNS (Zabbix version < 7.0)
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_proxy:
    proxy_name: ExampleProxy
    description: ExampleProxy
    status: passive
    state: present
    interface:
      dns: proxy.example.com
      port: 10051

- name: Create or update a proxy with proxy type active (Zabbix version >= 7.0)
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_proxy:
    proxy_name: ExampleProxy
    description: ExampleProxy
    operating_mode: active
    state: present
    allowed_addresses: ExampleProxy.local

- name: Create a new passive proxy using only its IP (Zabbix version >= 7.0)
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_proxy:
    proxy_name: ExampleProxy
    description: ExampleProxy
    operating_mode: passive
    state: present
    address: 10.1.1.2
    port: 10051

- name: Create a new passive proxy using only its DNS (Zabbix version >= 7.0)
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_proxy:
    proxy_name: ExampleProxy
    description: ExampleProxy
    operating_mode: passive
    state: present
    address: proxy.example.com
    port: 10051
"""

RETURN = r""" # """


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase

from ansible.module_utils.compat.version import LooseVersion

import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class Proxy(ZabbixBase):
    def __init__(self, module, zbx=None, zapi_wrapper=None):
        super(Proxy, self).__init__(module, zbx, zapi_wrapper)
        self.existing_data = None

    def proxy_exists(self, proxy_name):
        if LooseVersion(self._zbx_api_version) < LooseVersion("7.0"):
            result = self._zapi.proxy.get({"output": "extend",
                                           "selectInterface": "extend",
                                           "filter": {"host": proxy_name}})
        else:
            result = self._zapi.proxy.get({"output": "extend",
                                           "filter": {"name": proxy_name}})

        if len(result) > 0 and "proxyid" in result[0]:
            self.existing_data = result[0]
            return result[0]["proxyid"]
        else:
            return result

    def add_proxy(self, data):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)

            parameters = {}
            for item in data:
                if data[item]:
                    parameters[item] = data[item]

            if LooseVersion(self._zbx_api_version) < LooseVersion("7.0"):
                if "proxy_address" in data and data["status"] != "5":
                    parameters.pop("proxy_address", False)
            else:
                if "allowed_addresses" in data and data["operating_mode"] != "0":
                    parameters.pop("allowed_addresses", False)

            if LooseVersion(self._zbx_api_version) < LooseVersion("7.0"):
                if "interface" in data and data["status"] != "6":
                    parameters.pop("interface", False)
            else:
                if "interface" in data and data["operating_mode"] != "1":
                    parameters.pop("interface", False)

                if data["proxy_group"]:
                    proxy_group = data["proxy_group"]
                    result = self._zapi.proxygroup.get({"output": "extend", "filter": {"name": proxy_group}})

                    if len(result) == 0:
                        self._module.fail_json(msg="Failed to find proxy group %s" % (proxy_group))

                    proxy_group_id = result[0]["proxy_groupid"]
                    parameters.pop("proxy_group", False)
                    parameters["proxy_groupid"] = proxy_group_id

            proxy_ids_list = self._zapi.proxy.create(parameters)

            if LooseVersion(self._zbx_api_version) < LooseVersion("7.0"):
                self._module.exit_json(changed=True,
                                       result="Successfully added proxy %s (%s)" % (data["host"], data["status"]))
            else:
                self._module.exit_json(changed=True,
                                       result="Successfully added proxy %s (%s)" % (data["name"], data["operating_mode"]))
            if len(proxy_ids_list) >= 1:
                return proxy_ids_list["proxyids"][0]
        except Exception as e:
            if LooseVersion(self._zbx_api_version) < LooseVersion("7.0"):
                self._module.fail_json(msg="Failed to create proxy %s: %s" % (data["host"], e))
            else:
                self._module.fail_json(msg="Failed to create proxy %s: %s" % (data["name"], e))

    def delete_proxy(self, proxy_id, proxy_name):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            self._zapi.proxy.delete([proxy_id])
            self._module.exit_json(changed=True, result="Successfully deleted proxy %s" % proxy_name)
        except Exception as e:
            self._module.fail_json(msg="Failed to delete proxy %s: %s" % (proxy_name, str(e)))

    def update_proxy(self, proxy_id, data):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)

            parameters = {}
            for key in data:
                if data[key]:
                    parameters[key] = data[key]

            if LooseVersion(self._zbx_api_version) < LooseVersion("7.0"):
                status_or_operating_mode_name = "status"
                status_or_operating_mode_value = "5"
            else:
                status_or_operating_mode_name = "operating_mode"
                status_or_operating_mode_value = "0"
                if "custom_timeouts" in parameters:
                    parameters["custom_timeouts"] = str(parameters["custom_timeouts"])

                if data["proxy_group"]:
                    proxy_group = data["proxy_group"]
                    result = self._zapi.proxygroup.get({"output": "extend", "filter": {"name": proxy_group}})

                    if len(result) == 0:
                        self._module.fail_json(msg="Failed to find proxy group %s" % (proxy_group))

                    proxy_group_id = result[0]["proxy_groupid"]
                    parameters.pop("proxy_group", False)
                    parameters["proxy_groupid"] = proxy_group_id

            if "interface" in parameters:
                if parameters[status_or_operating_mode_name] == status_or_operating_mode_value:
                    # Active proxy
                    parameters.pop("interface", False)
                else:
                    # Passive proxy
                    parameters["interface"]["useip"] = str(parameters["interface"]["useip"])

            if parameters[status_or_operating_mode_name] == status_or_operating_mode_value:
                # Active proxy
                parameters.pop("tls_connect", False)
            else:
                # Passive proxy
                parameters.pop("tls_accept", False)

            parameters["proxyid"] = proxy_id

            change_parameters = {}
            difference = zabbix_utils.helper_cleanup_data(zabbix_utils.helper_compare_dictionaries(parameters, self.existing_data, change_parameters))

            if difference == {}:
                self._module.exit_json(changed=False)
            else:
                difference["proxyid"] = proxy_id
                self._zapi.proxy.update(parameters)
                if LooseVersion(self._zbx_api_version) < LooseVersion("7.0"):
                    self._module.exit_json(
                        changed=True,
                        result="Successfully updated proxy %s (%s)" % (data["host"], proxy_id)
                    )
                else:
                    self._module.exit_json(
                        changed=True,
                        result="Successfully updated proxy %s (%s)" % (data["name"], proxy_id)
                    )
        except Exception as e:
            if LooseVersion(self._zbx_api_version) < LooseVersion("7.0"):
                self._module.fail_json(msg="Failed to update proxy %s: %s" %
                                           (data["host"], e))
            else:
                self._module.fail_json(msg="Failed to update proxy %s: %s" %
                                           (data["name"], e))


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        proxy_name=dict(type="str", required=True),
        proxy_address=dict(type="str", required=False),
        status=dict(type="str", default="active", choices=["active", "passive"]),
        allowed_addresses=dict(type="str", required=False, default=None),
        operating_mode=dict(type="str", default="active", choices=["active", "passive"]),
        state=dict(type="str", default="present", choices=["present", "absent"]),
        description=dict(type="str", required=False),
        tls_connect=dict(type="str", default="no_encryption", choices=["no_encryption", "PSK", "certificate"]),
        tls_accept=dict(type="str", default="no_encryption", choices=["no_encryption", "PSK", "certificate"]),
        ca_cert=dict(type="str", required=False, default=None, aliases=["tls_issuer"]),
        tls_subject=dict(type="str", required=False, default=None),
        tls_psk_identity=dict(type="str", required=False, default=None),
        tls_psk=dict(type="str", required=False, default=None, no_log=True),
        interface=dict(
            type="dict",
            required=False,
            default={},
            options=dict(
                useip=dict(type="int", choices=[0, 1], default=0),
                ip=dict(type="str", default=""),
                dns=dict(type="str", default=""),
                port=dict(type="str", default="10051")
            ),
        ),
        address=dict(type="str", required=False, default=None),
        port=dict(type="str", required=False, default="10051"),
        proxy_group=dict(type="str", required=False, default=None),
        local_address=dict(type="str", required=False, default=None),
        local_port=dict(type="str", required=False, default="10051"),
        custom_timeouts=dict(type="int", required=False, default=0, choices=[0, 1]),
        timeout_zabbix_agent=dict(type="str", required=False, default=None),
        timeout_simple_check=dict(type="str", required=False, default=None),
        timeout_snmp_agent=dict(type="str", required=False, default=None),
        timeout_external_check=dict(type="str", required=False, default=None),
        timeout_db_monitor=dict(type="str", required=False, default=None),
        timeout_http_agent=dict(type="str", required=False, default=None),
        timeout_ssh_agent=dict(type="str", required=False, default=None),
        timeout_telnet_agent=dict(type="str", required=False, default=None),
        timeout_script=dict(type="str", required=False, default=None),
        timeout_browser=dict(type="str", required=False, default=None)
    ))

    # Create temporary proxy object to be able to pull Zabbix version to resolve parameters dependencies
    module = AnsibleModule(argument_spec=argument_spec)
    proxy = Proxy(module)

    if LooseVersion(proxy._zbx_api_version) < LooseVersion("7.0"):
        required = [
            ["tls_connect", "PSK", ("tls_psk_identity", "tls_psk"), False],
            ["tls_accept", "PSK", ("tls_psk_identity", "tls_psk"), False],
            ["status", "passive", ("interface",)]
        ]
    else:
        required = [
            ["operating_mode", "passive", ("address",)],
            ["custom_timeouts", 1, (
                "timeout_zabbix_agent", "timeout_simple_check", "timeout_snmp_agent",
                "timeout_external_check", "timeout_db_monitor", "timeout_http_agent",
                "timeout_ssh_agent", "timeout_telnet_agent", "timeout_script",
                "timeout_browser"), False]
        ]

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=required,
        supports_check_mode=True
    )

    proxy_name = module.params["proxy_name"]
    description = module.params["description"]
    tls_connect = module.params["tls_connect"]
    tls_accept = module.params["tls_accept"]
    tls_issuer = module.params["ca_cert"]
    tls_subject = module.params["tls_subject"]
    tls_psk_identity = module.params["tls_psk_identity"]
    tls_psk = module.params["tls_psk"]
    state = module.params["state"]

    proxy = Proxy(module)

    # convert enabled / disabled to integer
    if LooseVersion(proxy._zbx_api_version) < LooseVersion("7.0"):
        proxy_address = ""
        if "proxy_address" in module.params:
            proxy_address = module.params["proxy_address"]
        if "interface" in module.params:
            interface = module.params["interface"]
        status = 6 if module.params["status"] == "passive" else 5
    else:
        allowed_addresses = module.params["allowed_addresses"]
        operating_mode = 1 if module.params["operating_mode"] == "passive" else 0
        address = '127.0.0.1' if operating_mode == 0 else module.params["address"]
        port = module.params["port"]
        proxy_group = module.params["proxy_group"]
        local_address = module.params["local_address"]
        local_port = module.params["local_port"]
        allowed_addresses = module.params["allowed_addresses"]
        custom_timeouts = module.params["custom_timeouts"]
        timeout_zabbix_agent = module.params["timeout_zabbix_agent"]
        timeout_simple_check = module.params["timeout_simple_check"]
        timeout_snmp_agent = module.params["timeout_snmp_agent"]
        timeout_external_check = module.params["timeout_external_check"]
        timeout_db_monitor = module.params["timeout_db_monitor"]
        timeout_http_agent = module.params["timeout_http_agent"]
        timeout_ssh_agent = module.params["timeout_ssh_agent"]
        timeout_telnet_agent = module.params["timeout_telnet_agent"]
        timeout_script = module.params["timeout_script"]
        timeout_browser = module.params["timeout_browser"]
        if proxy_group:
            if local_address is None:
                module.fail_json(msg="local_address parameter is required when proxy_group is specified.")

    if tls_connect == "certificate":
        tls_connect = 4
    elif tls_connect == "PSK":
        tls_connect = 2
    else:
        tls_connect = 1

    if tls_accept == "certificate":
        tls_accept = 4
    elif tls_accept == "PSK":
        tls_accept = 2
    else:
        tls_accept = 1

    # check if proxy already exists
    proxy_id = proxy.proxy_exists(proxy_name)

    if proxy_id:
        if state == "absent":
            # remove proxy
            proxy.delete_proxy(proxy_id, proxy_name)
        else:
            if LooseVersion(proxy._zbx_api_version) < LooseVersion("7.0"):
                proxy.update_proxy(proxy_id, {
                    "host": proxy_name,
                    "description": description,
                    "status": str(status),
                    "tls_connect": str(tls_connect),
                    "tls_accept": str(tls_accept),
                    "tls_issuer": tls_issuer,
                    "tls_subject": tls_subject,
                    "tls_psk_identity": tls_psk_identity,
                    "tls_psk": tls_psk,
                    "interface": interface,
                    "proxy_address": proxy_address
                })
            else:
                proxy.update_proxy(proxy_id, {
                    "name": proxy_name,
                    "description": description,
                    "operating_mode": str(operating_mode),
                    "tls_connect": str(tls_connect),
                    "tls_accept": str(tls_accept),
                    "tls_issuer": tls_issuer,
                    "tls_subject": tls_subject,
                    "tls_psk_identity": tls_psk_identity,
                    "tls_psk": tls_psk,
                    "allowed_addresses": allowed_addresses,
                    "address": address,
                    "port": port,
                    "proxy_group": proxy_group,
                    "local_address": local_address,
                    "local_port": local_port,
                    "custom_timeouts": custom_timeouts,
                    "timeout_zabbix_agent": timeout_zabbix_agent,
                    "timeout_simple_check": timeout_simple_check,
                    "timeout_snmp_agent": timeout_snmp_agent,
                    "timeout_external_check": timeout_external_check,
                    "timeout_db_monitor": timeout_db_monitor,
                    "timeout_http_agent": timeout_http_agent,
                    "timeout_ssh_agent": timeout_ssh_agent,
                    "timeout_telnet_agent": timeout_telnet_agent,
                    "timeout_script": timeout_script,
                    "timeout_browser": timeout_browser
                })
    else:
        if state == "absent":
            # the proxy is already deleted.
            module.exit_json(changed=False)

        if LooseVersion(proxy._zbx_api_version) < LooseVersion("7.0"):
            proxy_id = proxy.add_proxy(data={
                "host": proxy_name,
                "description": description,
                "status": str(status),
                "tls_connect": str(tls_connect),
                "tls_accept": str(tls_accept),
                "tls_issuer": tls_issuer,
                "tls_subject": tls_subject,
                "tls_psk_identity": tls_psk_identity,
                "tls_psk": tls_psk,
                "interface": interface,
                "proxy_address": proxy_address
            })
        else:
            proxy_id = proxy.add_proxy(data={
                "name": proxy_name,
                "description": description,
                "operating_mode": str(operating_mode),
                "tls_connect": str(tls_connect),
                "tls_accept": str(tls_accept),
                "tls_issuer": tls_issuer,
                "tls_subject": tls_subject,
                "tls_psk_identity": tls_psk_identity,
                "tls_psk": tls_psk,
                "allowed_addresses": allowed_addresses,
                "address": address,
                "port": port,
                "proxy_group": proxy_group,
                "local_address": local_address,
                "local_port": local_port,
                "custom_timeouts": custom_timeouts,
                "timeout_zabbix_agent": timeout_zabbix_agent,
                "timeout_simple_check": timeout_simple_check,
                "timeout_snmp_agent": timeout_snmp_agent,
                "timeout_external_check": timeout_external_check,
                "timeout_db_monitor": timeout_db_monitor,
                "timeout_http_agent": timeout_http_agent,
                "timeout_ssh_agent": timeout_ssh_agent,
                "timeout_telnet_agent": timeout_telnet_agent,
                "timeout_script": timeout_script,
                "timeout_browser": timeout_browser
            })


if __name__ == "__main__":
    main()
