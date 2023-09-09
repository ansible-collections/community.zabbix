#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, ONODERA Masaru <masaru-onodera@ieee.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: zabbix_housekeeping

short_description: Update Zabbix housekeeping

description:
   - This module allows you to modify Zabbix housekeeping setting.

author:
    - ONODERA Masaru(@masa-orca)

requirements:
    - "python >= 3.9"

version_added: 1.6.0

options:
    hk_events_mode:
        description:
            - Internal housekeeping for events and alerts will be enabled if C(true).
        required: false
        type: bool
    hk_events_trigger:
        description:
            - Storage period of trigger data (e.g. 365d).
        required: false
        type: str
    hk_events_service:
        description:
            - Storage period of service data (e.g. 365d).
        required: false
        type: str
    hk_events_internal:
        description:
            - Storage period of internal data (e.g. 365d).
        required: false
        type: str
    hk_events_discovery:
        description:
            - Storage period of network discovery (e.g. 365d).
        required: false
        type: str
    hk_events_autoreg:
        description:
            - Storage period of autoregistration data (e.g. 365d).
        required: false
        type: str
    hk_services_mode:
        description:
            - Internal housekeeping for services will be enabled if C(true).
        required: false
        type: bool
    hk_services:
        description:
            - Storage period of services data (e.g. 365d).
        required: false
        type: str
    hk_audit_mode:
        description:
            - Internal housekeeping for audit will be enabled if C(true).
        required: false
        type: bool
    hk_audit:
        description:
            - Storage period of audit data (e.g. 365d).
        required: false
        type: str
    hk_sessions_mode:
        description:
            - Internal housekeeping for sessions will be enabled if C(true).
        required: false
        type: bool
    hk_sessions:
        description:
            - Storage period of sessions data (e.g. 365d).
        required: false
        type: str
    hk_history_mode:
        description:
            - Internal housekeeping for history will be enabled if C(true).
        required: false
        type: bool
    hk_history_global:
        description:
            - Overriding history period of each items will be enabled if C(true).
        required: false
        type: bool
    hk_history:
        description:
            - Storage priod of history data (e.g. 365d).
        required: false
        type: str
    hk_trends_mode:
        description:
            - Internal housekeeping for trends will be enabled if C(true).
        required: false
        type: bool
    hk_trends_global:
        description:
            - Overriding trend period of each items will be enabled if C(true).
        required: false
        type: bool
    hk_trends:
        description:
            - Storage priod of trends data (e.g. 365d).
        required: false
        type: str
    compression_status:
        description:
            - TimescaleDB compression for history and trends will be enabled if C(true).
        required: false
        type: bool
    compress_older:
        description:
            - Compress history and trends records older than this period if I(compression_status=true).
        required: false
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

- name: Update housekeeping all parameter
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_housekeeping:
    login_user: Admin
    login_password: secret
    hk_events_mode: yes
    hk_events_trigger: 365d
    hk_events_service: 365d
    hk_events_internal: 365d
    hk_events_discovery: 365d
    hk_events_autoreg: 365d
    hk_services_mode: yes
    hk_services: 365d
    hk_audit_mode: yes
    hk_audit: 365d
    hk_sessions_mode: yes
    hk_sessions: 365d
    hk_history_mode: yes
    hk_history_global: yes
    hk_history: 365d
    hk_trends_mode: yes
    hk_trends_global: yes
    hk_trends: 365d
    compression_status: off
    compress_older: 7d
"""

RETURN = """
msg:
    description: The result of the operation
    returned: success
    type: str
    sample: "Successfully update housekeeping setting"
"""

import re

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class Housekeeping(ZabbixBase):
    # get housekeeping setting
    def get_housekeeping(self):
        try:
            return self._zapi.housekeeping.get({"output": "extend"})
        except Exception as e:
            self._module.fail_json(msg="Failed to get housekeeping setting: %s" % e)

    # Check parameter about time is valid.
    def check_time_parameter(self, key_name, value):
        match_result = re.match("^[0-9]+[smhdw]$", value)
        if not match_result:
            self._module.fail_json(msg="Invalid value for %s! Please set value like 365d." % key_name)

    # update housekeeping setting
    def update_housekeeping(
            self,
            current_housekeeping,
            hk_events_mode,
            hk_events_trigger,
            hk_events_service,
            hk_events_internal,
            hk_events_discovery,
            hk_events_autoreg,
            hk_services_mode,
            hk_services,
            hk_audit_mode,
            hk_audit,
            hk_sessions_mode,
            hk_sessions,
            hk_history_mode,
            hk_history_global,
            hk_history,
            hk_trends_mode,
            hk_trends_global,
            hk_trends,
            compression_status,
            compress_older):
        try:
            params = {}

            if isinstance(hk_events_mode, bool):
                params["hk_events_mode"] = str(int(hk_events_mode))

            if hk_events_trigger:
                self.check_time_parameter("hk_events_trigger", hk_events_trigger)
                params["hk_events_trigger"] = hk_events_trigger

            if hk_events_service:
                self.check_time_parameter("hk_events_service", hk_events_service)
                params["hk_events_service"] = hk_events_service

            if hk_events_internal:
                self.check_time_parameter("hk_events_internal", hk_events_internal)
                params["hk_events_internal"] = hk_events_internal

            if hk_events_discovery:
                self.check_time_parameter("hk_events_discovery", hk_events_discovery)
                params["hk_events_discovery"] = hk_events_discovery

            if hk_events_autoreg:
                self.check_time_parameter("hk_events_autoreg", hk_events_autoreg)
                params["hk_events_autoreg"] = hk_events_autoreg

            if isinstance(hk_services_mode, bool):
                params["hk_services_mode"] = str(int(hk_services_mode))

            if hk_services:
                self.check_time_parameter("hk_services", hk_services)
                params["hk_services"] = hk_services

            if isinstance(hk_audit_mode, bool):
                params["hk_audit_mode"] = str(int(hk_audit_mode))

            if hk_audit:
                self.check_time_parameter("hk_audit", hk_audit)
                params["hk_audit"] = hk_audit

            if isinstance(hk_sessions_mode, bool):
                params["hk_sessions_mode"] = str(int(hk_sessions_mode))

            if hk_sessions:
                self.check_time_parameter("hk_sessions", hk_sessions)
                params["hk_sessions"] = hk_sessions

            if isinstance(hk_history_mode, bool):
                params["hk_history_mode"] = str(int(hk_history_mode))

            if isinstance(hk_history_global, bool):
                params["hk_history_global"] = str(int(hk_history_global))

            if hk_history:
                self.check_time_parameter("hk_history", hk_history)
                params["hk_history"] = hk_history

            if isinstance(hk_trends_mode, bool):
                params["hk_trends_mode"] = str(int(hk_trends_mode))

            if isinstance(hk_trends_global, bool):
                params["hk_trends_global"] = str(int(hk_trends_global))

            if hk_trends:
                self.check_time_parameter("hk_trends", hk_trends)
                params["hk_trends"] = hk_trends

            if isinstance(compression_status, bool):
                params["compression_status"] = str(int(compression_status))

            if compress_older:
                self.check_time_parameter("compress_older", compress_older)
                params["compress_older"] = compress_older

            future_housekeeping = current_housekeeping.copy()
            future_housekeeping.update(params)

            if future_housekeeping != current_housekeeping:
                if self._module.check_mode:
                    self._module.exit_json(changed=True)

                self._zapi.housekeeping.update(params)
                self._module.exit_json(changed=True, result="Successfully update housekeeping setting")
            else:
                self._module.exit_json(changed=False, result="Housekeeping setting is already up to date")
        except Exception as e:
            self._module.fail_json(msg="Failed to update housekeeping setting, Exception: %s" % e)


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        hk_events_mode=dict(type="bool"),
        hk_events_trigger=dict(type="str"),
        hk_events_service=dict(type="str"),
        hk_events_internal=dict(type="str"),
        hk_events_discovery=dict(type="str"),
        hk_events_autoreg=dict(type="str"),
        hk_services_mode=dict(type="bool"),
        hk_services=dict(type="str"),
        hk_audit_mode=dict(type="bool"),
        hk_audit=dict(type="str"),
        hk_sessions_mode=dict(type="bool"),
        hk_sessions=dict(type="str"),
        hk_history_mode=dict(type="bool"),
        hk_history_global=dict(type="bool"),
        hk_history=dict(type="str"),
        hk_trends_mode=dict(type="bool"),
        hk_trends_global=dict(type="bool"),
        hk_trends=dict(type="str"),
        compression_status=dict(type="bool"),
        compress_older=dict(type="str")
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    hk_events_mode = module.params["hk_events_mode"]
    hk_events_trigger = module.params["hk_events_trigger"]
    hk_events_service = module.params["hk_events_service"]
    hk_events_internal = module.params["hk_events_internal"]
    hk_events_discovery = module.params["hk_events_discovery"]
    hk_events_autoreg = module.params["hk_events_autoreg"]
    hk_services_mode = module.params["hk_services_mode"]
    hk_services = module.params["hk_services"]
    hk_audit_mode = module.params["hk_audit_mode"]
    hk_audit = module.params["hk_audit"]
    hk_sessions_mode = module.params["hk_sessions_mode"]
    hk_sessions = module.params["hk_sessions"]
    hk_history_mode = module.params["hk_history_mode"]
    hk_history_global = module.params["hk_history_global"]
    hk_history = module.params["hk_history"]
    hk_trends_mode = module.params["hk_trends_mode"]
    hk_trends_global = module.params["hk_trends_global"]
    hk_trends = module.params["hk_trends"]
    compression_status = module.params["compression_status"]
    compress_older = module.params["compress_older"]

    housekeeping = Housekeeping(module)

    current_housekeeping = housekeeping.get_housekeeping()
    housekeeping.update_housekeeping(
        current_housekeeping,
        hk_events_mode,
        hk_events_trigger,
        hk_events_service,
        hk_events_internal,
        hk_events_discovery,
        hk_events_autoreg,
        hk_services_mode,
        hk_services,
        hk_audit_mode,
        hk_audit,
        hk_sessions_mode,
        hk_sessions,
        hk_history_mode,
        hk_history_global,
        hk_history,
        hk_trends_mode,
        hk_trends_global,
        hk_trends,
        compression_status,
        compress_older
    )


if __name__ == "__main__":
    main()
