#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, ONODERA Masaru <masaru-onodera@ieee.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: zabbix_settings

short_description: Update Zabbix global settings.

description:
    - This module allows you to update Zabbix global settings.

author:
    - ONODERA Masaru(@masa-orca)

requirements:
    - "python >= 3.9"

version_added: 2.1.0

options:
    default_lang:
        description:
            - Default language for users.
        required: false
        type: str
    default_timezone:
        description:
            - Default time zone for users.
            - Please set C(system) if you want to use system time zone.
        required: false
        type: str
    default_theme:
        description:
            - Default theme for users.
        required: false
        type: str
        choices:
            - blue-theme
            - dark-theme
            - hc-light
            - hc-dark
    search_limit:
        description:
            - A number of search and filter results limit.
        required: false
        type: int
    max_overview_table_size:
        description:
            - Max number of columns and rows in overview tables
        required: false
        type: int
    max_in_table:
        description:
            - Max count of elements to show inside table cell
        required: false
        type: int
    server_check_interval:
        description:
            - The Zabbix shows "Zabbix server is down" warning if C(true).
        required: false
        type: bool
    work_period:
        description:
            - Working time setting.
            - U(https://www.zabbix.com/documentation/current/en/manual/appendix/time_period)
        required: false
        type: str
    show_technical_errors:
        description:
            - The Zabbix shows PHP and SQL technical errors to users who are non-Super admin or belong to user groups with debug mode not enabled if C(true).
        required: false
        type: bool
    history_period:
        description:
            - Max period of displaying history data.
            - Accepts seconds and time unit with suffix (e.g. 24h).
        required: false
        type: str
    period_default:
        description:
            - Default period value for time filter.
            - Accepts seconds and time unit with suffix (e.g. 1h).
        required: false
        type: str
    max_period:
        description:
            - Max period for time filter.
            - Accepts seconds and time unit with suffix (e.g. 1y).
        required: false
        type: str
    severity_color_0:
        description:
            - A custom color for not classified severity.
            - Please set hexadecimal color code (e.g. 00FF00).
        required: false
        type: str
    severity_color_1:
        description:
            - A custom color for information severity.
            - Please set hexadecimal color code (e.g. 00FF00).
        required: false
        type: str
    severity_color_2:
        description:
            - A custom color for warning severity.
            - Please set hexadecimal color code (e.g. 00FF00).
        required: false
        type: str
    severity_color_3:
        description:
            - A custom color for average severity.
            - Please set hexadecimal color code (e.g. 00FF00).
        required: false
        type: str
    severity_color_4:
        description:
            - A custom color for high severity.
            - Please set hexadecimal color code (e.g. 00FF00).
        required: false
        type: str
    severity_color_5:
        description:
            - A custom color for disaster severity.
            - Please set hexadecimal color code (e.g. 00FF00).
        required: false
        type: str
    severity_name_0:
        description:
            - A custom name for not classified severity.
        required: false
        type: str
    severity_name_1:
        description:
            - A custom name for information severity.
        required: false
        type: str
    severity_name_2:
        description:
            - A custom name for warning severity.
        required: false
        type: str
    severity_name_3:
        description:
            - A custom name for average severity.
        required: false
        type: str
    severity_name_4:
        description:
            - A custom name for high severity.
        required: false
        type: str
    severity_name_5:
        description:
            - A custom name for disaster severity.
        required: false
        type: str
    custom_color:
        description:
            - Custom event color settings will be activated if C(true).
        required: false
        type: bool
    ok_period:
        description:
            - A time of period for displaying OK triggers.
            - Accepts seconds and time unit with suffix (e.g. 5m).
        required: false
        type: str
    blink_period:
        description:
            - A time of period for blinking status changed triggers.
            - Accepts seconds and time unit with suffix (e.g. 5m).
        required: false
        type: str
    problem_unack_color:
        description:
            - A custom color for unacknowledged PROBLEM events.
            - This setting will be activated if I(custom_color=true).
            - Please set hexadecimal color code (e.g. 00FF00).
        required: false
        type: str
    problem_ack_color:
        description:
            - A custom color for acknowledged PROBLEM events.
            - This setting will be activated if I(custom_color=true).
            - Please set hexadecimal color code (e.g. 00FF00).
        required: false
        type: str
    ok_unack_color:
        description:
            - A custom color for unacknowledged RESOLVED events.
            - This setting will be activated if I(custom_color=true).
            - Please set hexadecimal color code (e.g. 00FF00).
        required: false
        type: str
    ok_ack_color:
        description:
            - A custom color for acknowledged RESOLVED events.
            - This setting will be activated if I(custom_color=true).
            - Please set hexadecimal color code (e.g. 00FF00).
        required: false
        type: str
    problem_unack_style:
        description:
            - Unacknowledged PROBLEM events blink if C(true).
        required: false
        type: bool
    problem_ack_style:
        description:
            - Acknowledged PROBLEM events blink if C(true).
        required: false
        type: bool
    ok_unack_style:
        description:
            - Unacknowledged RESOLVED events blink if C(true).
        required: false
        type: bool
    ok_ack_style:
        description:
            - Acknowledged RESOLVED events blink if C(true).
        required: false
        type: bool
    frontend_url:
        description:
            - A URL of frontend.
            - This parameter is used for url parameter of settings API.
        required: false
        type: str
    discovery_group:
        description:
            - A hostgroup which discovered hosts will belong to.
        required: false
        type: str
    default_inventory_mode:
        description:
            - A default value for host inventory mode.
        required: false
        type: str
        choices:
            - disabled
            - manual
            - automatic
    alert_usrgrp:
        description:
            - A name of user group which user belongs to receive an alerm message when database down.
        required: false
        type: str
    snmptrap_logging:
        description:
            - Logging unmatched SNMP traps will be ebabled if C(true).
        required: false
        type: bool
    login_attempts:
        description:
            - A number of login attempts you can try with non blocked.
        required: false
        type: int
    login_block:
        description:
            - A time of interval to reset login attempts when the user is blocked.
            - Accepts seconds and time unit with suffix (e.g. 5m).
        required: false
        type: str
    validate_uri_schemes:
        description:
            - Validate URI schemes if C(true).
        required: false
        type: bool
    uri_valid_schemes:
        description:
            - A list of valid URI scheme.
        required: false
        type: list
        elements: str
    x_frame_options:
        description:
            - A text of X-Frame-Options of HTTP header.
        required: false
        type: str
    iframe_sandboxing_enabled:
        description:
            - The Zabbix uses iframe sandboxing if C(true).
        required: false
        type: bool
    iframe_sandboxing_exceptions:
        description:
            - A text of iframe sandboxing exceptions.
        required: false
        type: str
    connect_timeout:
        description:
            - A time of connection timeout with Zabbix server.
        required: false
        type: str
    socket_timeout:
        description:
            - A time of network default timeout.
        required: false
        type: str
    media_type_test_timeout:
        description:
            - A time of network timeout for media type test.
        required: false
        type: str
    item_test_timeout:
        description:
            - A time of network timeout for item tests.
        required: false
        type: str
    script_timeout:
        description:
            - A time of network timeout for script execution.
        required: false
        type: str
    report_test_timeout:
        description:
            - A time of network timeout for scheduled report test.
        required: false
        type: str
    auditlog_enabled:
        description:
            - Enable audit logging if C(true).
        required: false
        type: bool
    geomaps_tile_provider:
        description:
            - A provider of Geomap tile.
            - Please set C(another) if you want use non default provider
        required: false
        type: str
        choices:
            - OpenStreetMap.Mapnik
            - OpenTopoMap
            - Stamen.TonerLite
            - Stamen.Terrain
            - USGS.USTopo
            - USGS.USImagery
            - another
    geomaps_tile_url:
        description:
            - A URL of geomap tile.
        required: false
        type: str
    geomaps_max_zoom:
        description:
            - Max zoom level of geomap.
        required: false
        type: str
    geomaps_attribution:
        description:
            - A text of Geomap attribution.
        required: false
        type: str
    vault_provider:
        description:
            - A name of vault provider.
            - This parameter is available since Zabbix 6.2.
        required: false
        type: str
        choices:
            - HashiCorp_Vault
            - CyberArk_Vault

notes:
    - This module manages settings related with settings api except ha_failover_delay.

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

- name: Update settings
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_settings:
    alert_usrgrp: "0"
    auditlog_enabled: false
    blink_period: "10m"
    connect_timeout: "30s"
    custom_color: false
    default_inventory_mode: automatic
"""

RETURN = """
msg:
    description: The result of the operation
    returned: success
    type: str
    sample: "Successfully update global settings"
"""

import re

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
from ansible.module_utils.compat.version import LooseVersion
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class Settings(ZabbixBase):
    # get setting setting
    def get_settings(self):
        try:
            return self._zapi.settings.get({"output": "extend"})
        except Exception as e:
            self._module.fail_json(msg="Failed to get settings: %s" % e)

    def _is_time(self, time):
        pattern = re.compile(r"^(\d+)([smhdwMy]?)$")
        search_result = pattern.search(time)
        if search_result is None:
            self._module.fail_json(msg="{0} is invalid value.".format(time))
        return True

    def _is_color(self, color):
        pattern = re.compile(r"^[0-9a-fA-F]{6}$")
        search_result = pattern.search(color)
        if search_result is None:
            self._module.fail_json(msg="{0} is invalid value.".format(color))
        return True

    def get_usrgrpid_from_name(self, usrgrp):
        usrgrpids = self._zapi.usergroup.get({"filter": {"name": usrgrp}})
        if not usrgrpids or len(usrgrpids) > 1:
            self._module.fail_json("User group '%s' cannot be found" % usrgrp)
        return usrgrpids[0]["usrgrpid"]

    def get_groupid_from_name(self, hostgroup):
        groupid = self._zapi.hostgroup.get({"filter": {"name": hostgroup}})
        if not groupid or len(groupid) > 1:
            self._module.fail_json("Host group '%s' cannot be found" % hostgroup)
        return groupid[0]["groupid"]

    def update_settings(
        self,
        current_settings,
        default_lang,
        default_timezone,
        default_theme,
        search_limit,
        max_overview_table_size,
        max_in_table,
        server_check_interval,
        work_period,
        show_technical_errors,
        history_period,
        period_default,
        max_period,
        severity_color_0,
        severity_color_1,
        severity_color_2,
        severity_color_3,
        severity_color_4,
        severity_color_5,
        severity_name_0,
        severity_name_1,
        severity_name_2,
        severity_name_3,
        severity_name_4,
        severity_name_5,
        custom_color,
        ok_period,
        blink_period,
        problem_unack_color,
        problem_ack_color,
        ok_unack_color,
        ok_ack_color,
        problem_unack_style,
        problem_ack_style,
        ok_unack_style,
        ok_ack_style,
        frontend_url,
        discovery_group,
        default_inventory_mode,
        alert_usrgrp,
        snmptrap_logging,
        login_attempts,
        login_block,
        validate_uri_schemes,
        uri_valid_schemes,
        x_frame_options,
        iframe_sandboxing_enabled,
        iframe_sandboxing_exceptions,
        connect_timeout,
        socket_timeout,
        media_type_test_timeout,
        item_test_timeout,
        script_timeout,
        report_test_timeout,
        auditlog_enabled,
        geomaps_tile_provider,
        geomaps_tile_url,
        geomaps_max_zoom,
        geomaps_attribution,
        vault_provider,
    ):
        try:
            params = {}

            if isinstance(default_lang, str):
                if default_lang != current_settings["default_lang"]:
                    params["default_lang"] = default_lang

            if isinstance(default_timezone, str):
                if default_timezone != current_settings["default_timezone"]:
                    params["default_timezone"] = default_timezone

            if isinstance(default_theme, str):
                if default_theme != current_settings["default_theme"]:
                    params["default_theme"] = default_theme

            if isinstance(search_limit, int):
                if str(search_limit) != current_settings["search_limit"]:
                    params["search_limit"] = str(search_limit)

            if isinstance(max_overview_table_size, int):
                if (
                    str(max_overview_table_size)
                    != current_settings["max_overview_table_size"]
                ):
                    params["max_overview_table_size"] = str(max_overview_table_size)

            if isinstance(max_in_table, int):
                if str(max_in_table) != current_settings["max_in_table"]:
                    params["max_in_table"] = str(max_in_table)

            if isinstance(server_check_interval, bool):
                if server_check_interval:
                    if current_settings["server_check_interval"] != "10":
                        params["server_check_interval"] = "10"
                else:
                    if current_settings["server_check_interval"] != "0":
                        params["server_check_interval"] = "0"

            if isinstance(work_period, str):
                if work_period != current_settings["work_period"]:
                    params["work_period"] = work_period

            if isinstance(show_technical_errors, bool):
                if show_technical_errors:
                    if current_settings["show_technical_errors"] != "1":
                        params["show_technical_errors"] = "1"
                else:
                    if current_settings["show_technical_errors"] != "0":
                        params["show_technical_errors"] = "0"

            if isinstance(history_period, str):
                if self._is_time(history_period):
                    if history_period != current_settings["history_period"]:
                        params["history_period"] = history_period

            if isinstance(period_default, str):
                if self._is_time(period_default):
                    if period_default != current_settings["period_default"]:
                        params["period_default"] = period_default

            if isinstance(max_period, str):
                if self._is_time(max_period):
                    if max_period != current_settings["max_period"]:
                        params["max_period"] = max_period

            if isinstance(severity_color_0, str):
                if self._is_color(severity_color_0):
                    if severity_color_0 != current_settings["severity_color_0"]:
                        params["severity_color_0"] = severity_color_0

            if isinstance(severity_color_1, str):
                if self._is_color(severity_color_1):
                    if severity_color_1 != current_settings["severity_color_1"]:
                        params["severity_color_1"] = severity_color_1

            if isinstance(severity_color_2, str):
                if self._is_color(severity_color_2):
                    if severity_color_2 != current_settings["severity_color_2"]:
                        params["severity_color_2"] = severity_color_2

            if isinstance(severity_color_3, str):
                if self._is_color(severity_color_3):
                    if severity_color_3 != current_settings["severity_color_3"]:
                        params["severity_color_3"] = severity_color_3

            if isinstance(severity_color_4, str):
                if self._is_color(severity_color_4):
                    if severity_color_4 != current_settings["severity_color_4"]:
                        params["severity_color_4"] = severity_color_4

            if isinstance(severity_color_5, str):
                if self._is_color(severity_color_5):
                    if severity_color_5 != current_settings["severity_color_5"]:
                        params["severity_color_5"] = severity_color_5

            if isinstance(severity_name_0, str):
                if severity_name_0 != current_settings["severity_name_0"]:
                    params["severity_name_0"] = severity_name_0

            if isinstance(severity_name_1, str):
                if severity_name_1 != current_settings["severity_name_1"]:
                    params["severity_name_1"] = severity_name_1

            if isinstance(severity_name_2, str):
                if severity_name_2 != current_settings["severity_name_2"]:
                    params["severity_name_2"] = severity_name_2

            if isinstance(severity_name_3, str):
                if severity_name_3 != current_settings["severity_name_3"]:
                    params["severity_name_3"] = severity_name_3

            if isinstance(severity_name_4, str):
                if severity_name_4 != current_settings["severity_name_4"]:
                    params["severity_name_4"] = severity_name_4

            if isinstance(severity_name_5, str):
                if severity_name_5 != current_settings["severity_name_5"]:
                    params["severity_name_5"] = severity_name_5

            if isinstance(custom_color, bool):
                if custom_color:
                    if current_settings["custom_color"] != "1":
                        params["custom_color"] = "1"
                else:
                    if current_settings["custom_color"] != "0":
                        params["custom_color"] = "0"

            if isinstance(ok_period, str):
                if self._is_time(ok_period):
                    if ok_period != current_settings["ok_period"]:
                        params["ok_period"] = ok_period

            if isinstance(blink_period, str):
                if self._is_time(blink_period):
                    if blink_period != current_settings["blink_period"]:
                        params["blink_period"] = blink_period

            if isinstance(problem_unack_color, str):
                if self._is_color(problem_unack_color):
                    if problem_unack_color != current_settings["problem_unack_color"]:
                        params["problem_unack_color"] = problem_unack_color

            if isinstance(problem_ack_color, str):
                if self._is_color(problem_ack_color):
                    if problem_ack_color != current_settings["problem_ack_color"]:
                        params["problem_ack_color"] = problem_ack_color

            if isinstance(ok_unack_color, str):
                if self._is_color(ok_unack_color):
                    if ok_unack_color != current_settings["ok_unack_color"]:
                        params["ok_unack_color"] = ok_unack_color

            if isinstance(ok_ack_color, str):
                if self._is_color(ok_ack_color):
                    if ok_ack_color != current_settings["ok_ack_color"]:
                        params["ok_ack_color"] = ok_ack_color

            if isinstance(problem_unack_style, bool):
                if problem_unack_style:
                    if current_settings["problem_unack_style"] != "1":
                        params["problem_unack_style"] = "1"
                else:
                    if current_settings["problem_unack_style"] != "0":
                        params["problem_unack_style"] = "0"

            if isinstance(problem_ack_style, bool):
                if problem_ack_style:
                    if current_settings["problem_ack_style"] != "1":
                        params["problem_ack_style"] = "1"
                else:
                    if current_settings["problem_ack_style"] != "0":
                        params["problem_ack_style"] = "0"

            if isinstance(ok_unack_style, bool):
                if ok_unack_style:
                    if current_settings["ok_unack_style"] != "1":
                        params["ok_unack_style"] = "1"
                else:
                    if current_settings["ok_unack_style"] != "0":
                        params["ok_unack_style"] = "0"

            if isinstance(ok_ack_style, bool):
                if ok_ack_style:
                    if current_settings["ok_ack_style"] != "1":
                        params["ok_ack_style"] = "1"
                else:
                    if current_settings["ok_ack_style"] != "0":
                        params["ok_ack_style"] = "0"

            if isinstance(frontend_url, str):
                if frontend_url != current_settings["url"]:
                    params["url"] = frontend_url

            if isinstance(discovery_group, str):
                discovery_groupid = self.get_groupid_from_name(discovery_group)
                if current_settings["discovery_groupid"] != discovery_groupid:
                    params["discovery_groupid"] = discovery_groupid

            if isinstance(default_inventory_mode, str):
                _default_inventory_mode = str(
                    zabbix_utils.helper_to_numeric_value(
                        ["disabled", "manual", "automatic"], default_inventory_mode
                    )
                    - 1
                )
                if (
                    _default_inventory_mode
                    != current_settings["default_inventory_mode"]
                ):
                    params["default_inventory_mode"] = _default_inventory_mode

            if isinstance(alert_usrgrp, str):
                if alert_usrgrp != "0":
                    alert_usrgrpid = self.get_usrgrpid_from_name(alert_usrgrp)
                else:
                    alert_usrgrpid = alert_usrgrp
                if current_settings["alert_usrgrpid"] != alert_usrgrpid:
                    params["alert_usrgrpid"] = alert_usrgrpid

            if isinstance(snmptrap_logging, bool):
                if snmptrap_logging:
                    if current_settings["snmptrap_logging"] != "1":
                        params["snmptrap_logging"] = "1"
                else:
                    if current_settings["snmptrap_logging"] != "0":
                        params["snmptrap_logging"] = "0"

            if isinstance(login_attempts, int):
                if str(login_attempts) != current_settings["login_attempts"]:
                    params["login_attempts"] = str(login_attempts)

            if isinstance(login_block, str):
                if self._is_time(login_block):
                    if login_block != current_settings["login_block"]:
                        params["login_block"] = login_block

            if isinstance(validate_uri_schemes, bool):
                if validate_uri_schemes:
                    if current_settings["validate_uri_schemes"] != "1":
                        params["validate_uri_schemes"] = "1"
                else:
                    if current_settings["validate_uri_schemes"] != "0":
                        params["validate_uri_schemes"] = "0"

            if isinstance(uri_valid_schemes, list):
                current_uri_valid_schemes = current_settings["uri_valid_schemes"].split(
                    ","
                )
                uri_valid_schemes.sort()
                current_uri_valid_schemes.sort()
                compare_result = []
                zabbix_utils.helper_compare_lists(
                    uri_valid_schemes, current_uri_valid_schemes, compare_result
                )
                if len(compare_result) != 0:
                    params["uri_valid_schemes"] = ",".join(uri_valid_schemes)

            if isinstance(x_frame_options, str):
                if x_frame_options != current_settings["x_frame_options"]:
                    params["x_frame_options"] = x_frame_options

            if isinstance(iframe_sandboxing_enabled, bool):
                if iframe_sandboxing_enabled:
                    if current_settings["iframe_sandboxing_enabled"] != "1":
                        params["iframe_sandboxing_enabled"] = "1"
                else:
                    if current_settings["iframe_sandboxing_enabled"] != "0":
                        params["iframe_sandboxing_enabled"] = "0"

            if isinstance(iframe_sandboxing_exceptions, str):
                if (
                    iframe_sandboxing_exceptions
                    != current_settings["iframe_sandboxing_exceptions"]
                ):
                    params[
                        "iframe_sandboxing_exceptions"
                    ] = iframe_sandboxing_exceptions

            if isinstance(connect_timeout, str):
                if self._is_time(connect_timeout):
                    if connect_timeout != current_settings["connect_timeout"]:
                        params["connect_timeout"] = connect_timeout

            if isinstance(socket_timeout, str):
                if self._is_time(socket_timeout):
                    if socket_timeout != current_settings["socket_timeout"]:
                        params["socket_timeout"] = socket_timeout

            if isinstance(media_type_test_timeout, str):
                if self._is_time(media_type_test_timeout):
                    if (
                        media_type_test_timeout
                        != current_settings["media_type_test_timeout"]
                    ):
                        params["media_type_test_timeout"] = media_type_test_timeout

            if isinstance(item_test_timeout, str):
                if self._is_time(item_test_timeout):
                    if item_test_timeout != current_settings["item_test_timeout"]:
                        params["item_test_timeout"] = item_test_timeout

            if isinstance(script_timeout, str):
                if self._is_time(script_timeout):
                    if script_timeout != current_settings["script_timeout"]:
                        params["script_timeout"] = script_timeout

            if isinstance(report_test_timeout, str):
                if self._is_time(report_test_timeout):
                    if report_test_timeout != current_settings["report_test_timeout"]:
                        params["report_test_timeout"] = report_test_timeout

            if isinstance(auditlog_enabled, bool):
                if auditlog_enabled:
                    if current_settings["auditlog_enabled"] != "1":
                        params["auditlog_enabled"] = "1"
                else:
                    if current_settings["auditlog_enabled"] != "0":
                        params["auditlog_enabled"] = "0"

            if isinstance(geomaps_tile_provider, str):
                _geomaps_tile_provider = geomaps_tile_provider
                if geomaps_tile_provider == "another":
                    _geomaps_tile_provider = ""
                if _geomaps_tile_provider != current_settings["geomaps_tile_provider"]:
                    params["geomaps_tile_provider"] = _geomaps_tile_provider

            if isinstance(geomaps_tile_url, str):
                if geomaps_tile_url != current_settings["geomaps_tile_url"]:
                    params["geomaps_tile_url"] = geomaps_tile_url

            if isinstance(geomaps_max_zoom, int):
                if str(geomaps_max_zoom) != current_settings["geomaps_max_zoom"]:
                    params["geomaps_max_zoom"] = str(geomaps_max_zoom)

            if isinstance(geomaps_attribution, str):
                if geomaps_attribution != current_settings["geomaps_attribution"]:
                    params["geomaps_attribution"] = geomaps_attribution

            if LooseVersion("6.2") <= LooseVersion(self._zbx_api_version):
                if isinstance(vault_provider, str):
                    _vault_provider = str(
                        zabbix_utils.helper_to_numeric_value(
                            ["HashiCorp_Vault", "CyberArk_Vault"], vault_provider
                        )
                    )
                    if _vault_provider != current_settings["vault_provider"]:
                        params["vault_provider"] = _vault_provider

            if params != {}:
                if self._module.check_mode:
                    self._module.exit_json(changed=True)
                self._zapi.settings.update(params)
                self._module.exit_json(
                    changed=True, result="Successfully updated global settings"
                )
            else:
                if self._module.check_mode:
                    self._module.exit_json(changed=False)
                self._module.exit_json(
                    changed=False, result="Settings are already up to date"
                )
        except Exception as e:
            self._module.fail_json(msg="Failed to update global settings: %s" % e)


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(
        dict(
            default_lang=dict(type="str"),
            default_timezone=dict(type="str"),
            default_theme=dict(
                type="str", choices=["blue-theme", "dark-theme", "hc-light", "hc-dark"]
            ),
            search_limit=dict(type="int"),
            max_overview_table_size=dict(type="int"),
            max_in_table=dict(type="int"),
            server_check_interval=dict(type="bool"),
            work_period=dict(type="str"),
            show_technical_errors=dict(type="bool"),
            history_period=dict(type="str"),
            period_default=dict(type="str"),
            max_period=dict(type="str"),
            severity_color_0=dict(type="str"),
            severity_color_1=dict(type="str"),
            severity_color_2=dict(type="str"),
            severity_color_3=dict(type="str"),
            severity_color_4=dict(type="str"),
            severity_color_5=dict(type="str"),
            severity_name_0=dict(type="str"),
            severity_name_1=dict(type="str"),
            severity_name_2=dict(type="str"),
            severity_name_3=dict(type="str"),
            severity_name_4=dict(type="str"),
            severity_name_5=dict(type="str"),
            custom_color=dict(type="bool"),
            ok_period=dict(type="str"),
            blink_period=dict(type="str"),
            problem_unack_color=dict(type="str"),
            problem_ack_color=dict(type="str"),
            ok_unack_color=dict(type="str"),
            ok_ack_color=dict(type="str"),
            problem_unack_style=dict(type="bool"),
            problem_ack_style=dict(type="bool"),
            ok_unack_style=dict(type="bool"),
            ok_ack_style=dict(type="bool"),
            frontend_url=dict(type="str"),
            discovery_group=dict(type="str"),
            default_inventory_mode=dict(
                type="str", choices=["disabled", "manual", "automatic"]
            ),
            alert_usrgrp=dict(type="str"),
            snmptrap_logging=dict(type="bool"),
            login_attempts=dict(type="int"),
            login_block=dict(type="str"),
            validate_uri_schemes=dict(type="bool"),
            uri_valid_schemes=dict(type="list", elements="str"),
            x_frame_options=dict(type="str"),
            iframe_sandboxing_enabled=dict(type="bool"),
            iframe_sandboxing_exceptions=dict(type="str"),
            connect_timeout=dict(type="str"),
            socket_timeout=dict(type="str"),
            media_type_test_timeout=dict(type="str"),
            item_test_timeout=dict(type="str"),
            script_timeout=dict(type="str"),
            report_test_timeout=dict(type="str"),
            auditlog_enabled=dict(type="bool"),
            geomaps_tile_provider=dict(
                type="str",
                choices=[
                    "OpenStreetMap.Mapnik",
                    "OpenTopoMap",
                    "Stamen.TonerLite",
                    "Stamen.Terrain",
                    "USGS.USTopo",
                    "USGS.USImagery",
                    "another",
                ],
            ),
            geomaps_tile_url=dict(type="str"),
            geomaps_max_zoom=dict(type="str"),
            geomaps_attribution=dict(type="str"),
            vault_provider=dict(
                type="str", choices=["HashiCorp_Vault", "CyberArk_Vault"]
            ),
        )
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=[
            [
                "geomaps_tile_provider",
                "another",
                ["geomaps_tile_url", "geomaps_max_zoom", "geomaps_attribution"],
            ],
        ],
        supports_check_mode=True,
    )

    default_lang = module.params["default_lang"]
    default_timezone = module.params["default_timezone"]
    default_theme = module.params["default_theme"]
    search_limit = module.params["search_limit"]
    max_overview_table_size = module.params["max_overview_table_size"]
    max_in_table = module.params["max_in_table"]
    server_check_interval = module.params["server_check_interval"]
    work_period = module.params["work_period"]
    show_technical_errors = module.params["show_technical_errors"]
    history_period = module.params["history_period"]
    period_default = module.params["period_default"]
    max_period = module.params["max_period"]
    severity_color_0 = module.params["severity_color_0"]
    severity_color_1 = module.params["severity_color_1"]
    severity_color_2 = module.params["severity_color_2"]
    severity_color_3 = module.params["severity_color_3"]
    severity_color_4 = module.params["severity_color_4"]
    severity_color_5 = module.params["severity_color_5"]
    severity_name_0 = module.params["severity_name_0"]
    severity_name_1 = module.params["severity_name_1"]
    severity_name_2 = module.params["severity_name_2"]
    severity_name_3 = module.params["severity_name_3"]
    severity_name_4 = module.params["severity_name_4"]
    severity_name_5 = module.params["severity_name_5"]
    custom_color = module.params["custom_color"]
    ok_period = module.params["ok_period"]
    blink_period = module.params["blink_period"]
    problem_unack_color = module.params["problem_unack_color"]
    problem_ack_color = module.params["problem_ack_color"]
    ok_unack_color = module.params["ok_unack_color"]
    ok_ack_color = module.params["ok_ack_color"]
    problem_unack_style = module.params["problem_unack_style"]
    problem_ack_style = module.params["problem_ack_style"]
    ok_unack_style = module.params["ok_unack_style"]
    ok_ack_style = module.params["ok_ack_style"]
    frontend_url = module.params["frontend_url"]
    discovery_group = module.params["discovery_group"]
    default_inventory_mode = module.params["default_inventory_mode"]
    alert_usrgrp = module.params["alert_usrgrp"]
    snmptrap_logging = module.params["snmptrap_logging"]
    login_attempts = module.params["login_attempts"]
    login_block = module.params["login_block"]
    validate_uri_schemes = module.params["validate_uri_schemes"]
    uri_valid_schemes = module.params["uri_valid_schemes"]
    x_frame_options = module.params["x_frame_options"]
    iframe_sandboxing_enabled = module.params["iframe_sandboxing_enabled"]
    iframe_sandboxing_exceptions = module.params["iframe_sandboxing_exceptions"]
    connect_timeout = module.params["connect_timeout"]
    socket_timeout = module.params["socket_timeout"]
    media_type_test_timeout = module.params["media_type_test_timeout"]
    item_test_timeout = module.params["item_test_timeout"]
    script_timeout = module.params["script_timeout"]
    report_test_timeout = module.params["report_test_timeout"]
    auditlog_enabled = module.params["auditlog_enabled"]
    geomaps_tile_provider = module.params["geomaps_tile_provider"]
    geomaps_tile_url = module.params["geomaps_tile_url"]
    geomaps_max_zoom = module.params["geomaps_max_zoom"]
    geomaps_attribution = module.params["geomaps_attribution"]
    vault_provider = module.params["vault_provider"]

    settings = Settings(module)

    current_settings = settings.get_settings()
    settings.update_settings(
        current_settings,
        default_lang,
        default_timezone,
        default_theme,
        search_limit,
        max_overview_table_size,
        max_in_table,
        server_check_interval,
        work_period,
        show_technical_errors,
        history_period,
        period_default,
        max_period,
        severity_color_0,
        severity_color_1,
        severity_color_2,
        severity_color_3,
        severity_color_4,
        severity_color_5,
        severity_name_0,
        severity_name_1,
        severity_name_2,
        severity_name_3,
        severity_name_4,
        severity_name_5,
        custom_color,
        ok_period,
        blink_period,
        problem_unack_color,
        problem_ack_color,
        ok_unack_color,
        ok_ack_color,
        problem_unack_style,
        problem_ack_style,
        ok_unack_style,
        ok_ack_style,
        frontend_url,
        discovery_group,
        default_inventory_mode,
        alert_usrgrp,
        snmptrap_logging,
        login_attempts,
        login_block,
        validate_uri_schemes,
        uri_valid_schemes,
        x_frame_options,
        iframe_sandboxing_enabled,
        iframe_sandboxing_exceptions,
        connect_timeout,
        socket_timeout,
        media_type_test_timeout,
        item_test_timeout,
        script_timeout,
        report_test_timeout,
        auditlog_enabled,
        geomaps_tile_provider,
        geomaps_tile_url,
        geomaps_max_zoom,
        geomaps_attribution,
        vault_provider,
    )


if __name__ == "__main__":
    main()
