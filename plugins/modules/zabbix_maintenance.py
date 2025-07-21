#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2013, Alexander Bulimov <lazywolf0@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
---
module: zabbix_maintenance
short_description: Create Zabbix maintenance windows
description:
    - This module will let you create Zabbix maintenance windows.
author: "Alexander Bulimov (@abulimov)"
requirements:
    - "python >= 3.9"
options:
    state:
        description:
            - Create or remove a maintenance window.
            - Maintenance window to remove is identified by name.
        default: present
        choices: [ "present", "absent" ]
        type: str
    host_names:
        description:
            - Hosts to manage maintenance window for.
            - B(Required) option when I(state=present) and I(host_groups) is not used.
        aliases: [ "host_name" ]
        type: list
        elements: str
    host_groups:
        description:
            - Host groups to manage maintenance window for.
            - B(Required) option when I(state=present) and I(host_names) is not used.
        aliases: [ "host_group" ]
        type: list
        elements: str
    append:
        description:
            - Whether to append hosts and host groups to the existing maintenance.
        type: bool
        default: false
    minutes:
        description:
            - Length of maintenance window in minutes.
            - Will default to 10 minutes if not explicitly set
            - This argument has been B(DEPRECATED) and replaced by the I(time_periods) argument and will be removed in 4.0.0
            - B(Use of this argument only allows for the creation of a single one-time maintenance window.)
        type: int
    name:
        description:
            - Unique name of maintenance window.
        required: true
        type: str
    desc:
        description:
            - Short description of maintenance window.
        aliases: [ "description" ]
        default: Created by Ansible
        type: str
    collect_data:
        description:
            - Type of maintenance. With data collection, or without.
        type: bool
        default: "yes"
    visible_name:
        description:
            - Type of zabbix host name to use for identifying hosts to include in the maintenance.
            - I(visible_name=yes) to search by visible name,  I(visible_name=no) to search by technical name.
        type: bool
        default: "yes"
    active_since:
        description:
            - Time when the maintenance becomes active.
            - The given value will be rounded down to minutes.
            - Uses `datetime.datetime.now() if not specified.
            - NOTE - This time will not update across multiple runs unless explicitly set.
        type: "str"
        default: ""
    active_till:
        description:
            - Time when the maintenance stops being active.
            - The given value will be rounded down to minutes.
            - Gets calculated from I(minutes) if not specified when using I(minutes) only.
            - When using I(time_periods) defaults to one year from I(active_since)
        type: "str"
        default: ""
    tags:
        description:
            - List of tags to assign to the hosts in maintenance.
            - Requires I(collect_data=yes).
        type: list
        elements: dict
        suboptions:
            tag:
                description:
                    - Name of the tag.
                type: str
                required: true
            value:
                description:
                    - Value of the tag.
                type: str
                default: ""
            operator:
                description:
                    - Condition operator.
                    - Possible values is
                    - 0 - Equals
                    - 2 - Contains
                type: int
                default: 2
    time_periods:
        description:
            - List scheduled outages within the maintenance period.
            - This argument replaces the I(minutes) argument.
        aliases: [ "time_period" ]
        type: list
        elements: dict
        suboptions:
            frequency:
                description:
                    - The frequency that this maintenance window will occur.
                type: str
                required: true
                choices: ['once', 'daily', 'weekly', 'monthly']
            duration:
                description:
                    - The duration of this maintenance window in minutes.
                type: int
                default: 10
            start_date:
                description:
                    - The date that the outage will occur on.
                    - for a I(frequency) of I(once) only.
                    - Uses `datetime.date.today() if not specified.
                type: str
            start_time:
                description:
                    - The time that this outage will start on.
                    - Times should be entered in the HH:MM format using a 24-hour clock
                type: str
                required: true
            every:
                description:
                    - The interval between each event.
                    - For a I(frequency) of I(daily) or I(weekly) this must be an B(integer).
                    - For example when I(frequency=daily) and I(every=2) the outage would occur every other day.
                    - For I'(frequency=monthly) with I(day_of_week) set, valid options include I(first), I(second), I(third), I(forth), I(last) (week)
                type: str
            day_of_week:
                description:
                    - The day of the week the maintenance window will occur.
                    - This argument is B(required) if I(frequency=weekly).
                    - This argument is B(required) if I(frequency=monthly) when I(day_of_month) is not set.
                type: list
                elements: str
            day_of_month:
                description:
                    - The day of the month the maintenance window will occur.
                    - This argument is B(required) if I(frequency=monthly) when I(day_of_week) is not set.
                type: int
            months:
                description:
                    - The months that the maintenance window will occur.
                    - This argument is B(required) when the I(frequency=monthly)
                aliases: [ "month" ]
                type: list
                elements: str

extends_documentation_fragment:
- community.zabbix.zabbix


notes:
    - Useful for setting hosts in maintenance mode before big update,
      and removing maintenance window after update.
    - Module creates maintenance window from now() to now() + minutes,
      so if Zabbix server's time and host's time are not synchronized,
      you will get strange results.
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

- name: Create a named maintenance window for host www1 for 90 minutes
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_maintenance:
    name: Update of www1
    host_name: www1.example.com
    state: present
    time_periods:
      - frequency: once
        duration: 90
        start_date: 2025-01-01
        start_time: 17:00

- name: Create a  maintenance window that occurs every other day for host www1 and host groups Office and Dev
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_maintenance:
    name: Update of www1
    host_name: www1.example.com
    host_groups:
      - Office
      - Dev
    state: present
    tags:
      - tag: ExampleHostsTag
      - tag: ExampleHostsTag2
        value: ExampleTagValue
      - tag: ExampleHostsTag3
        value: ExampleTagValue
        operator: 0
    time_periods:
      - frequency: daily
        start_time: 17:00
        every: 2

- name: Create a monthly (on the second Monday of the month) maintenance window for hosts www1 and db1, without data collection.
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_maintenance:
    name: update
    host_names:
      - www1.example.com
      - db1.example.com
    state: present
    collect_data: false
    time_periods:
      - frequency: monthly
        start_time: 17:00
        day_of_week: Monday
        every: second

- name: Remove maintenance window by name
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_maintenance:
    name: Test1
    state: absent

- name: Create maintenance window by date.  Window will occur on the 1st of January, April, July, and October
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_maintenance:
    name: TestDate
    state: present
    host_names:
      - host.example.org
    active_since: "1979-09-19 09:00"
    active_till: "1979-09-19 17:00"
    time_periods:
      - frequency: monthly
        months:
          - January
          - April
          - July
          - October
        day_of_month: 1
        start_time: 17:00
"""

import datetime
import time

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils
from ansible.module_utils.compat.version import LooseVersion


class MaintenanceModule(ZabbixBase):
    def create_maintenance(self, group_ids, host_ids, start_time, end_time,
                           maintenance_type, time_periods, name, desc, tags):
        parameters = {
            "groups": [{"groupid": groupid} for groupid in group_ids],
            "hosts": [{"hostid": hostid} for hostid in host_ids],
            "name": name,
            "maintenance_type": maintenance_type,
            "active_since": str(start_time),
            "active_till": str(end_time),
            "description": desc,
            "timeperiods": time_periods
        }
        if LooseVersion(self._zbx_api_version) < LooseVersion("7.0"):
            parameters["groupids"] = group_ids
            parameters["hostids"] = host_ids
            del parameters["groups"]
            del parameters["hosts"]
        if tags is not None:
            parameters["tags"] = tags
        self._zapi.maintenance.create(parameters)
        return 0, None, None

    def update_maintenance(self, maintenance_id, group_ids, host_ids,
                           start_time, end_time, maintenance_type, time_periods, desc, tags):
        parameters = {
            "maintenanceid": maintenance_id,
            "groups": [{"groupid": groupid} for groupid in group_ids],
            "hosts": [{"hostid": hostid} for hostid in host_ids],
            "maintenance_type": maintenance_type,
            "active_since": str(start_time),
            "active_till": str(end_time),
            "description": desc,
            "timeperiods": time_periods
        }
        if LooseVersion(self._zbx_api_version) < LooseVersion("7.0"):
            parameters["groupids"] = group_ids
            parameters["hostids"] = host_ids
            del parameters["groups"]
            del parameters["hosts"]
        if tags is not None:
            parameters["tags"] = tags
        self._zapi.maintenance.update(parameters)
        return 0, None, None

    def get_maintenance(self, name):
        parameters = {
            "filter": {"name": name},
            "output": "extend",
            "selectHostGroups": "extend",
            "selectHosts": "extend",
            "selectTags": "extend",
            "selectTimeperiods": "extend"
        }
        if LooseVersion(self._zbx_api_version) < LooseVersion("7.0"):
            parameters["selectGroups"] = parameters["selectHostGroups"]
            del parameters["selectHostGroups"]
        maintenances = self._zapi.maintenance.get(parameters)

        for maintenance in maintenances:
            groupids = []
            if "hostgroups" in maintenance:
                groups = maintenance["hostgroups"]
                maintenance.pop("hostgroups")
            elif "groups" in maintenance:
                groups = maintenance["groups"]

            if groups:
                for group in groups:
                    groupids.append(group["groupid"])
            maintenance["groups"] = groupids

            if "hosts" in maintenance:
                hostids = []
                for host in maintenance["hosts"]:
                    hostids.append(host["hostid"])
            maintenance["hosts"] = hostids

            timeperiods = []
            for period in maintenance["timeperiods"]:
                if period["timeperiod_type"] in ["0", "2"]:
                    for f in ["day", "dayofweek", "month"]:
                        if f in period.keys():
                            period.pop(f)
                if period["timeperiod_type"] == "0" and "every" in period.keys():
                    period.pop("every")
                timeperiods.append(period)
            maintenance["timeperiods"] = timeperiods
            return 0, maintenance, None
        return 0, None, None

    def delete_maintenance(self, maintenance_id):
        self._zapi.maintenance.delete([maintenance_id])
        return 0, None, None

    def get_group_ids(self, host_groups):
        group_ids = []
        for group in host_groups:
            result = self._zapi.hostgroup.get(
                {
                    "output": "extend",
                    "filter":
                    {
                        "name": group
                    }
                }
            )

            if not result:
                return 1, None, "Group id for group %s not found" % group

            group_ids.append(result[0]["groupid"])

        return 0, group_ids, None

    def get_host_ids(self, host_names, zabbix_host):
        host_ids = []
        for host in host_names:
            result = self._zapi.host.get(
                {
                    "output": "extend",
                    "filter":
                    {
                        zabbix_host: host
                    }
                }
            )

            if not result:
                return 1, None, "Host id for host %s not found" % host

            host_ids.append(result[0]["hostid"])

        return 0, host_ids, None

    def check_maint_properties(self, maintenance, groups, hosts, start_time,
                               end_time, maintenance_type, time_periods, desc, tags):
        if sorted(groups) != sorted(maintenance["groups"]):
            return True
        if sorted(hosts) != sorted(maintenance["hosts"]):
            return True
        if str(int(start_time)) != maintenance["active_since"]:
            return True
        if str(int(end_time)) != maintenance["active_till"]:
            return True
        if str(desc) != maintenance["description"]:
            return True
        if str(maintenance_type) != maintenance["maintenance_type"]:
            return True
        if tags is not None and "tags" in maintenance:
            s1 = sorted(tags, key=lambda k: (k["tag"], k.get("value", "")))
            s2 = sorted(maintenance["tags"], key=lambda k: (k["tag"], k.get("value", "")))
            if s1 != s2:
                for item in s1:
                    comp = s2.pop(0)
                    if sorted(item.keys()) != sorted(comp.keys()):
                        return True
                    for k in item.keys():
                        if str(item[k]) != str(comp[k]):
                            return True

        if len(zabbix_utils.helper_compare_lists(time_periods, maintenance["timeperiods"], [])) > 0:
            return True


def parse_days_of_week(module, days_of_week):
    DAYS = {
        "Monday": 1,
        "Tuesday": 2,
        "Wednesday": 4,
        "Thursday": 8,
        "Friday": 16,
        "Saturday": 32,
        "Sunday": 64
    }

    if len(days_of_week) < 1:
        module.fail_json(msg="The 'days_of_week' argument must be set.")

    total = 0

    try:
        for day in days_of_week:
            total += DAYS[day]
    except KeyError:
        module.fail_json(msg=f"{day} is not a valid value for the The 'days_of_week' argument.")
    return total


def parse_week_of_month(module, every):
    EVERY = {
        "first": 1,
        "second": 2,
        "third": 3,
        "fourth": 4
    }

    if every in EVERY.keys():
        return EVERY[every]
    else:
        module.fail_json(msg="The value in 'every' is not valid")


def parse_months(module, months):
    MONTHS = {
        "January": 1,
        "February": 2,
        "March": 4,
        "April": 8,
        "May": 16,
        "June": 32,
        "July": 64,
        "August": 128,
        "September": 256,
        "October": 512,
        "November": 1024,
        "December": 2048
    }

    if months is None:
        return 4095
    elif len(months) < 1:
        module.fail_json(msg="The 'months' argument may not be an empty list.")

    total = 0

    try:
        for month in months:
            total += MONTHS[month]
    except KeyError:
        module.fail_json(msg=f"{month} is not a valid value for the the 'month' argument.")
    return total


def parse_periods(module, time_periods, start_date):
    PERIODS = {
        "once": 0,
        "daily": 2,
        "weekly": 3,
        "monthly": 4
    }
    items = []

    for period in time_periods:
        this_period = {}
        frequeny = period['frequency']
        duration = period['duration'] * 60
        start_date = period['start_date']
        start_time = period['start_time']
        every = period['every']
        day_of_week = period['day_of_week']
        day_of_month = period['day_of_month']
        months = period['months']

        NULL_FIELDS = {
            "once": {
                "day_of_month": day_of_month,
                "day_of_week": day_of_week,
                "months": months,
                "every": every
            },
            "daily": {
                "day_of_month": day_of_month,
                "day_of_week": day_of_week,
                "months": months,
                "start_date": start_date
            },
            "weekly": {
                "day_of_month": day_of_month,
                "months": months,
                "start_date": start_date
            },
            "monthly": {"start_date": start_date}
        }

        # Sanitize fields
        null_fields = NULL_FIELDS[frequeny]
        for f in null_fields.keys():
            if null_fields[f]:
                module.fail_json(msg=f"The field '{f}' may not be set for a '{frequeny}' of 'once'")

        # Parse start_date/time fields
        if frequeny == "once":
            start_date = start_date + " " + start_time
            start_date = datetime.datetime.fromisoformat(start_date)
            start_date = int(time.mktime(start_date.timetuple()))
            start_date = (start_date // 60) * 60
            this_period['start_date'] = str(start_date)
        else:
            start_time = datetime.time.fromisoformat(start_time)
            start_time = ((start_time.hour * 60) + start_time.minute) * 60
            this_period['start_time'] = str(start_time)

        # Parse Every and Day of Week
        if frequeny in ["daily", "weekly"]:
            try:
                every = int(every)
            except ValueError:
                module.fail_json(msg=f"The value '{every}' is not valid for the 'every' argument.")
            if every >= 1:
                this_period['every'] = str(every)
            else:
                module.fail_json(msg="The 'every' argument must be a posative number.")

        if frequeny == "weekly":
            day_of_week = parse_days_of_week(module, day_of_week)
            this_period["dayofweek"] = str(day_of_week)
        elif frequeny == "monthly":
            if day_of_month and day_of_week:
                module.fail_json(msg="The 'day_of_week' argument may not be used with the 'day_of_month' argument.")

            if day_of_week:
                day_of_week = parse_days_of_week(module, day_of_week)
                this_period['dayofweek'] = str(day_of_week)
                this_period['every'] = str(parse_week_of_month(module, every))
            else:
                if not 1 <= day_of_month <= 31:
                    module.fail_json(msg=f"The value '{str(day_of_month)}' in the 'day_of_month' argument is not valid.")
                else:
                    this_period['day'] = str(day_of_month)

            this_period["month"] = str(parse_months(module, months))

        this_period["timeperiod_type"] = str(PERIODS[frequeny])
        this_period["period"] = str(duration)
        items.append(this_period)
    return items


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(
        dict(
            state=dict(
                type="str",
                required=False,
                default="present",
                choices=["present", "absent"]),
            host_names=dict(
                type="list",
                required=False,
                default=None,
                aliases=["host_name"],
                elements="str"),
            minutes=dict(
                type="int",
                required=False),
            host_groups=dict(
                type="list",
                required=False,
                default=None,
                aliases=["host_group"],
                elements="str"),
            append=dict(type="bool", required=False, default=False),
            name=dict(type="str", required=True),
            desc=dict(type="str", required=False, default="Created by Ansible", aliases=["description"]),
            collect_data=dict(type="bool", required=False, default=True),
            visible_name=dict(type="bool", required=False, default=True),
            active_since=dict(type="str", required=False, default=""),
            active_till=dict(type="str", required=False, default=""),
            tags=dict(
                type="list",
                elements="dict",
                required=False,
                options=dict(
                    tag=dict(type="str", required=True),
                    operator=dict(type="int", default=2),
                    value=dict(type="str", default="")
                )
            ),
            time_periods=dict(
                type="list",
                elements="dict",
                required=False,
                aliases=['time_period'],
                options=dict(
                    frequency=dict(
                        type="str",
                        required=True,
                        choices=['once', 'daily', 'weekly', 'monthly']
                    ),
                    duration=dict(type="int", default=10),
                    start_date=dict(type="str"),
                    start_time=dict(type="str", required=True),
                    every=dict(type="str"),
                    day_of_week=dict(type="list", elements="str"),
                    day_of_month=dict(type="int"),
                    months=dict(type="list", elements="str", aliases=["month"])
                )
            )
        )
    )
    mutually_exclusive = [("minutes", "time_periods")]

    module = AnsibleModule(
        argument_spec=argument_spec,
        mutually_exclusive=mutually_exclusive,
        supports_check_mode=True
    )

    maint = MaintenanceModule(module)
    host_names = module.params["host_names"]
    host_groups = module.params["host_groups"]
    append = module.params["append"]
    state = module.params["state"]
    minutes = module.params["minutes"]
    name = module.params["name"]
    desc = module.params["desc"]
    collect_data = module.params["collect_data"]
    visible_name = module.params["visible_name"]
    active_since = module.params["active_since"]
    active_till = module.params["active_till"]
    tags = module.params["tags"]
    time_periods = module.params["time_periods"]

    # Set Default for minutes if needed
    if not time_periods:
        minutes = minutes if minutes else 10
        module.params["minutes"] = minutes

    if collect_data:
        maintenance_type = 0
    else:
        maintenance_type = 1
        if tags is not None:
            module.fail_json(msg="Tags cannot be provided for maintenance without data collection.")

    if visible_name:
        zabbix_host = "name"
    else:
        zabbix_host = "host"

    changed = False

    if state == "present":
        if not host_names and not host_groups:
            module.fail_json(
                msg="At least one host_name or host_group must be defined for each created maintenance.")

        if host_groups:
            (rc, group_ids, error) = maint.get_group_ids(host_groups)
            if rc != 0:
                module.fail_json(msg="Failed to get group_ids: %s" % error)
        else:
            group_ids = []

        if host_names:
            (rc, host_ids, error) = maint.get_host_ids(host_names, zabbix_host)
            if rc != 0:
                module.fail_json(msg="Failed to get host_ids: %s" % error)
        else:
            host_ids = []

        (rc, maintenance, error) = maint.get_maintenance(name)
        if rc != 0:
            module.fail_json(
                msg="Failed to check maintenance %s existence: %s" % (name, error))

        if maintenance:
            if active_since == "":
                start_time = maintenance['active_since']
            else:
                start_time = datetime.datetime.fromisoformat(active_since)
                start_time = int(time.mktime(start_time.timetuple()))

            if active_till == "":
                if minutes:
                    end_time = int(start_time) + (minutes * 60)
                else:
                    end_time = maintenance['active_till']
            else:
                end_time = datetime.datetime.fromisoformat(active_till)
                end_time = int(time.mktime(end_time.timetuple()))
        else:
            start_time = datetime.datetime.fromisoformat(active_since) if active_since != "" else datetime.datetime.now().replace(second=0)
            start_time = int(time.mktime(start_time.timetuple()))

            # Set End Time
            if active_till:
                end_time = datetime.datetime.fromisoformat(active_till)
                end_time = int(time.mktime(end_time.timetuple()))
            elif minutes:
                end_time = start_time + (minutes * 60)
            else:
                end_time = start_time + (60 * 60 * 24 * 365)

        # Logic for backwards compatability.  Remove with 4.0.0
        if minutes:
            if time_periods:
                module.fail_json(msg="The 'time_periods' artibute cannot be set with the 'minutes' attribute.")
            time_periods = [{
                "timeperiod_type": "0",
                "start_date": str(start_time),
                "period": str((minutes * 60))
            }]
        else:
            time_periods = parse_periods(module, time_periods, active_since)

        if maintenance:
            if append:
                group_ids = list(set(group_ids + maintenance["groups"]))
                host_ids = list(set(host_ids + maintenance["hosts"]))

            if maint.check_maint_properties(maintenance, group_ids, host_ids, start_time, end_time, maintenance_type, time_periods, desc, tags):
                if module.check_mode:
                    changed = True
                else:
                    (rc, data, error) = maint.update_maintenance(
                        maintenance["maintenanceid"], group_ids, host_ids, start_time, end_time, maintenance_type, time_periods, desc, tags)
                    if rc == 0:
                        changed = True
                    else:
                        module.fail_json(
                            msg="Failed to update maintenance: %s" % error)
        else:
            if module.check_mode:
                changed = True
            else:
                (rc, data, error) = maint.create_maintenance(
                    group_ids, host_ids, start_time, end_time, maintenance_type, time_periods, name, desc, tags)
                if rc == 0:
                    changed = True
                else:
                    module.fail_json(
                        msg="Failed to create maintenance: %s" % error)
    # Absent
    else:
        (rc, maintenance, error) = maint.get_maintenance(name)
        if rc != 0:
            module.fail_json(
                msg="Failed to check maintenance %s existence: %s" % (name, error))

        if maintenance:
            if module.check_mode:
                changed = True
            else:
                (rc, data, error) = maint.delete_maintenance(
                    maintenance["maintenanceid"])
                if rc == 0:
                    changed = True
                else:
                    module.fail_json(
                        msg="Failed to remove maintenance: %s" % error)

    module.exit_json(changed=changed)


if __name__ == "__main__":
    main()
