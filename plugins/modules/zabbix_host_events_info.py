#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) stephane.travassac@fr.clara.net
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

RETURN = """
---
triggers_ok:
    description: Host Zabbix Triggers in OK state
    returned: On success
    type: complex
    contains:
          comments:
            description: Additional description of the trigger
            type: str
          description:
            description: Name of the trigger
            type: str
          error:
            description: Error text if there have been any problems when updating the state of the trigger
            type: str
          expression:
            description: Reduced trigger expression
            type: str
          flags:
            description: Origin of the trigger
            type: int
          lastchange:
            description: Time when the trigger last changed its state (timestamp)
            type: int
          priority:
            description: Severity of the trigger
            type: int
          state:
            description: State of the trigger
            type: int
          status:
            description: Whether the trigger is enabled or disabled
            type: int
          templateid:
            description: ID of the parent template trigger
            type: int
          triggerid:
            description: ID of the trigger
            type: int
          type:
            description: Whether the trigger can generate multiple problem events
            type: int
          url:
            description: URL associated with the trigger
            type: str
          value:
            description: Whether the trigger is in OK or problem state
            type: int
triggers_problem:
    description: Host Zabbix Triggers in problem state. See trigger and event objects in API documentation of your zabbix version for more
    returned: On success
    type: complex
    contains:
          comments:
            description: Additional description of the trigger
            type: str
          description:
            description: Name of the trigger
            type: str
          error:
            description: Error text if there have been any problems when updating the state of the trigger
            type: str
          expression:
            description: Reduced trigger expression
            type: str
          flags:
            description: Origin of the trigger
            type: int
          last_event:
            description: last event informations
            type: complex
            contains:
                acknowledged:
                    description: If set to true return only acknowledged events
                    type: int
                acknowledges:
                    description: acknowledges informations
                    type: complex
                    contains:
                        alias:
                            description: Account who acknowledge
                            type: str
                        clock:
                            description: Time when the event was created (timestamp)
                            type: int
                        message:
                            description: Text of the acknowledgement message
                            type: str
                clock:
                    description: Time when the event was created (timestamp)
                    type: int
                eventid:
                    description: ID of the event
                    type: int
                tags:
                    description: List of tags
                    type: list
                value:
                    description: State of the related object
                    type: int
          lastchange:
            description: Time when the trigger last changed its state (timestamp)
            type: int
          priority:
            description: Severity of the trigger
            type: int
          state:
            description: State of the trigger
            type: int
          status:
            description: Whether the trigger is enabled or disabled
            type: int
          templateid:
            description: ID of the parent template trigger
            type: int
          triggerid:
            description: ID of the trigger
            type: int
          type:
            description: Whether the trigger can generate multiple problem events
            type: int
          url:
            description: URL associated with the trigger
            type: str
          value:
            description: Whether the trigger is in OK or problem state
            type: int
"""

DOCUMENTATION = """
---
module: zabbix_host_events_info
short_description: Get all triggers about a Zabbix host
description:
   - This module allows you to see if a Zabbix host have no active alert to make actions on it.
     For this case use module Ansible "fail" to exclude host in trouble.
   - Length of "triggers_ok" allow if template's triggers exist for Zabbix Host
author:
    - "Stéphane Travassac (@stravassac)"
requirements:
    - "python >= 3.9"
options:
    host_identifier:
        description:
            - Identifier of Zabbix Host
        required: true
        type: str
    host_id_type:
        description:
            - Type of host_identifier
        choices:
            - hostname
            - visible_name
            - hostid
        required: false
        default: hostname
        type: str
    trigger_severity:
        description:
            - Zabbix severity for search filter
        default: average
        required: false
        choices:
            - not_classified
            - information
            - warning
            - average
            - high
            - disaster
        type: str
    tags:
        description:
            - list of tags to filter by
        required: false
        type: list
        elements: dict
        suboptions:
          tag:
            description:
                - the tag name
            required: true
            type: str
          value:
            description:
                - the tag value
            required: true
            type: str
          operator:
            description:
                - how to match tags
            required: true
            type: str
            choices:
                - like
                - equal
                - not_like
                - not_equal
                - exists
                - not_exists

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

- name: exclude machine if alert active on it
  # set task level variables as we change ansible_connection plugin here
  vars:
      ansible_network_os: community.zabbix.zabbix
      ansible_connection: httpapi
      ansible_httpapi_port: 443
      ansible_httpapi_use_ssl: true
      ansible_httpapi_validate_certs: false
      ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
      ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_host_events_info:
      host_identifier: "{{inventory_hostname}}"
      host_id_type: "hostname"
  register: zbx_host
  delegate_to: localhost
- fail:
    msg: "machine alert in zabbix"
  when: zbx_host["triggers_problem"]|length > 0


- name: filter events for host based on tag
  # set task level variables as we change ansible_connection plugin here
  vars:
      ansible_network_os: community.zabbix.zabbix
      ansible_connection: httpapi
      ansible_httpapi_port: 443
      ansible_httpapi_use_ssl: true
      ansible_httpapi_validate_certs: false
      ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
      ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_host_events_info:
      host_identifier: "{{inventory_hostname}}"
      host_id_type: "hostname"
      tags:
        - tag: ExampleTag
          value: ExampleValue
          operator: equal
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils
from ansible.module_utils.compat.version import LooseVersion


class Host(ZabbixBase):
    def get_host(self, host_identifier, host_inventory, search_key):
        """ Get host by hostname|visible_name|hostid """
        host = self._zapi.host.get(
            {"output": "extend", "selectParentTemplates": ["name"], "filter": {search_key: host_identifier},
             "selectInventory": host_inventory})
        if len(host) < 1:
            self._module.fail_json(msg="Host not found: %s" % host_identifier)
        else:
            return host[0]

    def get_triggers_by_host_id_in_problem_state(self, host_id, trigger_severity, tags=None):
        """ Get triggers in problem state from a hostid"""
        output = "extend"
        if tags:
            triggers_list = self._zapi.trigger.get({"output": output, "hostids": host_id,
                                                    "min_severity": trigger_severity, "tags": tags})
        else:
            triggers_list = self._zapi.trigger.get({"output": output, "hostids": host_id,
                                                    "min_severity": trigger_severity})
        return triggers_list

    def get_last_event_by_trigger_id(self, triggers_id):
        """ Get the last event from triggerid"""
        output = ["eventid", "clock", "acknowledged", "value"]
        parameters = {"output": output, "objectids": triggers_id, "selectAcknowledges": "extend",
                      "selectTags": "extend", "limit": 1, "sortfield": "clock", "sortorder": "DESC"}
        if LooseVersion(self._zbx_api_version) < LooseVersion("7.0"):
            parameters["select_acknowledges"] = parameters["selectAcknowledges"]
            del parameters["selectAcknowledges"]
        event = self._zapi.event.get(parameters)
        return event[0]


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        host_identifier=dict(type="str", required=True),
        host_id_type=dict(
            default="hostname",
            type="str",
            choices=["hostname", "visible_name", "hostid"]),
        trigger_severity=dict(
            type="str",
            required=False,
            default="average",
            choices=["not_classified", "information", "warning", "average", "high", "disaster"]),
        tags=dict(
            type="list",
            required=False,
            elements="dict"),
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    trigger_severity_map = {"not_classified": 0, "information": 1, "warning": 2, "average": 3, "high": 4, "disaster": 5}
    tags_operator_map = {"like": 0, "equal": 1, "not_like": 2, "not_equal": 3, "exists": 4, "not_exists": 5}
    host_id = module.params["host_identifier"]
    host_id_type = module.params["host_id_type"]
    trigger_severity = trigger_severity_map[module.params["trigger_severity"]]
    tags = module.params["tags"]

    host_inventory = "hostid"

    host = Host(module)

    if host_id_type == "hostname":
        zabbix_host = host.get_host(host_id, host_inventory, "host")
        host_id = zabbix_host["hostid"]

    elif host_id_type == "visible_name":
        zabbix_host = host.get_host(host_id, host_inventory, "name")
        host_id = zabbix_host["hostid"]

    elif host_id_type == "hostid":
        # check hostid exist
        zabbix_host = host.get_host(host_id, host_inventory, "hostid")

    if tags:
        for tag in tags:
            tag["operator"] = tags_operator_map[tag["operator"]]

    triggers = host.get_triggers_by_host_id_in_problem_state(host_id, trigger_severity, tags)

    triggers_ok = []
    triggers_problem = []
    for trigger in triggers:
        # tGet last event for trigger with problem value = 1
        # https://www.zabbix.com/documentation/3.4/manual/api/reference/trigger/object
        if int(trigger["value"]) == 1:
            event = host.get_last_event_by_trigger_id(trigger["triggerid"])
            trigger["last_event"] = event
            triggers_problem.append(trigger)
        else:
            triggers_ok.append(trigger)

    module.exit_json(ok=True, triggers_ok=triggers_ok, triggers_problem=triggers_problem)


if __name__ == "__main__":
    main()
