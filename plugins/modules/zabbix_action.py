#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: zabbix_action

short_description: Create/Delete/Update Zabbix actions


description:
    - This module allows you to create, modify and delete Zabbix actions.

author:
    - Ruben Tsirunyan (@rubentsirunyan)
    - Ruben Harutyunov (@K-DOT)

requirements:
    - "python >= 3.9"

options:
    name:
        type: str
        description:
            - Name of the action
        required: true
    event_source:
        type: str
        description:
            - Type of events that the action will handle.
            - Required when C(state=present).
        required: false
        choices: ["trigger", "discovery", "auto_registration", "internal"]
    state:
        type: str
        description:
            - State of the action.
            - On C(present), it will create an action if it does not exist or update the action if the associated data is different.
            - On C(absent), it will remove the action if it exists.
        choices: ["present", "absent"]
        default: "present"
    status:
        type: str
        description:
            - Status of the action.
        choices: ["enabled", "disabled"]
        default: "enabled"
    pause_in_maintenance:
        description:
            - Whether to pause escalation during maintenance periods or not.
            - Can be used when I(event_source=trigger).
        type: "bool"
        default: true
    notify_if_canceled:
        description:
            - Weather to notify when escalation is canceled.
            - Can be used when I(event_source=trigger).
        type: "bool"
        default: true
    esc_period:
        type: str
        description:
            - Default operation step duration. Must be greater than 60 seconds.
            - Accepts seconds, time unit with suffix and user macro since => Zabbix 3.4
            - Required when C(state=present).
        required: false
    conditions:
        type: list
        elements: dict
        description:
            - List of conditions to use for filtering results.
            - For more information about suboptions of this option please
              check out Zabbix API documentation U(https://www.zabbix.com/documentation/5.0/manual/api/reference/action/object#action_filter_condition)
        default: []
        suboptions:
            type:
                type: str
                description:
                    - Type (label) of the condition.
                    - "Possible values when I(event_source=trigger):"
                    - " - C(host_group)"
                    - " - C(host)"
                    - " - C(trigger)"
                    - " - C(trigger_name)"
                    - " - C(trigger_severity)"
                    - " - C(time_period)"
                    - " - C(host_template)"
                    - " - C(maintenance_status) known in Zabbix 4.0 and above as 'Problem is suppressed'"
                    - " - C(event_tag)"
                    - " - C(event_tag_value)"
                    - "Possible values when I(event_source=discovery):"
                    - " - C(host_IP)"
                    - " - C(discovered_service_type)"
                    - " - C(discovered_service_port)"
                    - " - C(discovery_status)"
                    - " - C(uptime_or_downtime_duration)"
                    - " - C(received_value)"
                    - " - C(discovery_rule)"
                    - " - C(discovery_check)"
                    - " - C(proxy)"
                    - " - C(discovery_object)"
                    - "Possible values when I(event_source=auto_registration):"
                    - " - C(proxy)"
                    - " - C(host_name)"
                    - " - C(host_metadata)"
                    - "Possible values when I(event_source=internal):"
                    - " - C(host_group)"
                    - " - C(host)"
                    - " - C(host_template)"
                    - " - C(event_type)"
                required: true
            value:
                type: str
                description:
                    - Value to compare with.
                    - "When I(type=discovery_status), the choices are:"
                    - " - C(up)"
                    - " - C(down)"
                    - " - C(discovered)"
                    - " - C(lost)"
                    - "When I(type=discovery_object), the choices are:"
                    - " - C(host)"
                    - " - C(service)"
                    - "When I(type=event_type), the choices are:"
                    - " - C(item in not supported state)"
                    - " - C(item in normal state)"
                    - " - C(LLD rule in not supported state)"
                    - " - C(LLD rule in normal state)"
                    - " - C(trigger in unknown state)"
                    - " - C(trigger in normal state)"
                    - "When I(type=trigger_severity), the choices are (case-insensitive):"
                    - " - C(not classified)"
                    - " - C(information)"
                    - " - C(warning)"
                    - " - C(average)"
                    - " - C(high)"
                    - " - C(disaster)"
                    - Irrespective of user-visible names being changed in Zabbix. Defaults to C(not classified) if omitted.
                    - Besides the above options, this is usually either the name
                      of the object or a string to compare with.
            value2:
                type: str
                description:
                    - Secondary value to compare with.
                    - Required for trigger actions when condition I(type=event_tag_value).
            operator:
                type: str
                description:
                    - Condition operator.
                    - When I(type) is set to C(time_period), the choices are C(in), C(not in).
                choices:
                    - "equals"
                    - "="
                    - "does not equal"
                    - "<>"
                    - "contains"
                    - "like"
                    - "does not contain"
                    - "not like"
                    - "in"
                    - "is greater than or equals"
                    - ">="
                    - "is less than or equals"
                    - "<="
                    - "not in"
                    - "matches"
                    - "does not match"
                    - "Yes"
                    - "No"
                required: true
            formulaid:
                type: str
                description:
                    - Arbitrary unique ID that is used to reference the condition from a custom expression.
                    - Can only contain upper-case letters.
                    - Required for custom expression filters and ignored otherwise.
    eval_type:
        type: str
        description:
            - Filter condition evaluation method.
            - Defaults to C(andor) if conditions are less then 2 or if
              I(formula) is not specified.
            - Defaults to C(custom_expression) when formula is specified.
        choices:
            - "andor"
            - "and"
            - "or"
            - "custom_expression"
    formula:
        type: str
        description:
            - User-defined expression to be used for evaluating conditions with a custom expression.
            - The expression must contain IDs that reference each condition by its formulaid.
            - The IDs used in the expression must exactly match the ones
              defined in the I(conditions). No condition can remain unused or omitted.
            - Required when I(eval_type=custom_expression).
            - Use sequential IDs that start at "A". If non-sequential IDs are used, Zabbix re-indexes them.
              This makes each module run notice the difference in IDs and update the action.
    operations:
        type: list
        elements: dict
        description:
            - List of action operations
        default: []
        suboptions:
            type:
                type: str
                description:
                    - Type of operation.
                    - "Valid choices when setting type for I(recovery_operations) and I(acknowledge_operations):"
                    - " - C(send_message)"
                    - " - C(remote_command)"
                    - " - C(notify_all_involved)"
                    - Choice C(notify_all_involved) only supported in I(recovery_operations) and I(acknowledge_operations).
                    - C(add_host_tags) and C(remove_host_tags) available since Zabbix 7.0.
                choices:
                    - send_message
                    - remote_command
                    - add_host
                    - remove_host
                    - add_to_host_group
                    - remove_from_host_group
                    - link_to_template
                    - unlink_from_template
                    - enable_host
                    - disable_host
                    - set_host_inventory_mode
                    - notify_all_involved
                    - add_host_tags
                    - remove_host_tags
                required: true
            esc_period:
                type: str
                description:
                    - Duration of an escalation step in seconds.
                    - Must be greater than 60 seconds.
                    - Accepts seconds, time unit with suffix and user macro.
                    - If set to 0 or 0s, the default action escalation period will be used.
                default: 0s
            esc_step_from:
                type: int
                description:
                    - Step to start escalation from.
                default: 1
            esc_step_to:
                type: int
                description:
                    - Step to end escalation at.
                    - Specify 0 for infinitely.
                default: 1
            send_to_groups:
                type: list
                elements: str
                description:
                    - User groups to send messages to.
            send_to_users:
                type: list
                elements: str
                description:
                    - Users (usernames or aliases) to send messages to.
            op_message:
                type: str
                description:
                    - Operation message text.
                    - If I(op_message) and I(subject) not defined then "default message" from media type will be used
            subject:
                type: str
                description:
                    - Operation message subject.
                    - If I(op_message) and I(subject) not defined then "default message" from media type will be used
            media_type:
                type: str
                description:
                    - Media type that will be used to send the message.
                    - Can be used with I(type=send_message) or I(type=notify_all_involved) inside I(acknowledge_operations).
                    - Set to C(all) for all media types
                default: "all"
            operation_condition:
                type: "str"
                description:
                    - The action operation condition object defines a condition that must be met to perform the current operation.
                choices:
                    - acknowledged
                    - not_acknowledged
            host_groups:
                type: list
                elements: str
                description:
                    - List of host groups host should be added to.
                    - Required when I(type=add_to_host_group) or I(type=remove_from_host_group).
            templates:
                type: list
                elements: str
                description:
                    - List of templates host should be linked to.
                    - Required when I(type=link_to_template) or I(type=unlink_from_template).
            inventory:
                type: str
                description:
                    - Host inventory mode.
                    - Required when I(type=set_host_inventory_mode).
                choices:
                    - manual
                    - automatic
            command_type:
                type: str
                description:
                    - Type of operation command.
                    - Required when I(type=remote_command).
                choices:
                    - custom_script
                    - ipmi
                    - ssh
                    - telnet
                    - global_script
            command:
                type: str
                description:
                    - Command to run.
                    - Required when I(type=remote_command) and I(command_type!=global_script).
            execute_on:
                type: str
                description:
                    - Target on which the custom script operation command will be executed.
                    - Required when I(type=remote_command) and I(command_type=custom_script).
                choices:
                    - agent
                    - server
                    - proxy
            run_on_groups:
                type: list
                elements: str
                description:
                    - Host groups to run remote commands on.
                    - Required when I(type=remote_command) and I(run_on_hosts) is not set.
            run_on_hosts:
                type: list
                elements: str
                description:
                    - Hosts to run remote commands on.
                    - Required when I(type=remote_command) and I(run_on_groups) is not set.
                    - If set to 0 the command will be run on the current host.
            ssh_auth_type:
                type: str
                description:
                    - Authentication method used for SSH commands.
                    - Required when I(type=remote_command) and I(command_type=ssh).
                choices:
                    - password
                    - public_key
            ssh_privatekey_file:
                type: str
                description:
                    - Name of the private key file used for SSH commands with public key authentication.
                    - Required when I(ssh_auth_type=public_key).
                    - Can be used when I(type=remote_command).
            ssh_publickey_file:
                type: str
                description:
                    - Name of the public key file used for SSH commands with public key authentication.
                    - Required when I(ssh_auth_type=public_key).
                    - Can be used when I(type=remote_command).
            username:
                type: str
                description:
                    - User name used for authentication.
                    - Required when I(ssh_auth_type in [public_key, password]) or I(command_type=telnet).
                    - Can be used when I(type=remote_command).
            password:
                type: str
                description:
                    - Password used for authentication.
                    - Required when I(ssh_auth_type=password) or I(command_type=telnet).
                    - Can be used when I(type=remote_command).
            port:
                type: int
                description:
                    - Port number used for authentication.
                    - Can be used when I(command_type in [ssh, telnet]) and I(type=remote_command).
            script_name:
                type: str
                description:
                    - The name of script used for global script commands.
                    - Required when I(command_type=global_script).
                    - Can be used when I(type=remote_command).
            tags:
                type: list
                elements: dict
                description:
                    - Host tags to adt have tag property defined.
                    - The value property is optional. or remove.
                    - upported if operationtype is set to C(add host tags) or C(remove host tags).
                suboptions:
                    tag:
                      type: str
                      description: Tag name
                    value:
                      type: str
                      description: Tag value (optional)
    recovery_operations:
        type: list
        elements: dict
        description:
            - List of recovery operations.
            - C(Suboptions) are the same as for I(operations).
        default: []
        suboptions:
            type:
                type: str
                description:
                    - Type of operation.
                choices:
                    - send_message
                    - remote_command
                    - notify_all_involved
                required: true
            command_type:
                type: str
                required: false
                description:
                    - Type of operation command.
                choices:
                    - custom_script
                    - ipmi
                    - ssh
                    - telnet
                    - global_script
            command:
                type: str
                required: false
                description:
                    - Command to run.
            execute_on:
                type: str
                required: false
                description:
                    - Target on which the custom script operation command will be executed.
                choices:
                    - agent
                    - server
                    - proxy
            ssh_auth_type:
                type: str
                description:
                    - Authentication method used for SSH commands.
                    - Required when I(type=remote_command) and I(command_type=ssh).
                choices:
                    - password
                    - public_key
            ssh_privatekey_file:
                type: str
                description:
                    - Name of the private key file used for SSH commands with public key authentication.
                    - Required when I(ssh_auth_type=public_key).
                    - Can be used when I(type=remote_command).
            ssh_publickey_file:
                type: str
                description:
                    - Name of the public key file used for SSH commands with public key authentication.
                    - Required when I(ssh_auth_type=public_key).
                    - Can be used when I(type=remote_command).
            run_on_groups:
                type: list
                elements: str
                description:
                    - Host groups to run remote commands on.
                    - Required when I(type=remote_command) and I(run_on_hosts) is not set.
            run_on_hosts:
                type: list
                elements: str
                description:
                    - Hosts to run remote commands on.
                    - Required when I(type=remote_command) and I(run_on_groups) is not set.
                    - If set to 0 the command will be run on the current host.
            send_to_groups:
                type: list
                elements: str
                description:
                    - User groups to send messages to.
            send_to_users:
                type: list
                elements: str
                description:
                    - Users (usernames or aliases) to send messages to.
            media_type:
                type: str
                description:
                    - Media type that will be used to send the message.
                    - Can be used with I(type=send_message) or I(type=notify_all_involved) inside I(acknowledge_operations).
                    - Set to C(all) for all media types
                default: "all"
            op_message:
                type: str
                description:
                    - Operation message text.
                    - If I(op_message) and I(subject) not defined then "default message" from media type will be used
            subject:
                type: str
                description:
                    - Operation message subject.
                    - If I(op_message) and I(subject) not defined then "default message" from media type will be used
            username:
                type: str
                description:
                    - User name used for authentication.
                    - Required when I(ssh_auth_type in [public_key, password]) or I(command_type=telnet).
                    - Can be used when I(type=remote_command).
            password:
                type: str
                description:
                    - Password used for authentication.
                    - Required when I(ssh_auth_type=password) or I(command_type=telnet).
                    - Can be used when I(type=remote_command).
            port:
                type: int
                description:
                    - Port number used for authentication.
                    - Can be used when I(command_type in [ssh, telnet]) and I(type=remote_command).
            script_name:
                type: str
                description:
                    - The name of script used for global script commands.
                    - Required when I(command_type=global_script).
                    - Can be used when I(type=remote_command).
    acknowledge_operations:
        type: list
        elements: dict
        description:
            - List of acknowledge operations.
            - Action acknowledge operations are known as update operations since Zabbix 4.0.
            - C(Suboptions) are the same as for I(operations).
        suboptions:
            type:
                type: str
                description:
                    - Type of operation.
                choices:
                    - send_message
                    - remote_command
                    - notify_all_involved
                required: true
            command_type:
                type: str
                description:
                    - Type of operation command.
                required: false
                choices:
                    - custom_script
                    - ipmi
                    - ssh
                    - telnet
                    - global_script
            execute_on:
                type: str
                required: false
                description:
                    - Target on which the custom script operation command will be executed.
                choices:
                    - agent
                    - server
                    - proxy
            command:
                type: str
                required: false
                description:
                    - Command to run.
            ssh_auth_type:
                type: str
                description:
                    - Authentication method used for SSH commands.
                    - Required when I(type=remote_command) and I(command_type=ssh).
                choices:
                    - password
                    - public_key
            ssh_privatekey_file:
                type: str
                description:
                    - Name of the private key file used for SSH commands with public key authentication.
                    - Required when I(ssh_auth_type=public_key).
                    - Can be used when I(type=remote_command).
            ssh_publickey_file:
                type: str
                description:
                    - Name of the public key file used for SSH commands with public key authentication.
                    - Required when I(ssh_auth_type=public_key).
                    - Can be used when I(type=remote_command).
            run_on_groups:
                type: list
                elements: str
                description:
                    - Host groups to run remote commands on.
                    - Required when I(type=remote_command) and I(run_on_hosts) is not set.
            run_on_hosts:
                type: list
                elements: str
                description:
                    - Hosts to run remote commands on.
                    - Required when I(type=remote_command) and I(run_on_groups) is not set.
                    - If set to 0 the command will be run on the current host.
            send_to_groups:
                type: list
                elements: str
                description:
                    - User groups to send messages to.
            send_to_users:
                type: list
                elements: str
                description:
                    - Users (usernames or aliases) to send messages to.
            media_type:
                type: str
                description:
                    - Media type that will be used to send the message.
                    - Can be used with I(type=send_message) or I(type=notify_all_involved) inside I(acknowledge_operations).
                    - Set to C(all) for all media types
                default: "all"
            op_message:
                type: str
                description:
                    - Operation message text.
                    - If I(op_message) and I(subject) not defined then "default message" from media type will be used
            subject:
                type: str
                description:
                    - Operation message subject.
                    - If I(op_message) and I(subject) not defined then "default message" from media type will be used
            username:
                type: str
                description:
                    - User name used for authentication.
                    - Required when I(ssh_auth_type in [public_key, password]) or I(command_type=telnet).
                    - Can be used when I(type=remote_command).
            password:
                type: str
                description:
                    - Password used for authentication.
                    - Required when I(ssh_auth_type=password) or I(command_type=telnet).
                    - Can be used when I(type=remote_command).
            port:
                type: int
                description:
                    - Port number used for authentication.
                    - Can be used when I(command_type in [ssh, telnet]) and I(type=remote_command).
            script_name:
                type: str
                description:
                    - The name of script used for global script commands.
                    - Required when I(command_type=global_script).
                    - Can be used when I(type=remote_command).
        aliases: [ update_operations ]
        default: []
    pause_symptoms:
        type: bool
        description:
            - Whether to pause escalation if event is a symptom event.
            - I(supported) if C(event_source) is set to C(trigger)
            - Works only with >= Zabbix 6.4
        default: true


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

# Trigger action with only one condition
- name: Deploy trigger action
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_action:
    name: "Send alerts to Admin"
    event_source: "trigger"
    state: present
    status: enabled
    esc_period: 60
    conditions:
      - type: "trigger_severity"
        operator: ">="
        value: "Information"
    operations:
      - type: send_message
        subject: "Something bad is happening"
        op_message: "Come on, guys do something"
        media_type: "Email"
        send_to_users:
          - "Admin"

# Trigger action with multiple conditions and operations
- name: Deploy trigger action
  # set task level  variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_action:
    name: "Send alerts to Admin"
    event_source: "trigger"
    state: present
    status: enabled
    esc_period: 1m
    conditions:
      - type: "trigger_name"
        operator: "like"
        value: "Zabbix agent is unreachable"
        formulaid: A
      - type: "trigger_severity"
        operator: ">="
        value: "disaster"
        formulaid: B
    formula: A or B
    operations:
      - type: send_message
        media_type: "Email"
        send_to_users:
          - "Admin"
      - type: remote_command
        command: "systemctl restart zabbix-agent"
        command_type: custom_script
        execute_on: server
        run_on_hosts:
          - 0

# Trigger action with recovery and acknowledge operations
- name: Deploy trigger action
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_action:
    name: "Send alerts to Admin"
    event_source: "trigger"
    state: present
    status: enabled
    esc_period: 1h
    conditions:
      - type: "trigger_severity"
        operator: ">="
        value: "Information"
    operations:
      - type: send_message
        subject: "Something bad is happening"
        op_message: "Come on, guys do something"
        media_type: "Email"
        send_to_users:
          - "Admin"
    recovery_operations:
      - type: send_message
        subject: "Host is down"
        op_message: "Come on, guys do something"
        media_type: "Email"
        send_to_users:
          - "Admin"
    acknowledge_operations:
      - type: send_message
        media_type: "Email"
        send_to_users:
          - "Admin"
"""

RETURN = """
msg:
    description: The result of the operation
    returned: success
    type: str
    sample: "Action Deleted: Register webservers, ID: 0001"
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
from ansible.module_utils.compat.version import LooseVersion

import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class Zapi(ZabbixBase):
    def __init__(self, module, zbx=None):
        super(Zapi, self).__init__(module, zbx)
        self._zapi_wrapper = self

    def check_if_action_exists(self, name):
        """Check if action exists.

        Args:
            name: Name of the action.

        Returns:
            The return value. True for success, False otherwise.

        """
        try:
            _params = {
                "selectOperations": "extend",
                "selectRecoveryOperations": "extend",
                "selectUpdateOperations": "extend",
                "selectFilter": "extend",
                "filter": {"name": [name]}
            }
            _action = self._zapi.action.get(_params)
            return _action
        except Exception as e:
            self._module.fail_json(msg="Failed to check if action '%s' exists: %s" % (name, e))

    def get_action_by_name(self, name):
        """Get action by name

        Args:
            name: Name of the action.

        Returns:
            dict: Zabbix action

        """
        try:
            action_list = self._zapi.action.get({
                "output": "extend",
                "filter": {"name": [name]}
            })
            if len(action_list) < 1:
                self._module.fail_json(msg="Action not found: %s" % name)
            else:
                return action_list[0]
        except Exception as e:
            self._module.fail_json(msg="Failed to get ID of '%s': %s" % (name, e))

    def get_host_by_host_name(self, host_name):
        """Get host by host name

        Args:
            host_name: host name.

        Returns:
            host matching host name

        """
        try:
            host_list = self._zapi.host.get({
                "output": "extend",
                "selectInventory": "extend",
                "filter": {"host": [host_name]}
            })
            if len(host_list) < 1:
                self._module.fail_json(msg="Host not found: %s" % host_name)
            else:
                return host_list[0]
        except Exception as e:
            self._module.fail_json(msg="Failed to get host '%s': %s" % (host_name, e))

    def get_hostgroup_by_hostgroup_name(self, hostgroup_name):
        """Get host group by host group name

        Args:
            hostgroup_name: host group name.

        Returns:
            host group matching host group name

        """
        try:
            hostgroup_list = self._zapi.hostgroup.get({
                "output": "extend",
                "filter": {"name": [hostgroup_name]}
            })
            if len(hostgroup_list) < 1:
                self._module.fail_json(msg="Host group not found: %s" % hostgroup_name)
            else:
                return hostgroup_list[0]
        except Exception as e:
            self._module.fail_json(msg="Failed to get host group '%s': %s" % (hostgroup_name, e))

    def get_template_by_template_name(self, template_name):
        """Get template by template name

        Args:
            template_name: template name.

        Returns:
            template matching template name

        """
        try:
            template_list = self._zapi.template.get({
                "output": "extend",
                "filter": {"host": [template_name]}
            })
            if len(template_list) < 1:
                self._module.fail_json(msg="Template not found: %s" % template_name)
            else:
                return template_list[0]
        except Exception as e:
            self._module.fail_json(msg="Failed to get template '%s': %s" % (template_name, e))

    def get_trigger_by_trigger_name(self, trigger_name):
        """Get trigger by trigger name

        Args:
            trigger_name: trigger name.

        Returns:
            trigger matching trigger name

        """
        try:
            trigger_list = self._zapi.trigger.get({
                "output": "extend",
                "filter": {"description": [trigger_name]}
            })
            if len(trigger_list) < 1:
                self._module.fail_json(msg="Trigger not found: %s" % trigger_name)
            else:
                return trigger_list[0]
        except Exception as e:
            self._module.fail_json(msg="Failed to get trigger '%s': %s" % (trigger_name, e))

    def get_discovery_rule_by_discovery_rule_name(self, discovery_rule_name):
        """Get discovery rule by discovery rule name

        Args:
            discovery_rule_name: discovery rule name.

        Returns:
            discovery rule matching discovery rule name

        """
        try:
            discovery_rule_list = self._zapi.drule.get({
                "output": "extend",
                "filter": {"name": [discovery_rule_name]}
            })
            if len(discovery_rule_list) < 1:
                self._module.fail_json(msg="Discovery rule not found: %s" % discovery_rule_name)
            else:
                return discovery_rule_list[0]
        except Exception as e:
            self._module.fail_json(msg="Failed to get discovery rule '%s': %s" % (discovery_rule_name, e))

    def get_discovery_check_by_discovery_check_name(self, discovery_check_name):
        """Get discovery check  by discovery check name

        Args:
            discovery_check_name: discovery check name.

        Returns:
            discovery check matching discovery check name

        """
        try:
            discovery_rule_name, dcheck_type = discovery_check_name.split(": ")
            dcheck_type_to_number = {
                "SSH": "0",
                "LDAP": "1",
                "SMTP": "2",
                "FTP": "3",
                "HTTP": "4",
                "POP": "5",
                "NNTP": "6",
                "IMAP": "7",
                "TCP": "8",
                "Zabbix agent": "9",
                "SNMPv1 agent": "10",
                "SNMPv2 agent": "11",
                "ICMP ping": "12",
                "SNMPv3 agent": "13",
                "HTTPS": "14",
                "Telnet": "15"
            }

            if dcheck_type.startswith('SNMP'):
                # Extract type correctly from Discovery rule name
                # <Discovery name>: SNMPv2 agent "<IOD>"
                dcheck_type = dcheck_type.split(" \"")[0]

            if dcheck_type not in dcheck_type_to_number:
                self._module.fail_json(msg="Discovery check type: %s does not exist" % dcheck_type)

            discovery_rule_list = self._zapi.drule.get({
                "output": ["dchecks"],
                "filter": {"name": [discovery_rule_name]},
                "selectDChecks": "extend"
            })
            if len(discovery_rule_list) < 1:
                self._module.fail_json(msg="Discovery check not found: %s" % discovery_check_name)

            for dcheck in discovery_rule_list[0]["dchecks"]:
                if dcheck_type.startswith('SNMP'):
                    if (dcheck_type_to_number[dcheck_type] == dcheck["type"]
                            and discovery_check_name.split("\"")[1] == dcheck["key_"]):
                        return dcheck
                elif dcheck_type_to_number[dcheck_type] == dcheck["type"]:
                    return dcheck
            self._module.fail_json(msg="Discovery check not found: %s" % discovery_check_name)
        except Exception as e:
            self._module.fail_json(msg="Failed to get discovery check '%s': %s" % (discovery_check_name, e))

    def get_proxy_by_proxy_name(self, proxy_name):
        """Get proxy by proxy name

        Args:
            proxy_name: proxy name.

        Returns:
            proxy matching proxy name

        """
        try:
            if LooseVersion(self._zbx_api_version) >= LooseVersion('7.0'):
                filter = {'name': [proxy_name]}
            else:
                filter = {'host': [proxy_name]}
            proxy_list = self._zapi.proxy.get({
                "output": "extend",
                "filter": filter,
            })
            if len(proxy_list) < 1:
                self._module.fail_json(msg="Proxy not found: %s" % proxy_name)
            else:
                return proxy_list[0]
        except Exception as e:
            self._module.fail_json(msg="Failed to get proxy '%s': %s" % (proxy_name, e))

    def get_mediatype_by_mediatype_name(self, mediatype_name):
        """Get mediatype by mediatype name

        Args:
            mediatype_name: mediatype name

        Returns:
            mediatype matching mediatype name

        """
        filter = {"name": [mediatype_name]}

        try:
            if str(mediatype_name).lower() == "all":
                return "0"
            mediatype_list = self._zapi.mediatype.get({
                "output": "extend",
                "filter": filter
            })
            if len(mediatype_list) < 1:
                self._module.fail_json(msg="Media type not found: %s" % mediatype_name)
            else:
                return mediatype_list[0]["mediatypeid"]
        except Exception as e:
            self._module.fail_json(msg="Failed to get mediatype '%s': %s" % (mediatype_name, e))

    def get_user_by_user_name(self, user_name):
        """Get user by user name

        Args:
            user_name: user name

        Returns:
            user matching user name

        """
        try:
            filter = {"username": [user_name]}
            user_list = self._zapi.user.get({
                "output": "extend",
                "filter": filter,
            })
            if len(user_list) < 1:
                self._module.fail_json(msg="User not found: %s" % user_name)
            else:
                return user_list[0]
        except Exception as e:
            self._module.fail_json(msg="Failed to get user '%s': %s" % (user_name, e))

    def get_usergroup_by_usergroup_name(self, usergroup_name):
        """Get usergroup by usergroup name

        Args:
            usergroup_name: usergroup name

        Returns:
            usergroup matching usergroup name

        """
        try:
            usergroup_list = self._zapi.usergroup.get({
                "output": "extend",
                "filter": {"name": [usergroup_name]}
            })
            if len(usergroup_list) < 1:
                self._module.fail_json(msg="User group not found: %s" % usergroup_name)
            else:
                return usergroup_list[0]
        except Exception as e:
            self._module.fail_json(msg="Failed to get user group '%s': %s" % (usergroup_name, e))

    # get script by script name
    def get_script_by_script_name(self, script_name):
        """Get script by script name

        Args:
            script_name: script name

        Returns:
            script matching script name

        """
        try:
            if script_name is None:
                return {}
            script_list = self._zapi.script.get({
                "output": "extend",
                "filter": {"name": [script_name]}
            })
            if len(script_list) < 1:
                self._module.fail_json(msg="Script not found: %s" % script_name)
            else:
                return script_list[0]
        except Exception as e:
            self._module.fail_json(msg="Failed to get script '%s': %s" % (script_name, e))


class Action(Zapi):
    def __init__(self, module, zbx=None):
        super(Action, self).__init__(module, zbx)
        self.existing_data = None

    def _construct_parameters(self, **kwargs):
        """Construct parameters.

        Args:
            **kwargs: Arbitrary keyword parameters.

        Returns:
            dict: dictionary of specified parameters
        """

        _params = {
            "name": kwargs["name"],
            "eventsource": zabbix_utils.helper_to_numeric_value([
                "trigger",
                "discovery",
                "auto_registration",
                "internal"], kwargs["event_source"]),
            "esc_period": kwargs.get("esc_period"),
            "filter": kwargs["conditions"],
            "operations": kwargs["operations"],
            "recovery_operations": kwargs.get("recovery_operations"),
            "acknowledge_operations": kwargs.get("acknowledge_operations"),
            "status": zabbix_utils.helper_to_numeric_value([
                "enabled",
                "disabled"], kwargs["status"])
        }

        if kwargs["event_source"] == "trigger":
            _params["pause_suppressed"] = "1" if kwargs["pause_in_maintenance"] else "0"
            if LooseVersion(self._zbx_api_version) >= LooseVersion("6.4"):
                _params["pause_symptoms"] = "1" if kwargs["pause_symptoms"] else "0"
            _params["notify_if_canceled"] = "1" if kwargs["notify_if_canceled"] else "0"

        _params["update_operations"] = kwargs.get("update_operations")
        if "update_operations" in _params and not isinstance(_params.get("update_operations", None), type(None)):
            _params.pop("acknowledge_operations", None)
        elif isinstance(_params.get("acknowledge_operations", None), list):
            _params["update_operations"] = _params.pop("acknowledge_operations", [])
        else:
            _params["update_operations"] = []
            _params.pop("acknowledge_operations", None)

        if "esc_period" in _params and isinstance(_params.get("esc_period", None), type(None)):
            _params.pop("esc_period")

        if "recovery_operations" in _params:
            if isinstance(_params.get("recovery_operations", None), type(None)) or len(_params.get("recovery_operations", [])) == 0:
                _params.pop("recovery_operations")

        if "update_operations" in _params:
            if isinstance(_params.get("update_operations", None), type(None)) or len(_params.get("update_operations", [])) == 0:
                _params.pop("update_operations")

        if _params["eventsource"] not in [0, 3]:
            _params.pop("esc_period")

        return _params

    def check_difference(self, **kwargs):
        """Check difference between action and user specified parameters.

        Args:
            **kwargs: Arbitrary keyword parameters.

        Returns:
            dict: dictionary of differences
        """
        existing_action = zabbix_utils.helper_convert_unicode_to_str(self.check_if_action_exists(kwargs["name"])[0])
        parameters = zabbix_utils.helper_convert_unicode_to_str(self._construct_parameters(**kwargs))
        change_parameters = {}
        _diff = zabbix_utils.helper_cleanup_data(zabbix_utils.helper_compare_dictionaries(parameters, existing_action, change_parameters))
        return _diff

    def update_action(self, **kwargs):
        """Update action.

        Args:
            **kwargs: Arbitrary keyword parameters.

        Returns:
            action: updated action
        """
        try:
            if self._module.check_mode:
                self._module.exit_json(msg="Action would be updated if check mode was not specified: %s" % kwargs, changed=True)
            kwargs["actionid"] = kwargs.pop("action_id")
            return self._zapi.action.update(kwargs)
        except Exception as e:
            self._module.fail_json(msg="Failed to update action '%s': %s" % (kwargs["actionid"], e))

    def add_action(self, **kwargs):
        """Add action.

        Args:
            **kwargs: Arbitrary keyword parameters.

        Returns:
            action: added action
        """
        try:
            if self._module.check_mode:
                self._module.exit_json(msg="Action would be added if check mode was not specified", changed=True)
            parameters = self._construct_parameters(**kwargs)
            action_list = self._zapi.action.create(parameters)
            return action_list["actionids"][0]
        except Exception as e:
            self._module.fail_json(msg="Failed to create action '%s': %s" % (kwargs["name"], e))

    def delete_action(self, action_id):
        """Delete action.

        Args:
            action_id: Action id

        Returns:
            action: deleted action
        """
        try:
            if self._module.check_mode:
                self._module.exit_json(msg="Action would be deleted if check mode was not specified", changed=True)
            return self._zapi.action.delete([action_id])
        except Exception as e:
            self._module.fail_json(msg="Failed to delete action '%s': %s" % (action_id, e))


class Operations(Zapi):
    def _construct_operationtype(self, operation):
        """Construct operation type.

        Args:
            operation: operation to construct

        Returns:
            str: constructed operation
        """
        try:
            return zabbix_utils.helper_to_numeric_value([
                "send_message",
                "remote_command",
                "add_host",
                "remove_host",
                "add_to_host_group",
                "remove_from_host_group",
                "link_to_template",
                "unlink_from_template",
                "enable_host",
                "disable_host",
                "set_host_inventory_mode",
                "none",
                "none",
                "add_host_tags",
                "remove_host_tags"],
                operation["type"]
            )
        except Exception:
            self._module.fail_json(msg="Unsupported value '%s' for operation type." % operation["type"])

    def _construct_opmessage(self, operation):
        """Construct operation message.

        Args:
            operation: operation to construct the message

        Returns:
            dict: constructed operation message
        """
        try:
            return {
                "default_msg": "0" if operation.get("op_message") is not None or operation.get("subject") is not None else "1",
                "mediatypeid": self._zapi_wrapper.get_mediatype_by_mediatype_name(
                    operation.get("media_type")
                ) if operation.get("media_type") is not None else "0",
                "message": operation.get("op_message"),
                "subject": operation.get("subject"),
            }
        except Exception as e:
            self._module.fail_json(msg="Failed to construct operation message. The error was: %s" % e)

    def _construct_opmessage_usr(self, operation):
        """Construct operation message user.

        Args:
            operation: operation to construct the message user

        Returns:
            list: constructed operation message user or None if operation not found
        """
        if operation.get("send_to_users") is None:
            return None
        return [{
            "userid": self._zapi_wrapper.get_user_by_user_name(_user)["userid"]
        } for _user in operation.get("send_to_users")]

    def _construct_opmessage_grp(self, operation):
        """Construct operation message group.

        Args:
            operation: operation to construct the message group

        Returns:
            list: constructed operation message group or None if operation not found
        """
        if operation.get("send_to_groups") is None:
            return None
        return [{
            "usrgrpid": self._zapi_wrapper.get_usergroup_by_usergroup_name(_group)["usrgrpid"]
        } for _group in operation.get("send_to_groups")]

    def _construct_opcommand(self, operation):
        """Construct operation command.

        Args:
            operation: operation to construct command

        Returns:
            list: constructed operation command
        """
        try:
            opcommand = {
                "scriptid": self._zapi_wrapper.get_script_by_script_name(
                    operation.get("script_name")
                ).get("scriptid")
            }

            return opcommand

        except Exception as e:
            self._module.fail_json(msg="Failed to construct operation command. The error was: %s" % e)

    def _construct_opcommand_hst(self, operation):
        """Construct operation command host.

        Args:
            operation: operation to construct command host

        Returns:
            list: constructed operation command host
        """
        if operation.get("run_on_hosts") is None:
            return None
        return [{
            "hostid": self._zapi_wrapper.get_host_by_host_name(_host)["hostid"]
        } if str(_host) != "0" else {"hostid": "0"} for _host in operation.get("run_on_hosts")]

    def _construct_opcommand_grp(self, operation):
        """Construct operation command group.

        Args:
            operation: operation to construct command group

        Returns:
            list: constructed operation command group
        """
        if operation.get("run_on_groups") is None:
            return None
        return [{
            "groupid": self._zapi_wrapper.get_hostgroup_by_hostgroup_name(_group)["groupid"]
        } for _group in operation.get("run_on_groups")]

    def _construct_opgroup(self, operation):
        """Construct operation group.

        Args:
            operation: operation to construct group

        Returns:
            list: constructed operation group
        """
        return [{
            "groupid": self._zapi_wrapper.get_hostgroup_by_hostgroup_name(_group)["groupid"]
        } for _group in operation.get("host_groups", [])]

    def _construct_optemplate(self, operation):
        """Construct operation template.

        Args:
            operation: operation to construct template

        Returns:
            list: constructed operation template
        """
        return [{
            "templateid": self._zapi_wrapper.get_template_by_template_name(_template)["templateid"]
        } for _template in operation.get("templates", [])]

    def _construct_opinventory(self, operation):
        """Construct operation inventory.

        Args:
            operation: operation to construct inventory

        Returns:
            dict: constructed operation inventory
        """
        return {
            "inventory_mode": zabbix_utils.helper_to_numeric_value([
                "manual",
                "automatic"
            ], operation.get("inventory"))
        }

    def _construct_opconditions(self, operation):
        """Construct operation conditions.

        Args:
            operation: operation to construct the conditions

        Returns:
            list: constructed operation conditions
        """
        _opcond = operation.get("operation_condition")
        if _opcond is not None:
            if _opcond == "acknowledged":
                _value = "1"
            elif _opcond == "not_acknowledged":
                _value = "0"
            return [{
                "conditiontype": "14",
                "operator": "0",
                "value": _value
            }]
        return []

    def construct_the_data(self, operations, event_source):
        """Construct the operation data using helper methods.

        Args:
            operation: operation to construct

        Returns:
            list: constructed operation data
        """
        constructed_data = []
        for op in operations:
            operation_type = self._construct_operationtype(op)
            constructed_operation = {
                "operationtype": operation_type,
                "esc_period": op.get("esc_period"),
                "esc_step_from": op.get("esc_step_from"),
                "esc_step_to": op.get("esc_step_to")
            }
            # Send Message type
            if constructed_operation["operationtype"] == 0:
                constructed_operation["opmessage"] = self._construct_opmessage(op)
                constructed_operation["opmessage_usr"] = self._construct_opmessage_usr(op)
                constructed_operation["opmessage_grp"] = self._construct_opmessage_grp(op)
                if event_source == "trigger":
                    # opconditions valid only for "trigger" action
                    constructed_operation["opconditions"] = self._construct_opconditions(op)

            # Send Command type
            if constructed_operation["operationtype"] == 1:
                constructed_operation["opcommand"] = self._construct_opcommand(op)
                constructed_operation["opcommand_hst"] = self._construct_opcommand_hst(op)
                constructed_operation["opcommand_grp"] = self._construct_opcommand_grp(op)
                if event_source == "trigger":
                    # opconditions valid only for "trigger" action
                    constructed_operation["opconditions"] = self._construct_opconditions(op)

            # Add to/Remove from host group
            if constructed_operation["operationtype"] in (4, 5):
                constructed_operation["opgroup"] = self._construct_opgroup(op)

            if LooseVersion(self._zbx_api_version) >= LooseVersion("7.0"):
                # Add/Remove tags
                if constructed_operation["operationtype"] in (13, 14):
                    constructed_operation["optag"] = op["tags"]

            # Link/Unlink template
            if constructed_operation["operationtype"] in (6, 7):
                constructed_operation["optemplate"] = self._construct_optemplate(op)

            # Set inventory mode
            if constructed_operation["operationtype"] == 10:
                constructed_operation["opinventory"] = self._construct_opinventory(op)

            # Remove escalation params when for event sources where they are not applicable
            if event_source in ["trigger", "internal"]:
                if isinstance(constructed_operation.get("esc_period"), type(None)):
                    constructed_operation["esc_period"] = 0
            else:
                constructed_operation.pop("esc_period")
                constructed_operation.pop("esc_step_from")
                constructed_operation.pop("esc_step_to")

            constructed_data.append(constructed_operation)

        return zabbix_utils.helper_cleanup_data(constructed_data)


class RecoveryOperations(Operations):
    """
    Restructures the user defined recovery operations data to fit the Zabbix API requirements
    """

    def _construct_operationtype(self, operation):
        """Construct operation type.

        Args:
            operation: operation to construct type

        Returns:
            str: constructed operation type
        """
        try:
            return zabbix_utils.helper_to_numeric_value([
                "send_message",
                "remote_command",
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                "notify_all_involved"], operation["type"]
            )
        except Exception:
            self._module.fail_json(msg="Unsupported value '%s' for recovery operation type." % operation["type"])

    def construct_the_data(self, operations):
        """Construct the recovery operations data using helper methods.

        Args:
            operation: operation to construct

        Returns:
            list: constructed recovery operations data
        """
        constructed_data = []
        for op in operations:
            operation_type = self._construct_operationtype(op)
            constructed_operation = {
                "operationtype": operation_type,
            }

            # Send Message type
            if constructed_operation["operationtype"] == 0:
                constructed_operation["opmessage"] = self._construct_opmessage(op)
                constructed_operation["opmessage_usr"] = self._construct_opmessage_usr(op)
                constructed_operation["opmessage_grp"] = self._construct_opmessage_grp(op)

            if constructed_operation["operationtype"] == 11:
                constructed_operation["opmessage"] = self._construct_opmessage(op)
                constructed_operation["opmessage"].pop("mediatypeid")

            # Send Command type
            if constructed_operation["operationtype"] == 1:
                constructed_operation["opcommand"] = self._construct_opcommand(op)
                constructed_operation["opcommand_hst"] = self._construct_opcommand_hst(op)
                constructed_operation["opcommand_grp"] = self._construct_opcommand_grp(op)

            constructed_data.append(constructed_operation)

        return zabbix_utils.helper_cleanup_data(constructed_data)


class AcknowledgeOperations(Operations):
    """
    Restructures the user defined acknowledge operations data to fit the Zabbix API requirements
    """

    def _construct_operationtype(self, operation):
        """Construct operation type.

        Args:
            operation: operation to construct type

        Returns:
            str: constructed operation type
        """
        try:
            return zabbix_utils.helper_to_numeric_value([
                "send_message",
                "remote_command",
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                "notify_all_involved"], operation["type"]
            )
        except Exception:
            self._module.fail_json(msg="Unsupported value '%s' for acknowledge operation type." % operation["type"])

    def construct_the_data(self, operations):
        """Construct the acknowledge operations data using helper methods.

        Args:
            operation: operation to construct

        Returns:
            list: constructed acknowledge operations data
        """
        constructed_data = []
        for op in operations:
            operation_type = self._construct_operationtype(op)
            constructed_operation = {
                "operationtype": operation_type,
            }

            # Send Message type
            if constructed_operation["operationtype"] == 0:
                constructed_operation["opmessage"] = self._construct_opmessage(op)
                constructed_operation["opmessage_usr"] = self._construct_opmessage_usr(op)
                constructed_operation["opmessage_grp"] = self._construct_opmessage_grp(op)

            if constructed_operation["operationtype"] == 12:
                constructed_operation["opmessage"] = self._construct_opmessage(op)
                constructed_operation["opmessage"].pop("mediatypeid")

            # Send Command type
            if constructed_operation["operationtype"] == 1:
                constructed_operation["opcommand"] = self._construct_opcommand(op)
                constructed_operation["opcommand_hst"] = self._construct_opcommand_hst(op)
                constructed_operation["opcommand_grp"] = self._construct_opcommand_grp(op)

            constructed_data.append(constructed_operation)

        return zabbix_utils.helper_cleanup_data(constructed_data)


class Filter(Zapi):
    def _construct_evaltype(self, _eval_type, _formula, _conditions):
        """Construct the eval type

        Args:
            _formula: zabbix condition evaluation formula
            _conditions: list of conditions to check

        Returns:
            dict: constructed acknowledge operations data
        """
        if len(_conditions) <= 1:
            return {
                "evaltype": "0",
                "formula": None
            }
        if _eval_type == "andor":
            return {
                "evaltype": "0",
                "formula": None
            }
        if _eval_type == "and":
            return {
                "evaltype": "1",
                "formula": None
            }
        if _eval_type == "or":
            return {
                "evaltype": "2",
                "formula": None
            }
        if _eval_type == "custom_expression":
            if _formula is not None:
                return {
                    "evaltype": "3",
                    "formula": _formula
                }
            else:
                self._module.fail_json(msg="'formula' is required when 'eval_type' is set to 'custom_expression'")
        if _formula is not None:
            return {
                "evaltype": "3",
                "formula": _formula
            }
        return {
            "evaltype": "0",
            "formula": None
        }

    def _construct_conditiontype(self, _condition):
        """Construct the condition type

        Args:
            _condition: condition to check

        Returns:
            str: constructed condition type data
        """
        try:
            return zabbix_utils.helper_to_numeric_value([
                "host_group",
                "host",
                "trigger",
                "trigger_name",
                "trigger_severity",
                "trigger_value",
                "time_period",
                "host_ip",
                "discovered_service_type",
                "discovered_service_port",
                "discovery_status",
                "uptime_or_downtime_duration",
                "received_value",
                "host_template",
                None,
                None,
                "maintenance_status",
                None,
                "discovery_rule",
                "discovery_check",
                "proxy",
                "discovery_object",
                "host_name",
                "event_type",
                "host_metadata",
                "event_tag",
                "event_tag_value"], _condition["type"]
            )
        except Exception:
            self._module.fail_json(msg="Unsupported value '%s' for condition type." % _condition["type"])

    def _construct_operator(self, _condition):
        """Construct operator

        Args:
            _condition: condition to construct

        Returns:
            str: constructed operator
        """
        try:
            return zabbix_utils.helper_to_numeric_value([
                ["equals", "="],
                ["does not equal", "<>"],
                ["contains", "like"],
                ["does not contain", "not like"],
                "in",
                ["is greater than or equals", ">="],
                ["is less than or equals", "<="],
                "not in",
                "matches",
                "does not match",
                "Yes",
                "No"], _condition["operator"]
            )
        except Exception:
            self._module.fail_json(msg="Unsupported value '%s' for operator." % _condition["operator"])

    def _construct_value(self, conditiontype, value):
        """Construct operator

        Args:
            conditiontype: type of condition to construct
            value: value to construct

        Returns:
            str: constructed value
        """
        try:
            # Host group
            if conditiontype == 0:
                return self._zapi_wrapper.get_hostgroup_by_hostgroup_name(value)["groupid"]
            # Host
            if conditiontype == 1:
                return self._zapi_wrapper.get_host_by_host_name(value)["hostid"]
            # Trigger
            if conditiontype == 2:
                return self._zapi_wrapper.get_trigger_by_trigger_name(value)["triggerid"]
            # Trigger name: return as is
            # Trigger severity
            if conditiontype == 4:
                return zabbix_utils.helper_to_numeric_value([
                    "not classified",
                    "information",
                    "warning",
                    "average",
                    "high",
                    "disaster"], value or "not classified"
                )

            # Trigger value
            if conditiontype == 5:
                return zabbix_utils.helper_to_numeric_value([
                    "ok",
                    "problem"], value or "ok"
                )
            # Time period: return as is
            # Host IP: return as is
            # Discovered service type
            if conditiontype == 8:
                return zabbix_utils.helper_to_numeric_value([
                    "SSH",
                    "LDAP",
                    "SMTP",
                    "FTP",
                    "HTTP",
                    "POP",
                    "NNTP",
                    "IMAP",
                    "TCP",
                    "Zabbix agent",
                    "SNMPv1 agent",
                    "SNMPv2 agent",
                    "ICMP ping",
                    "SNMPv3 agent",
                    "HTTPS",
                    "Telnet"], value
                )
            # Discovered service port: return as is
            # Discovery status
            if conditiontype == 10:
                return zabbix_utils.helper_to_numeric_value([
                    "up",
                    "down",
                    "discovered",
                    "lost"], value
                )
            if conditiontype == 13:
                return self._zapi_wrapper.get_template_by_template_name(value)["templateid"]
            # maintenance_status
            if conditiontype == 16:
                return zabbix_utils.helper_to_numeric_value([
                    "Yes",
                    "No"], value
                )
            if conditiontype == 18:
                return self._zapi_wrapper.get_discovery_rule_by_discovery_rule_name(value)["druleid"]
            if conditiontype == 19:
                return self._zapi_wrapper.get_discovery_check_by_discovery_check_name(value)["dcheckid"]
            if conditiontype == 20:
                return self._zapi_wrapper.get_proxy_by_proxy_name(value)["proxyid"]
            if conditiontype == 21:
                return zabbix_utils.helper_to_numeric_value([
                    "pchldrfor0",
                    "host",
                    "service"], value
                )
            if conditiontype == 23:
                return zabbix_utils.helper_to_numeric_value([
                    "item in not supported state",
                    "item in normal state",
                    "LLD rule in not supported state",
                    "LLD rule in normal state",
                    "trigger in unknown state",
                    "trigger in normal state"], value
                )
            return value
        except Exception:
            self._module.fail_json(
                msg="""Unsupported value '%s' for specified condition type.
                       Check out Zabbix API documentation for supported values for
                       condition type '%s' at
                       https://www.zabbix.com/documentation/3.4/manual/api/reference/action/object#action_filter_condition""" % (value, conditiontype)
            )

    def construct_the_data(self, _eval_type, _formula, _conditions):
        """Construct the user defined filter conditions to fit the Zabbix API
        requirements operations data using helper methods.

        Args:
            _formula:  zabbix condition evaluation formula
            _conditions: conditions to construct

        Returns:
            dict: user defined filter conditions
        """
        if _conditions is None:
            return None
        constructed_data = {}
        constructed_data["conditions"] = []
        for cond in _conditions:
            condition_type = self._construct_conditiontype(cond)
            constructed_data["conditions"].append({
                "conditiontype": condition_type,
                "value": self._construct_value(condition_type, cond.get("value")),
                "value2": cond.get("value2"),
                "formulaid": cond.get("formulaid"),
                "operator": self._construct_operator(cond)
            })
        _constructed_evaltype = self._construct_evaltype(
            _eval_type,
            _formula,
            constructed_data["conditions"]
        )
        constructed_data["evaltype"] = _constructed_evaltype["evaltype"]
        constructed_data["formula"] = _constructed_evaltype["formula"]
        return zabbix_utils.helper_cleanup_data(constructed_data)


def main():
    """Main ansible module function
    """

    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        esc_period=dict(type="str", required=False),
        name=dict(type="str", required=True),
        event_source=dict(type="str", required=False, choices=["trigger", "discovery", "auto_registration", "internal"]),
        state=dict(type="str", required=False, default="present", choices=["present", "absent"]),
        status=dict(type="str", required=False, default="enabled", choices=["enabled", "disabled"]),
        pause_in_maintenance=dict(type="bool", required=False, default=True),
        conditions=dict(
            type="list",
            required=False,
            default=[],
            elements="dict",
            options=dict(
                formulaid=dict(type="str", required=False),
                operator=dict(
                    type="str",
                    required=True,
                    choices=[
                        "equals",
                        "=",
                        "does not equal",
                        "<>",
                        "contains",
                        "like",
                        "does not contain",
                        "not like",
                        "in",
                        "is greater than or equals",
                        ">=",
                        "is less than or equals",
                        "<=",
                        "not in",
                        "matches",
                        "does not match",
                        "Yes",
                        "No"
                    ]
                ),
                type=dict(type="str", required=True),
                value=dict(type="str", required=False),
                value2=dict(type="str", required=False)
            ),
            required_if=[
                ["type", "event_tag_value", ["value2"]],
            ]
        ),
        formula=dict(type="str", required=False, default=None),
        eval_type=dict(type="str", required=False, default=None, choices=["andor", "and", "or", "custom_expression"]),
        operations=dict(
            type="list",
            required=False,
            default=[],
            elements="dict",
            options=dict(
                type=dict(
                    type="str",
                    required=True,
                    choices=[
                        "send_message",
                        "remote_command",
                        "add_host",
                        "remove_host",
                        "add_to_host_group",
                        "remove_from_host_group",
                        "link_to_template",
                        "unlink_from_template",
                        "enable_host",
                        "disable_host",
                        "set_host_inventory_mode",
                        "notify_all_involved",
                        "add_host_tags",
                        "remove_host_tags"
                    ]
                ),
                esc_period=dict(type="str", required=False, default="0s"),
                esc_step_from=dict(type="int", required=False, default=1),
                esc_step_to=dict(type="int", required=False, default=1),
                operation_condition=dict(
                    type="str",
                    required=False,
                    default=None,
                    choices=["acknowledged", "not_acknowledged"]
                ),
                # when type is remote_command
                command_type=dict(
                    type="str",
                    required=False,
                    choices=[
                        "custom_script",
                        "ipmi",
                        "ssh",
                        "telnet",
                        "global_script"
                    ]
                ),
                command=dict(type="str", required=False),
                execute_on=dict(
                    type="str",
                    required=False,
                    choices=["agent", "server", "proxy"]
                ),
                password=dict(type="str", required=False, no_log=True),
                port=dict(type="int", required=False),
                run_on_groups=dict(type="list", required=False, elements="str"),
                run_on_hosts=dict(type="list", required=False, elements="str"),
                script_name=dict(type="str", required=False),
                ssh_auth_type=dict(type="str", required=False, choices=["password", "public_key"]),
                ssh_privatekey_file=dict(type="str", required=False),
                ssh_publickey_file=dict(type="str", required=False),
                username=dict(type="str", required=False),
                # when type is send_message
                media_type=dict(type="str", required=False, default="all"),
                subject=dict(type="str", required=False),
                op_message=dict(type="str", required=False),
                send_to_groups=dict(type="list", required=False, elements="str"),
                send_to_users=dict(type="list", required=False, elements="str"),
                # when type is add_to_host_group or remove_from_host_group
                host_groups=dict(type="list", required=False, elements="str"),
                # when type is set_host_inventory_mode
                inventory=dict(type="str", required=False, choices=["manual", "automatic"]),
                # when type is link_to_template or unlink_from_template
                templates=dict(type="list", required=False, elements="str"),
                tags=dict(type="list", required=False, elements="dict")
            ),
            required_if=[
                ["type", "remote_command", ["command_type"]],
                ["type", "remote_command", ["run_on_groups", "run_on_hosts"], True],
                ["command_type", "custom_script", ["command", "execute_on"]],
                ["command_type", "ipmi", ["command"]],
                ["command_type", "ssh", ["command", "ssh_auth_type"]],
                ["ssh_auth_type", "password", ["username", "password"]],
                ["ssh_auth_type", "public_key", ["username", "ssh_privatekey_file", "ssh_publickey_file"]],
                ["command_type", "telnet", ["command", "username", "password"]],
                ["command_type", "global_script", ["script_name"]],
                ["type", "add_to_host_group", ["host_groups"]],
                ["type", "remove_from_host_group", ["host_groups"]],
                ["type", "link_to_template", ["templates"]],
                ["type", "unlink_from_template", ["templates"]],
                ["type", "set_host_inventory_mode", ["inventory"]],
                ["type", "send_message", ["send_to_users", "send_to_groups"], True],
                ["type", "add_host_tags", ["tags"], True],
                ["type", "remove_host_tags", ["tags"], True]
            ]
        ),
        recovery_operations=dict(
            type="list",
            required=False,
            default=[],
            elements="dict",
            options=dict(
                type=dict(
                    type="str",
                    required=True,
                    choices=[
                        "send_message",
                        "remote_command",
                        "notify_all_involved"
                    ]
                ),
                # when type is remote_command
                command_type=dict(
                    type="str",
                    required=False,
                    choices=[
                        "custom_script",
                        "ipmi",
                        "ssh",
                        "telnet",
                        "global_script"
                    ]
                ),
                command=dict(type="str", required=False),
                execute_on=dict(
                    type="str",
                    required=False,
                    choices=["agent", "server", "proxy"]
                ),
                password=dict(type="str", required=False, no_log=True),
                port=dict(type="int", required=False),
                run_on_groups=dict(type="list", required=False, elements="str"),
                run_on_hosts=dict(type="list", required=False, elements="str"),
                script_name=dict(type="str", required=False),
                ssh_auth_type=dict(type="str", required=False, choices=["password", "public_key"]),
                ssh_privatekey_file=dict(type="str", required=False),
                ssh_publickey_file=dict(type="str", required=False),
                username=dict(type="str", required=False),
                # when type is send_message
                media_type=dict(type="str", required=False, default="all"),
                subject=dict(type="str", required=False),
                op_message=dict(type="str", required=False),
                send_to_groups=dict(type="list", required=False, elements="str"),
                send_to_users=dict(type="list", required=False, elements="str"),
            ),
            required_if=[
                ["type", "remote_command", ["command_type"]],
                ["type", "remote_command", [
                    "run_on_groups",
                    "run_on_hosts"
                ], True],
                ["command_type", "custom_script", [
                    "command",
                    "execute_on"
                ]],
                ["command_type", "ipmi", ["command"]],
                ["command_type", "ssh", ["command", "ssh_auth_type"]],
                ["ssh_auth_type", "password", ["username", "password"]],
                ["ssh_auth_type", "public_key", ["username", "ssh_privatekey_file", "ssh_publickey_file"]],
                ["command_type", "telnet", ["command", "username", "password"]],
                ["command_type", "global_script", ["script_name"]],
                ["type", "send_message", ["send_to_users", "send_to_groups"], True]
            ]
        ),
        acknowledge_operations=dict(
            type="list",
            required=False,
            default=[],
            elements="dict",
            aliases=["update_operations"],
            options=dict(
                type=dict(
                    type="str",
                    required=True,
                    choices=[
                        "send_message",
                        "remote_command",
                        "notify_all_involved"
                    ]
                ),
                # when type is remote_command
                command_type=dict(
                    type="str",
                    required=False,
                    choices=[
                        "custom_script",
                        "ipmi",
                        "ssh",
                        "telnet",
                        "global_script"
                    ]
                ),
                command=dict(type="str", required=False),
                execute_on=dict(
                    type="str",
                    required=False,
                    choices=["agent", "server", "proxy"]
                ),
                password=dict(type="str", required=False, no_log=True),
                port=dict(type="int", required=False),
                run_on_groups=dict(type="list", required=False, elements="str"),
                run_on_hosts=dict(type="list", required=False, elements="str"),
                script_name=dict(type="str", required=False),
                ssh_auth_type=dict(type="str", required=False, choices=["password", "public_key"]),
                ssh_privatekey_file=dict(type="str", required=False),
                ssh_publickey_file=dict(type="str", required=False),
                username=dict(type="str", required=False),
                # when type is send_message
                media_type=dict(type="str", required=False, default="all"),
                subject=dict(type="str", required=False),
                op_message=dict(type="str", required=False),
                send_to_groups=dict(type="list", required=False, elements="str"),
                send_to_users=dict(type="list", required=False, elements="str"),
            ),
            required_if=[
                ["type", "remote_command", ["command_type"]],
                ["type", "remote_command", [
                    "run_on_groups",
                    "run_on_hosts"
                ], True],
                ["command_type", "custom_script", [
                    "command",
                    "execute_on"
                ]],
                ["command_type", "ipmi", ["command"]],
                ["command_type", "ssh", ["command", "ssh_auth_type"]],
                ["ssh_auth_type", "password", ["username", "password"]],
                ["ssh_auth_type", "public_key", ["username", "ssh_privatekey_file", "ssh_publickey_file"]],
                ["command_type", "telnet", ["command", "username", "password"]],
                ["command_type", "global_script", ["script_name"]],
                ["type", "send_message", ["send_to_users", "send_to_groups"], True]
            ]
        ),
        pause_symptoms=dict(type="bool", required=False, default=True),
        notify_if_canceled=dict(type="bool", required=False, default=True)
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=[
            ["state", "present", [
                "event_source"
            ]]
        ],
        supports_check_mode=True
    )

    name = module.params["name"]
    esc_period = module.params["esc_period"]
    event_source = module.params["event_source"]
    state = module.params["state"]
    status = module.params["status"]
    pause_in_maintenance = module.params["pause_in_maintenance"]
    conditions = module.params["conditions"]
    formula = module.params["formula"]
    eval_type = module.params["eval_type"]
    operations = module.params["operations"]
    recovery_operations = module.params["recovery_operations"]
    acknowledge_operations = module.params["acknowledge_operations"]
    pause_symptoms = module.params["pause_symptoms"]
    notify_if_canceled = module.params["notify_if_canceled"]

    zapi_wrapper = Zapi(module)
    action = Action(module)

    action_exists = zapi_wrapper.check_if_action_exists(name)
    ops = Operations(module, zapi_wrapper)
    recovery_ops = RecoveryOperations(module, zapi_wrapper)
    acknowledge_ops = AcknowledgeOperations(module, zapi_wrapper)
    fltr = Filter(module, zapi_wrapper)

    if action_exists:
        action_id = zapi_wrapper.get_action_by_name(name)["actionid"]
        if state == "absent":
            result = action.delete_action(action_id)
            module.exit_json(changed=True, msg="Action Deleted: %s, ID: %s" % (name, result))
        else:
            kwargs = dict(
                action_id=action_id,
                name=name,
                event_source=event_source,
                esc_period=esc_period,
                status=status,
                pause_in_maintenance=pause_in_maintenance,
                operations=ops.construct_the_data(operations, event_source),
                recovery_operations=recovery_ops.construct_the_data(recovery_operations),
                conditions=fltr.construct_the_data(eval_type, formula, conditions),
                notify_if_canceled=notify_if_canceled
            )

            if LooseVersion(zapi_wrapper._zbx_api_version) >= LooseVersion("6.4"):
                kwargs["pause_symptoms"] = pause_symptoms

            kwargs[argument_spec["acknowledge_operations"]["aliases"][0]] = acknowledge_ops.construct_the_data(acknowledge_operations)

            difference = action.check_difference(**kwargs)

            if difference == {}:
                module.exit_json(changed=False, msg="Action is up to date: %s" % (name))
            else:
                result = action.update_action(
                    action_id=action_id,
                    **difference
                )
                module.exit_json(changed=True, msg="Action Updated: %s, ID: %s" % (name, result))
    else:
        if state == "absent":
            module.exit_json(changed=False)
        else:
            kwargs = dict(
                name=name,
                event_source=event_source,
                esc_period=esc_period,
                status=status,
                pause_in_maintenance=pause_in_maintenance,
                operations=ops.construct_the_data(operations, event_source),
                recovery_operations=recovery_ops.construct_the_data(recovery_operations),
                conditions=fltr.construct_the_data(eval_type, formula, conditions),
                notify_if_canceled=notify_if_canceled
            )

            kwargs[argument_spec["acknowledge_operations"]["aliases"][0]] = acknowledge_ops.construct_the_data(acknowledge_operations)

            if LooseVersion(zapi_wrapper._zbx_api_version) >= LooseVersion("6.4"):
                kwargs["pause_symptoms"] = pause_symptoms

            action_id = action.add_action(**kwargs)
            module.exit_json(changed=True, msg="Action created: %s, ID: %s" % (name, action_id))


if __name__ == "__main__":
    main()
