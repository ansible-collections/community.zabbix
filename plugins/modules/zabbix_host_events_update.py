#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: zabbix_host_events_update
short_description: update the status of event(s).
description:
   - Updates the status of event(s).
author:
    - "Andrew Lathrop (@aplathrop)"
requirements:
    - "python >= 2.6"

options:
    params:
        description:
            - Parameters to update event(s) with.
            - Parameters as defined at https://www.zabbix.com/documentation/current/en/manual/api/reference/event/acknowledge
            - Additionally supported parameters are below
        required: true
        type: dict
        suboptions:
            action:
                description:
                  - action to update the event with
                  - Overrides "action" in API docs
                  - Required when I(actions) is not used.
                  - Mutually exclusive with I(actions).
                required: false
                type: str
                choices:
                  - close_problem
                  - close
                  - acknowledge_event
                  - acknowledge
                  - ack
                  - add_message
                  - message
                  - msg
                  - change_severity
                  - severity
                  - unacknowledge_event
                  - unacknowledge
                  - unack
                  - suppress_event
                  - suppress
                  - unsuppress_event
                  - unsuppress
                  - change_event_rank_to_cause
                  - convert_to_cause
                  - change_event_rank_to_symptom
                  - convert_to_symptom
            actions:
                description:
                  - actions to update the event with
                  - Overrides "action" in API docs
                  - Required when I(action) is not used.
                  - Mutually exclusive with I(action).
                required: false
                type: list
                elements: str
                choices:
                  - close_problem
                  - close
                  - acknowledge_event
                  - acknowledge
                  - ack
                  - add_message
                  - message
                  - msg
                  - change_severity
                  - severity
                  - unacknowledge_event
                  - unacknowledge
                  - unack
                  - suppress_event
                  - suppress
                  - unsuppress_event
                  - unsuppress
                  - change_event_rank_to_cause
                  - convert_to_cause
                  - change_event_rank_to_symptom
                  - convert_to_symptom
            severity:
                description:
                  - New severity for events.
                  - Overrides "severity" in API docs
                required: False
                type: str
                choices:
                    - not_classified
                    - information
                    - warning
                    - average
                    - high
                    - disaster
            msg:
                description:
                  - Text of the message.
                  - Alias for "message" in API docs
                required: False
                type: str

extends_documentation_fragment:
- community.zabbix.zabbix
'''

EXAMPLES = r'''

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

# Acknowledge single event
- name: ack event
  community.zabbix.zabbix_host_events_update:
    params:
      eventids: 12345
      actions: ack

- name: ack and close event with a message
  community.zabbix.zabbix_host_events_update:
    params:
      eventids: [12345, 67890]
      actions: ['ack', 'msg', 'close']
      msg: 'closed by user'

'''

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class Hosteventsupdate(ZabbixBase):
    ACTIONS = {'close_problem': 1,
               'close': 1,
               'acknowledge_event': 2,
               'acknowledge': 2,
               'ack': 2,
               'add_message': 4,
               'message': 4,
               'msg': 4,
               'change_severity': 8,
               'severity': 8,
               'unacknowledge_event': 16,
               'unacknowledge': 16,
               'unack': 16,
               'suppress_event': 32,
               'suppress': 32,
               'unsuppress_event': 64,
               'unsuppress': 64,
               'change_event_rank_to_cause': 128,
               'convert_to_cause': 128,
               'change_event_rank_to_symptom': 256,
               'convert_to_symptom': 256}

    SEVERITY_TYPES = {'not_classified': 0,
                      'information': 1,
                      'warning': 2,
                      'average': 3,
                      'high': 4,
                      'disaster': 5}

    def get_events(self, eventids):
        try:
            results = self._zapi.event.get({'eventids': eventids})
        except Exception as e:
            self._module.fail_json(msg="Failed to get event: %s" % e)
        return results

    def update_event(self, params):
        if 'severity' in params:
            if params['severity'] not in self.SEVERITY_TYPES:
                self._module.fail_json(msg="%s is not a valid severity type" % params['severity'])
            severity = self.SEVERITY_TYPES[params['severity']]
            params['severity'] = severity
        if 'action' in params:
            if params['action'] not in self.ACTIONS:
                self._module.fail_json(msg="%s is not a valid action" % params['action'])
            action_id = self.ACTIONS[params['action']]
        elif 'actions' in params:
            action_id = 0
            for action in params['actions']:
                if action not in self.ACTIONS:
                    self._module.fail_json(msg="%s is not a valid action" % action)
                action_id += self.ACTIONS[action]
            params.pop('actions')
        else:
            self._module.fail_json(msg="params must contain either 'action' or 'actions'")
        params['action'] = action_id
        if 'msg' in params:
            params['message'] = params['msg']
            params.pop('msg')
        if self._module.check_mode:
            self._module.exit_json(changed=True)
        try:
            results = self._zapi.event.acknowledge(params)
        except Exception as e:
            self._module.fail_json(msg="Failed to update event: %s" % e)
        return results

    def check_events_changed(self, eventids, old_events):
        new_events = self.get_events(eventids)
        return old_events != new_events


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(
        params=dict(type='dict', required=True))
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    params = module.params['params']

    hosteventsupdate = Hosteventsupdate(module)

    events = hosteventsupdate.get_events(params['eventids'])
    results = hosteventsupdate.update_event(params)
    changed = hosteventsupdate.check_events_changed(params['eventids'], events)
    module.exit_json(changed=changed, result=results)


if __name__ == '__main__':
    main()
