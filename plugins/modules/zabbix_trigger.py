#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: zabbix_trigger
short_description: Create/delete Zabbix triggers
description:
   - Create triggers if they do not exist.
   - Delete existing triggers if they exist.
author:
    - "Andrew Lathrop (@aplathrop)"
requirements:
    - "python >= 2.6"

options:
    state:
        description:
            - Create or delete trigger.
        required: false
        type: str
        default: "present"
        choices: [ "present", "absent" ]
    name:
        description:
            - Name of trigger to create or delete.
            - Overrides "description" in API docs.
            - Cannot be changed. If a trigger's name needs to be changed, it needs to deleted and recreated
        required: true
        type: str
    host_name:
        description:
            - Name of host to add trigger to.
            - Required when I(template_name) is not used.
            - Mutually exclusive with I(template_name).
        required: false
        type: str
    template_name:
        description:
            - Name of template to add trigger to.
            - Required when I(host_name) is not used.
            - Mutually exclusive with I(host_name).
        required: false
        type: str
    desc:
        description:
            - Additional description of the trigger.
            - Overrides "comments" in API docs.
        required: false
        type: str
        aliases: [ "description" ]
    dependencies:
        description:
            - list of triggers that this trigger is dependent on
        required: false
        type: list
        elements: dict
        suboptions:
                name:
                    description:
                        - Name of dependent trigger.
                    required: true
                    type: str
                host_name:
                    description:
                        - Name of host containing dependent trigger.
                        - Required when I(template_name) is not used.
                        - Mutually exclusive with I(template_name).
                    required: false
                    type: str
                template_name:
                    description:
                        - Name of template containing dependent trigger.
                        - Required when I(host_name) is not used.
                        - Mutually exclusive with I(host_name).
                    required: false
                    type: str
    params:
        description:
            - Parameters to create/update trigger with.
            - Required if state is "present".
            - Parameters as defined at https://www.zabbix.com/documentation/current/en/manual/api/reference/trigger/object
            - Additionally supported parameters are below.
        required: false
        type: dict
        suboptions:
            severity:
                description:
                    - Severity of the trigger.
                    - Alias for "priority" in API docs.
                required: false
                type: str
                aliases: [ "priority" ]
                choices:
                    - not_classified
                    - information
                    - warning
                    - average
                    - high
                    - disaster
            status:
                description:
                    - Status of the trigger.
                required: false
                type: str
                choices: [ "enabled", "disabled" ]
            enabled:
                description:
                    - Status of the trigger.
                    - Overrides "status" in API docs.
                required: false
                type: bool
            new_name:
                description:
                    - New name for trigger
                required: false
                type: str
            generate_multiple_events:
                description:
                    - Whether the trigger can generate multiple problem events.
                    - Alias for "type" in API docs.
                required: false
                type: bool
            recovery_mode:
                description:
                    - OK event generation mode.
                    - Overrides "recovery_mode" in API docs.
                required: false
                type: str
                choices:
                    - expression
                    - recovery_expression
                    - none
            correlation_mode:
                description:
                    - OK event closes.
                    - Overrides "correlation_mode" in API docs.
                required: false
                type: str
                choices: [ "all", "tag" ]
            manual_close:
                description:
                    - Allow manual close.
                    - Overrides "manual_close" in API docs.
                required: false
                type: bool

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

# Create ping trigger on example_host
- name: create ping trigger
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_trigger:
    name: agent_ping
    host_name: example_host
    params:
        severity: high
        expression: 'nodata(/example_host/agent.ping,1m)=1'
        manual_close: True
        enabled: True
    state: present

# Create ping trigger on example_template
- name: create ping trigger
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_trigger:
    name: agent_ping
    host_name: example_template
    params:
        severity: high
        expression: 'nodata(/example_template/agent.ping,1m)=1'
        manual_close: True
        enabled: True
    state: present

# Add tags to the existing Zabbix trigger
- name: update ping trigger
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_trigger:
    name: agent_ping
    host_name: example_template
    params:
        severity: high
        expression: 'nodata(/example_template/agent.ping,1m)=1'
        manual_close: True
        enabled: True
        tags:
          - tag: class
            value: application
    state: present

# delete Zabbix trigger
- name: delete ping trigger
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_trigger:
    name: agent_ping
    host_name: example_template
    state: absent

- name: Rename Zabbix trigger
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_trigger:
    name: agent_ping
    template_name: example_template
    params:
      new_name: new_agent_ping
    state: present
'''

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class Trigger(ZabbixBase):

    PRIORITY_TYPES = {'not_classified': 0,
                      'information': 1,
                      'warning': 2,
                      'average': 3,
                      'high': 4,
                      'disaster': 5}

    RECOVERY_MODES = {'expression': 0,
                      'recovery_expression': 1,
                      'none': 2}

    def get_triggers(self, trigger_name, host_name, template_name):
        if host_name is not None:
            host = host_name
        else:
            host = template_name
        triggers = []
        try:
            triggers = self._zapi.trigger.get({'filter': {'description': trigger_name, 'host': host}})
        except Exception as e:
            self._module.fail_json(msg="Failed to get trigger: %s" % e)
        return triggers

    def sanitize_params(self, name, params, desc=None, dependencies=None):
        params['description'] = name
        if desc is not None:
            params['comments'] = desc
        if 'severity' in params:
            params['priority'] = params['severity']
            params.pop("severity")
        if 'priority' in params:
            priority_id = self.PRIORITY_TYPES[params['priority']]
            params['priority'] = priority_id
        if 'enabled' in params:
            if params['enabled']:
                params['status'] = 'enabled'
            else:
                params['status'] = 'disabled'
            params.pop("enabled")
        if 'status' in params:
            status = params['status']
            if status == 'enabled':
                params['status'] = 0
            elif status == 'disabled':
                params['status'] = 1
            else:
                self._module.fail_json(msg="Status must be 'enabled' or 'disabled', got %s" % status)
        if 'generate_multiple_events' in params:
            multiple_event_type = params['generate_multiple_events']
            if multiple_event_type:
                params['type'] = 1
            else:
                params['type'] = 0
        if 'recovery_mode' in params:
            recovery_mode_id = self.RECOVERY_MODES[params['recovery_mode']]
            params['recovery_mode'] = recovery_mode_id
        if 'correlation_mode' in params:
            correlation_mode = params['correlation_mode']
            if correlation_mode == 'all':
                params['correlation_mode'] = 0
            elif correlation_mode == 'tag':
                params['correlation_mode'] = 1
            else:
                self._module.fail_json(msg="correlation_mode must be all or tag, got %s" % correlation_mode)
        if 'manual_close' in params:
            manual_close = params['manual_close']
            if manual_close:
                params['manual_close'] = 1
            else:
                params['manual_close'] = 0
        if dependencies is not None:
            params['dependencies'] = []
            for dependency in dependencies:
                host_name = None
                template_name = None
                if 'host_name' in dependency:
                    host_name = dependency
                elif 'template_name' in dependency:
                    template_name = dependency
                else:
                    self._module.fail_json(msg="Each dependency must contain either the host_name or the template_name")
                triggers = self.get_triggers(dependency['name'], host_name, template_name)
                for trigger in triggers:
                    params['dependencies'].append({'triggerid': trigger['triggerid']})

    def add_trigger(self, params):
        if self._module.check_mode:
            self._module.exit_json(changed=True)
        try:
            results = self._zapi.trigger.create(params)
        except Exception as e:
            self._module.fail_json(msg="Failed to create trigger: %s" % e)
        return results

    def update_trigger(self, params):
        if self._module.check_mode:
            self._module.exit_json(changed=True)
        try:
            results = self._zapi.trigger.update(params)
        except Exception as e:
            self._module.fail_json(msg="Failed to update trigger: %s" % e)
        return results

    def check_trigger_changed(self, old_trigger):
        try:
            new_trigger = self._zapi.trigger.get({"triggerids": "%s" % old_trigger['triggerid']})[0]
        except Exception as e:
            self._module.fail_json(msg="Failed to get trigger: %s" % e)
        return old_trigger != new_trigger

    def delete_trigger(self, trigger_id):
        if self._module.check_mode:
            self._module.exit_json(changed=True)
        try:
            results = self._zapi.trigger.delete(trigger_id)
        except Exception as e:
            self._module.fail_json(msg="Failed to delete trigger: %s" % e)
        return results


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        name=dict(type='str', required=True),
        host_name=dict(type='str', required=False),
        template_name=dict(type='str', required=False),
        params=dict(type='dict', required=False),
        desc=dict(type='str', required=False, aliases=['description']),
        dependencies=dict(type='list', elements='dict', required=False),
        state=dict(type='str', default="present", choices=['present', 'absent']),
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        required_one_of=[
            ['host_name', 'template_name']
        ],
        mutually_exclusive=[
            ['host_name', 'template_name']
        ],
        required_if=[
            ['state', 'present', ['params']]
        ],
        supports_check_mode=True
    )

    name = module.params['name']
    host_name = module.params['host_name']
    template_name = module.params['template_name']
    params = module.params['params']
    desc = module.params['desc']
    dependencies = module.params['dependencies']
    state = module.params['state']

    trigger = Trigger(module)

    if state == "absent":
        triggers = trigger.get_triggers(name, host_name, template_name)
        if len(triggers) == 0:
            module.exit_json(changed=False, result="No trigger to delete.")
        else:
            delete_ids = []
            for t in triggers:
                delete_ids.append(t['triggerid'])
            results = trigger.delete_trigger(delete_ids)
            module.exit_json(changed=True, result=results)

    elif state == "present":
        trigger.sanitize_params(name, params, desc, dependencies)
        triggers = trigger.get_triggers(name, host_name, template_name)
        if 'new_name' in params:
            new_name_trigger = trigger.get_triggers(params['new_name'], host_name, template_name)
            if len(new_name_trigger) > 0:
                module.exit_json(changed=False, result=[{'triggerids': [new_name_trigger[0]['triggerid']]}])
        if len(triggers) == 0:
            if 'new_name' in params:
                module.fail_json('Cannot rename trigger:  %s is not found' % name)
            results = trigger.add_trigger(params)
            module.exit_json(changed=True, result=results)
        else:
            results = []
            changed = False
            for t in triggers:
                params['triggerid'] = t['triggerid']
                params.pop('description')
                if 'new_name' in params:
                    params['description'] = params['new_name']
                    params.pop("new_name")
                results.append(trigger.update_trigger(params))
                changed_trigger = trigger.check_trigger_changed(t)
                if changed_trigger:
                    changed = True
            module.exit_json(changed=changed, result=results)


if __name__ == '__main__':
    main()
