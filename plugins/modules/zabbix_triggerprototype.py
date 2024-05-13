#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: zabbix_triggerprototype
short_description: Create/delete Zabbix triggerprototypes
description:
   - Create triggerprototypes if they do not exist.
   - Delete existing triggerprototypes if they exist.
author:
    - "Andrew Lathrop (@aplathrop)"
requirements:
    - "python >= 2.6"

options:
    state:
        description:
            - Create or delete trigger prototype.
        required: false
        type: str
        default: "present"
        choices: [ "present", "absent" ]
    name:
        description:
            - Name of trigger prototype to create or delete.
            - Overrides "description" in API docs.
            - Cannot be changed. If a trigger prototype's name needs to be changed, it needs to deleted and recreated
        required: true
        type: str
    host_name:
        description:
            - Name of host to add trigger prototype to.
            - Required when I(template_name) is not used.
            - Mutually exclusive with I(template_name).
        required: false
        type: str
    template_name:
        description:
            - Name of template to add trigger prototype to.
            - Required when I(host_name) is not used.
            - Mutually exclusive with I(host_name).
        required: false
        type: str
    desc:
        description:
            - Additional description of the trigger prototype.
            - Overrides "comments" in API docs.
        required: false
        type: str
        aliases: [ "description" ]
    dependencies:
        description:
            - list of trigger prototypes that this trigger prototype is dependent on
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
            - Parameters to create/update trigger prototype with.
            - Required if state is "present".
            - Parameters as defined at https://www.zabbix.com/documentation/current/en/manual/api/reference/triggerprototype/object
            - Additionally supported parameters are below.
        required: false
        type: dict
        suboptions:
            severity:
                description:
                    - Severity of the trigger prototype.
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
                    - Status of the trigger prototype.
                required: false
                type: str
                choices: [ "enabled", "disabled" ]
            enabled:
                description:
                    - Status of the trigger prototype.
                    - Overrides "status" in API docs.
                required: false
                type: bool
            generate_multiple_events:
                description:
                    - Whether the trigger prototype can generate multiple problem events.
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

# Create trigger prototype on example_host using example_rule
- name: create trigger prototype
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_triggerprototype:
    name: '{% raw %}Free disk space is less than 20% on volume {#FSNAME}{% endraw %}'
    host_name: example_host
    params:
      severity: high
      expression: "{% raw %}last(/example_host/vfs.fs.size[{#FSNAME}, pused])>80{% endraw %}"
      recovery_mode: none
      manual_close: True
      enabled: True
    state: present

# Create trigger prototype on example_template using example_rule
- name: create trigger prototype
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_triggerprototype:
    name: '{% raw %}Free disk space is less than 20% on volume {#FSNAME}{% endraw %}'
    template_name: example_template
    params:
      severity: high
      expression: "{% raw %}last(/example_host/vfs.fs.size[{#FSNAME}, pused])>80{% endraw %}"
      recovery_mode: none
      manual_close: True
      enabled: True
    state: present

# Add tags to the existing Zabbix trigger prototype
- name: update trigger prototype
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_triggerprototype:
    name: '{% raw %}Free disk space is less than 20% on volume {#FSNAME}{% endraw %}'
    template_name: example_template
    params:
      severity: high
      expression: "{% raw %}last(/example_host/vfs.fs.size[{#FSNAME}, pused])>80{% endraw %}"
      recovery_mode: none
      manual_close: True
      enabled: True
      tags:
          - tag: class
            value: application
    state: present

# Delete Zabbix trigger prototype
- name: delete trigger prototype
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_triggerprototype:
    name: '{% raw %}Free disk space is less than 20% on volume {#FSNAME}{% endraw %}'
    template_name: example_template
    state: absent
'''

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class Triggerprototype(ZabbixBase):

    PRIORITY_TYPES = {'not_classified': 0,
                      'information': 1,
                      'warning': 2,
                      'average': 3,
                      'high': 4,
                      'disaster': 5}

    RECOVERY_MODES = {'expression': 0,
                      'recovery_expression': 1,
                      'none': 2}

    def get_triggerprototypes(self, triggerprototype_name, host_name, template_name):
        if host_name is not None:
            host = host_name
        else:
            host = template_name
        triggerprototypes = []
        try:
            triggerprototypes = self._zapi.triggerprototype.get({'filter': {'description': triggerprototype_name, 'host': host}})
        except Exception as e:
            self._module.fail_json(msg="Failed to get triggerprototype: %s" % e)
        return triggerprototypes

    def sanitize_params(self, name, params, desc=None, dependencies=None):
        params['description'] = name
        if desc is not None:
            params['comments'] = desc
        if 'severity' in params:
            params['priority'] = params['severity']
            params.pop('severity')
        if 'priority' in params:
            priority_id = self.PRIORITY_TYPES[params['priority']]
            params['priority'] = priority_id
        if 'enabled' in params:
            if params['enabled']:
                params['status'] = 'enabled'
            else:
                params['status'] = 'disabled'
            params.pop('enabled')
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
                triggers = self.get_triggerprototypes(dependency['name'], host_name, template_name)
                for trigger in triggers:
                    params['dependencies'].append({'triggerid': trigger['triggerid']})

    def add_triggerprototype(self, params):
        if self._module.check_mode:
            self._module.exit_json(changed=True)
        try:
            results = self._zapi.triggerprototype.create(params)
        except Exception as e:
            self._module.fail_json(msg="Failed to create triggerprototype: %s" % e)
        return results

    def update_triggerprototype(self, params):
        if self._module.check_mode:
            self._module.exit_json(changed=True)
        try:
            results = self._zapi.triggerprototype.update(params)
        except Exception as e:
            self._module.fail_json(msg="Failed to update triggerprototype: %s" % e)
        return results

    def check_triggerprototype_changed(self, old_triggerprototype):
        try:
            new_triggerprototype = self._zapi.triggerprototype.get({'triggerids': '%s' % old_triggerprototype['triggerid']})[0]
        except Exception as e:
            self._module.fail_json(msg="Failed to get triggerprototype: %s" % e)
        return old_triggerprototype != new_triggerprototype

    def delete_triggerprototype(self, trigger_id):
        if self._module.check_mode:
            self._module.exit_json(changed=True)
        try:
            results = self._zapi.triggerprototype.delete(trigger_id)
        except Exception as e:
            self._module.fail_json(msg="Failed to delete triggerprototype: %s" % e)
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

    triggerprototype = Triggerprototype(module)

    if state == "absent":
        triggerprototypes = triggerprototype.get_triggerprototypes(name, host_name, template_name)
        if len(triggerprototypes) == 0:
            module.exit_json(changed=False, result="No triggerprototype to delete.")
        else:
            delete_ids = []
            for t in triggerprototypes:
                delete_ids.append(t['triggerid'])
            results = triggerprototype.delete_triggerprototype(delete_ids)
            module.exit_json(changed=True, result=results)

    elif state == "present":
        triggerprototype.sanitize_params(name, params, desc, dependencies)
        triggerprototypes = triggerprototype.get_triggerprototypes(name, host_name, template_name)
        if len(triggerprototypes) == 0:
            results = triggerprototype.add_triggerprototype(params)
            module.exit_json(changed=True, result=results)
        else:
            results = []
            changed = False
            for t in triggerprototypes:
                params['triggerid'] = t['triggerid']
                params.pop('description')
                results.append(triggerprototype.update_triggerprototype(params))
                changed_trigger = triggerprototype.check_triggerprototype_changed(t)
                if changed_trigger:
                    changed = True
            module.exit_json(changed=changed, result=results)


if __name__ == '__main__':
    main()
