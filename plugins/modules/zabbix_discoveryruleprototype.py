#!/usr/bin/python
# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: zabbix_discoveryruleprototype
short_description: Create, update and delete Zabbix LLD rule prototypes
description:
    - Manage low-level discovery rule prototypes on hosts and templates.
    - Requires Zabbix 7.4 or later. Telemetry queries require Zabbix 8.0 or later.
version_added: "5.0.0"
author:
    - Manuel Pesenti (@manuello1996)
requirements:
    - python >= 3.9
options:
    name:
        description:
            - Name of the LLD rule prototype.
        type: str
        required: true
    discoveryrule_name:
        description:
            - Name of the parent LLD rule or LLD rule prototype on the selected host or template.
            - The parent name must identify exactly one rule or prototype.
        type: str
        required: true
    host_name:
        description:
            - Technical name of the host that owns the parent.
            - Specify exactly one of O(host_name) and O(template_name).
        type: str
    template_name:
        description:
            - Technical name of the template that owns the parent.
            - Specify exactly one of O(host_name) and O(template_name).
        type: str
    params:
        description:
            - Properties from the LLD rule prototype API object. Required for O(state=present).
            - The module sets C(name), C(hostid), C(ruleid) and C(itemid).
            - Unlisted properties are passed directly to the API.
            - See U(https://www.zabbix.com/documentation/current/en/manual/api/reference/discoveryruleprototype/object).
        type: dict
        suboptions:
            type:
                description:
                    - Prototype type. Required on creation.
                    - C(telemetry_query) maps to API value 24 and requires Zabbix 8.0 or later.
                type: str
                choices:
                    - zabbix_agent
                    - zabbix_trapper
                    - simple_check
                    - zabbix_internal
                    - zabbix_agent_active
                    - external_check
                    - database_monitor
                    - ipmi_agent
                    - ssh_agent
                    - telnet_agent
                    - jmx_agent
                    - dependent_item
                    - http_agent
                    - snmp_agent
                    - script
                    - browser
                    - nested
                    - telemetry_query
            key:
                description:
                    - Alias for API property C(key_). Required on creation unless C(key_) is supplied.
                    - Must contain an LLD macro.
                type: str
            interval:
                description:
                    - Alias for API property C(delay).
                type: str
            enabled:
                description:
                    - Whether the prototype is enabled. Overrides C(status).
                type: bool
            status:
                description:
                    - Whether the prototype is enabled.
                type: str
                choices: [enabled, disabled]
            new_name:
                description:
                    - New name for an existing prototype.
                type: str
            query:
                description:
                    - Telemetry query API object, passed without conversion.
                    - Required when creating a C(telemetry_query) prototype.
                type: dict
            time_shift:
                description:
                    - Gap between the query range end and the current time, from 0 to 86400 seconds.
                    - Accepts seconds, time suffixes, user macros and LLD macros. Zabbix defaults to C(15s).
                    - Supported for C(telemetry_query) on Zabbix 8.0 or later.
                type: str
            lookback_limit:
                description:
                    - Maximum query lookback period, from 1 to 259200 seconds.
                    - Accepts seconds, time suffixes, user macros and LLD macros. Zabbix defaults to C(10m).
                    - Supported for C(telemetry_query) on Zabbix 8.0 or later.
                type: str
            granularity:
                description:
                    - Query bucket duration, from 1 to 86400 seconds, no greater than C(lookback_limit).
                    - Accepts seconds, time suffixes, user macros and LLD macros. Zabbix defaults to C(15s).
                    - Supported for C(telemetry_query) on Zabbix 8.0 or later.
                type: str
            timeout:
                description:
                    - Polling timeout for supported types, including C(telemetry_query) on Zabbix 8.0 or later.
                    - An empty string uses proxy/global timeout settings.
                type: str
            preprocessing:
                description:
                    - API preprocessing steps, using the same type names as M(community.zabbix.zabbix_discoveryrule).
                type: list
                elements: dict
    state:
        description:
            - Whether the prototype should exist.
        type: str
        choices: [present, absent]
        default: present
extends_documentation_fragment:
    - community.zabbix.zabbix
'''

EXAMPLES = r'''
- name: Create a telemetry query LLD rule prototype (Zabbix >= 8.0)
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_host: zabbix.example.com
    ansible_user: Admin
    ansible_httpapi_pass: "{{ zabbix_password }}"
  community.zabbix.zabbix_discoveryruleprototype:
    name: !unsafe 'Discover telemetry for {#SERVICE}'
    discoveryrule_name: Discover services
    template_name: Telemetry services
    params:
      type: telemetry_query
      key: !unsafe 'telemetry.discovery[{#SERVICE}]'
      interval: 1m
      query:
        signal_type: 0
        columns:
          - column: ResourceAttributes
            attribute_key: service.name
        aggregated_columns:
          - function: 4
            alias: record_count
        filter:
          evaltype: 0
          conditions:
            - column: ResourceAttributes
              attribute_key: service.name
              operator: 0
              value: !unsafe '{#SERVICE}'
      time_shift: 15s
      lookback_limit: 10m
      granularity: 15s

- name: Delete a prototype
  community.zabbix.zabbix_discoveryruleprototype:
    name: !unsafe 'Discover telemetry for {#SERVICE}'
    discoveryrule_name: Discover services
    template_name: Telemetry services
    state: absent
'''

RETURN = r'''
result:
    description: IDs of the affected prototypes, or an empty dictionary when an absent prototype does not exist.
    returned: success
    type: dict
    sample: {"itemids": ["12345"]}
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.compat.version import LooseVersion

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
from ansible_collections.community.zabbix.plugins.module_utils.discoveryrule import DiscoveryRuleParams
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class DiscoveryrulePrototype(DiscoveryRuleParams, ZabbixBase):
    ITEM_TYPES = dict((key, value) for key, value in DiscoveryRuleParams.ITEM_TYPES.items() if value not in (9, 15, 17))
    ITEM_TYPES.update(browser=22, nested=23)

    def get_parent(self, name, host):
        try:
            options = {'output': ['itemid', 'hostid'], 'filter': {'name': name, 'host': host}}
            parents = self._zapi.discoveryrule.get(options) + self._zapi.discoveryruleprototype.get(options)
        except Exception as e:
            self._module.fail_json(msg="Failed to get parent LLD rule: %s" % e)
        if len(parents) > 1:
            self._module.fail_json(msg="Parent LLD rule name '%s' is ambiguous on '%s'" % (name, host))
        return parents[0] if parents else None

    def get_prototypes(self, name, parent):
        try:
            return self._zapi.discoveryruleprototype.get({
                'output': 'extend', 'discoveryids': parent['itemid'], 'filter': {'name': name},
                'selectPreprocessing': 'extend', 'selectFilter': 'extend',
                'selectLLDMacroPaths': 'extend', 'selectOverrides': 'extend',
            })
        except Exception as e:
            self._module.fail_json(msg="Failed to get LLD rule prototypes: %s" % e)

    @staticmethod
    def matches(expected, existing, field=None):
        if isinstance(expected, dict):
            return isinstance(existing, dict) and all(
                key in existing and DiscoveryrulePrototype.matches(value, existing[key], key) for key, value in expected.items()
            )
        if isinstance(expected, list):
            if not isinstance(existing, list) or len(expected) != len(existing):
                return False
            if field == 'conditions':
                # The API sorts filter conditions independently of the submitted order.
                remaining = list(existing)
                for value in expected:
                    index = next((i for i, current in enumerate(remaining) if DiscoveryrulePrototype.matches(value, current)), None)
                    if index is None:
                        return False
                    remaining.pop(index)
                return True
            return all(
                DiscoveryrulePrototype.matches(value, current) for value, current in zip(expected, existing)
            )
        return str(expected) == str(existing)

    def apply(self, name, parent, params, state):
        existing = self.get_prototypes(name, parent)
        if len(existing) > 1:
            self._module.fail_json(msg="LLD rule prototype name '%s' is ambiguous under the parent" % name)
        if state == 'absent':
            if not existing:
                self._module.exit_json(changed=False, result={})
            ids = [existing[0]['itemid']]
            result = {'itemids': ids}
            if not self._module.check_mode:
                result = self.call_api('delete', ids)
            self._module.exit_json(changed=True, result=result)

        if params.get('type') == 'telemetry_query' and LooseVersion(self._zbx_api_version) < LooseVersion('8.0'):
            self._module.fail_json(msg="Telemetry query LLD rule prototypes require Zabbix 8.0 or later")
        if params.get('type') is not None and params['type'] not in self.ITEM_TYPES:
            self._module.fail_json(msg="Unknown LLD rule prototype type '%s'" % params['type'])
        self.sanitize_params(name, params)
        for key in ('hostid', 'ruleid', 'itemid'):
            params.pop(key, None)
        new_name = params.pop('new_name', None)
        if new_name and not existing:
            existing = self.get_prototypes(new_name, parent)
            if len(existing) > 1:
                self._module.fail_json(msg="LLD rule prototype name '%s' is ambiguous under the parent" % new_name)
        if not existing:
            if new_name:
                self._module.fail_json(msg="Cannot rename LLD rule prototype '%s': not found" % name)
            if 'type' not in params or 'key_' not in params:
                self._module.fail_json(msg="Creating an LLD rule prototype requires params.type and params.key or params.key_")
            if params['type'] == 24 and 'query' not in params:
                self._module.fail_json(msg="Creating a telemetry query LLD rule prototype requires params.query")
            params.update(hostid=parent['hostid'], ruleid=parent['itemid'])
            result = {} if self._module.check_mode else self.call_api('create', params)
            self._module.exit_json(changed=True, result=result)

        if new_name:
            params['name'] = new_name
        changes = {key: value for key, value in params.items() if not self.matches(value, existing[0].get(key))}
        result = {'itemids': [existing[0]['itemid']]}
        if changes and not self._module.check_mode:
            changes['itemid'] = existing[0]['itemid']
            result = self.call_api('update', changes)
        self._module.exit_json(changed=bool(changes), result=result)

    def call_api(self, method, params):
        try:
            return getattr(self._zapi.discoveryruleprototype, method)(params)
        except Exception as e:
            self._module.fail_json(msg="Failed to %s LLD rule prototype: %s" % (method, e))


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(
        name=dict(type='str', required=True),
        discoveryrule_name=dict(type='str', required=True),
        host_name=dict(type='str'),
        template_name=dict(type='str'),
        params=dict(type='dict'),
        state=dict(type='str', default='present', choices=['present', 'absent']),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        required_one_of=[['host_name', 'template_name']],
        mutually_exclusive=[['host_name', 'template_name']],
        required_if=[['state', 'present', ['params']]],
        supports_check_mode=True,
    )
    prototype = DiscoveryrulePrototype(module)
    if LooseVersion(prototype._zbx_api_version) < LooseVersion('7.4'):
        module.fail_json(msg="LLD rule prototypes require Zabbix 7.4 or later")
    parent = prototype.get_parent(
        module.params['discoveryrule_name'], module.params['host_name'] or module.params['template_name'],
    )
    if parent is None:
        if module.params['state'] == 'absent':
            module.exit_json(changed=False, result={})
        module.fail_json(msg="Parent LLD rule '%s' was not found" % module.params['discoveryrule_name'])
    prototype.apply(module.params['name'], parent, module.params['params'], module.params['state'])


if __name__ == '__main__':
    main()
