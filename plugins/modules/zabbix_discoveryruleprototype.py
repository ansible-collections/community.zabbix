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
            - Only supplied properties are managed. Omitted properties retain their existing values or API defaults.
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
                    - LLD rule prototype key. Required on creation.
                    - Must contain an LLD macro.
                type: str
                aliases: [key_]
            interval:
                description:
                    - Update interval of the prototype.
                type: str
                aliases: [delay]
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
                suboptions:
                    type:
                        description:
                            - Preprocessing step type.
                        type: str
                        required: true
                        choices:
                            - regex
                            - xml_xpath
                            - jsonpath
                            - does_not_match_regular_expression
                            - not_match_regex
                            - check_for_error_in_json
                            - check_for_json_error
                            - check_for_error_in_xml
                            - check_for_xml_error
                            - discard_unchanged_with_heartbeat
                            - javascript
                            - prometheus_to_json
                            - csv_to_json
                            - replace
                            - xml_to_json
                            - snmp_walk_value
                            - snmp_walk_to_json
                    params:
                        description:
                            - Step parameters, separated by newlines when multiple parameters are required.
                        type: str
                    error_handler:
                        description:
                            - Action on preprocessing failure.
                        type: str
                        choices: [zabbix_server, discard, set_custom_value, set_custom_error_message]
                    error_handler_params:
                        description:
                            - Custom value or error message for the error handler.
                        type: str
            password:
                description:
                    - Password for the prototype's authentication method. Redacted from module output.
                type: str
            ssl_key_password:
                description:
                    - Password for the SSL private key. Redacted from module output.
                type: str
            username:
                description:
                    - User name for the prototype's authentication method.
                type: str
            publickey:
                description:
                    - SSH public key file name.
                type: str
            privatekey:
                description:
                    - SSH private key file name.
                type: str
            authtype:
                description:
                    - API authentication method. SSH accepts 0 (password) or 1 (public key).
                    - HTTP accepts 0 (none), 1 (basic) or 2 (NTLM).
                type: int
                choices: [0, 1, 2]
            params:
                description:
                    - Executed script or SQL query, depending on the prototype type.
                type: str
            parameters:
                description:
                    - Named script or browser parameters. Their order is ignored when comparing existing settings.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Unique parameter name.
                        type: str
                        required: true
                    value:
                        description:
                            - Parameter value.
                        type: str
                        required: true
            lld_macro_paths:
                description:
                    - LLD macro paths. Their order is ignored when comparing existing settings.
                type: list
                elements: dict
                suboptions:
                    lld_macro:
                        description:
                            - LLD macro name.
                        type: str
                        required: true
                    path:
                        description:
                            - JSONPath used to extract the macro value.
                        type: str
                        required: true
            filter:
                description:
                    - LLD filter API object, including its evaluation method and conditions.
                type: dict
            overrides:
                description:
                    - LLD override API objects.
                type: list
                elements: dict
            description:
                description:
                    - Description of the prototype.
                type: str
            interfaceid:
                description:
                    - Host interface ID, required for host prototypes whose type requires an interface.
                type: str
            master_itemid:
                description:
                    - Master item ID for a dependent prototype.
                type: str
            snmp_oid:
                description:
                    - SNMP object ID for an SNMP prototype.
                type: str
            ipmi_sensor:
                description:
                    - IPMI sensor for an IPMI prototype.
                type: str
            jmx_endpoint:
                description:
                    - JMX endpoint for a JMX prototype.
                type: str
            trapper_hosts:
                description:
                    - Hosts allowed to send data to a trapper prototype.
                type: str
            url:
                description:
                    - URL for an HTTP agent prototype.
                type: str
            http_proxy:
                description:
                    - HTTP proxy connection string.
                type: str
            headers:
                description:
                    - HTTP request headers. Header values are redacted from module output.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Header name.
                        type: str
                        required: true
                    value:
                        description:
                            - Header value.
                        type: str
                        required: true
            query_fields:
                description:
                    - HTTP query fields, in request order.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Query field name.
                        type: str
                        required: true
                    value:
                        description:
                            - Query field value.
                        type: str
                        required: true
            posts:
                description:
                    - HTTP request body.
                type: str
            post_type:
                description:
                    - HTTP request body format, using 0 for raw, 2 for JSON or 3 for XML.
                type: int
                choices: [0, 2, 3]
            status_codes:
                description:
                    - Accepted HTTP status codes and ranges, separated by commas.
                type: str
            follow_redirects:
                description:
                    - Whether to follow HTTP redirects, using API values 0 (disabled) or 1 (enabled).
                type: int
                choices: [0, 1]
            retrieve_mode:
                description:
                    - HTTP response content, using 0 for body, 1 for headers or 2 for both.
                type: int
                choices: [0, 1, 2]
            request_method:
                description:
                    - HTTP method, using 0 for GET, 1 for POST, 2 for PUT or 3 for HEAD.
                type: int
                choices: [0, 1, 2, 3]
            output_format:
                description:
                    - HTTP response format, using 0 for raw or 1 for JSON.
                type: int
                choices: [0, 1]
            allow_traps:
                description:
                    - Whether to accept incoming HTTP agent data, using API values 0 (disabled) or 1 (enabled).
                type: int
                choices: [0, 1]
            ssl_cert_file:
                description:
                    - SSL certificate file path.
                type: str
            ssl_key_file:
                description:
                    - SSL private key file path.
                type: str
            verify_peer:
                description:
                    - Whether to verify the SSL certificate, using API values 0 (disabled) or 1 (enabled).
                type: int
                choices: [0, 1]
            verify_host:
                description:
                    - Whether to verify the SSL host name, using API values 0 (disabled) or 1 (enabled).
                type: int
                choices: [0, 1]
            lifetime_type:
                description:
                    - Lost resource deletion policy, using 0 for after a period, 1 for never or 2 for immediately.
                type: int
                choices: [0, 1, 2]
            lifetime:
                description:
                    - Period before deleting lost resources when O(params.lifetime_type=0).
                type: str
            enabled_lifetime_type:
                description:
                    - Lost resource disabling policy, using 0 for after a period, 1 for never or 2 for immediately.
                type: int
                choices: [0, 1, 2]
            enabled_lifetime:
                description:
                    - Period before disabling lost resources when O(params.enabled_lifetime_type=0).
                type: str
            discover:
                description:
                    - Whether to discover the prototype, using API values 0 (discover) or 1 (do not discover).
                type: int
                choices: [0, 1]
            uuid:
                description:
                    - UUID for a template prototype. Generated by Zabbix when omitted.
                type: str
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
            if (field in ('conditions', 'lld_macro_paths')
                    or (field == 'parameters' and all(isinstance(value, dict) for value in expected))):
                # Filter conditions, named parameters and macro paths have no meaningful order.
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

        params = zabbix_utils.helper_cleanup_data(params)
        self.sanitize_params(name, params)
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
        changes = {key: value for key, value in params.items() if not self.matches(value, existing[0].get(key), key)}
        result = {'itemids': [existing[0]['itemid']]}
        if changes and not self._module.check_mode:
            changes['itemid'] = existing[0]['itemid']
            result = self.call_api('update', changes)
        self._module.exit_json(changed=bool(changes), result=result)

    def call_api(self, method, params):
        if method != 'delete':
            params = {key: params[key] for key in (
                'name', 'hostid', 'ruleid', 'itemid', 'type', 'key_', 'delay', 'status',
                'query', 'time_shift', 'lookback_limit', 'granularity', 'timeout', 'preprocessing',
                'password', 'ssl_key_password', 'username', 'publickey', 'privatekey', 'authtype',
                'params', 'parameters', 'lld_macro_paths', 'filter', 'overrides', 'description',
                'interfaceid', 'master_itemid', 'snmp_oid', 'ipmi_sensor', 'jmx_endpoint', 'trapper_hosts',
                'url', 'http_proxy', 'headers', 'query_fields', 'posts', 'post_type', 'status_codes',
                'follow_redirects', 'retrieve_mode', 'request_method', 'output_format', 'allow_traps',
                'ssl_cert_file', 'ssl_key_file', 'verify_peer', 'verify_host', 'lifetime_type', 'lifetime',
                'enabled_lifetime_type', 'enabled_lifetime', 'discover', 'uuid',
            ) if key in params}
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
        params=dict(type='dict', options=dict(
            type=dict(type='str', choices=list(DiscoveryrulePrototype.ITEM_TYPES)),
            key=dict(type='str', aliases=['key_']),
            interval=dict(type='str', aliases=['delay']),
            enabled=dict(type='bool'),
            status=dict(type='str', choices=['enabled', 'disabled']),
            new_name=dict(type='str'),
            query=dict(type='dict'),
            time_shift=dict(type='str'),
            lookback_limit=dict(type='str'),
            granularity=dict(type='str'),
            timeout=dict(type='str'),
            preprocessing=dict(type='list', elements='dict', options=dict(
                type=dict(type='str', required=True, choices=list(DiscoveryRuleParams.PREPROCESSING_TYPES)),
                params=dict(type='str'),
                error_handler=dict(type='str', choices=list(DiscoveryRuleParams.PREPROCESSING_ERROR_HANDLERS)),
                error_handler_params=dict(type='str'),
            )),
            password=dict(type='str', no_log=True),
            ssl_key_password=dict(type='str', no_log=True),
            username=dict(type='str'),
            publickey=dict(type='str'),
            privatekey=dict(type='str'),
            authtype=dict(type='int', choices=[0, 1, 2]),
            params=dict(type='str'),
            parameters=dict(type='list', elements='dict', options=dict(
                name=dict(type='str', required=True),
                value=dict(type='str', required=True),
            )),
            lld_macro_paths=dict(type='list', elements='dict', options=dict(
                lld_macro=dict(type='str', required=True),
                path=dict(type='str', required=True),
            )),
            filter=dict(type='dict'),
            overrides=dict(type='list', elements='dict'),
            description=dict(type='str'),
            interfaceid=dict(type='str'),
            master_itemid=dict(type='str'),
            snmp_oid=dict(type='str'),
            ipmi_sensor=dict(type='str'),
            jmx_endpoint=dict(type='str'),
            trapper_hosts=dict(type='str'),
            url=dict(type='str'),
            http_proxy=dict(type='str'),
            headers=dict(type='list', elements='dict', options=dict(
                name=dict(type='str', required=True),
                value=dict(type='str', required=True, no_log=True),
            )),
            query_fields=dict(type='list', elements='dict', options=dict(
                name=dict(type='str', required=True),
                value=dict(type='str', required=True),
            )),
            posts=dict(type='str'),
            post_type=dict(type='int', choices=[0, 2, 3]),
            status_codes=dict(type='str'),
            follow_redirects=dict(type='int', choices=[0, 1]),
            retrieve_mode=dict(type='int', choices=[0, 1, 2]),
            request_method=dict(type='int', choices=[0, 1, 2, 3]),
            output_format=dict(type='int', choices=[0, 1]),
            allow_traps=dict(type='int', choices=[0, 1]),
            ssl_cert_file=dict(type='str'),
            ssl_key_file=dict(type='str'),
            verify_peer=dict(type='int', choices=[0, 1]),
            verify_host=dict(type='int', choices=[0, 1]),
            lifetime_type=dict(type='int', choices=[0, 1, 2]),
            lifetime=dict(type='str'),
            enabled_lifetime_type=dict(type='int', choices=[0, 1, 2]),
            enabled_lifetime=dict(type='str'),
            discover=dict(type='int', choices=[0, 1]),
            uuid=dict(type='str'),
        )),
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
