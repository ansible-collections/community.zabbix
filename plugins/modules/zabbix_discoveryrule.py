#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: zabbix_discoveryrule
short_description: Create/delete Zabbix low-level discovery (LLD) rules
description:
   - Create discoveryrules if they do not exist.
   - Delete existing discoveryrules if they exist.
author:
    - "Andrew Lathrop (@aplathrop)"
requirements:
    - "python >= 2.6"

options:
    state:
        description:
            - Create or delete discovery rule.
        required: false
        type: str
        default: "present"
        choices: [ "present", "absent" ]
    name:
        description:
            - Name of discovery rule to create or delete.
        required: true
        type: str
    host_name:
        description:
            - Name of host to add discovery rule to.
            - Required when I(template_name) is not used.
            - Mutually exclusive with I(template_name).
        required: false
        type: str
    template_name:
        description:
            - Name of template to add discovery rule to.
            - Required when I(host_name) is not used.
            - Mutually exclusive with I(host_name).
        required: false
        type: str
    params:
        description:
            - Parameters to create/update discovery rule with.
            - Required if state is "present".
            - Parameters as defined at https://www.zabbix.com/documentation/current/en/manual/api/reference/discoveryrule/object
            - Additionally supported parameters are below
        required: false
        type: dict
        suboptions:
            key:
                description:
                    - LLD rule key.
                    - Alias for "key_" in API docs
                required: false
                type: str
            interval:
                description:
                    - Update interval of the LLD rule.
                    - Alias for "delay" in API docs
                required: false
                type: str
            status:
                description:
                    - Status of the LLD rule.
                required: false
                type: str
                choices: [ "enabled", "disabled" ]
            enabled:
                description:
                    - Status of the LLD rule.
                    - Overrides "status" in API docs
                required: false
                type: bool
            type:
                description:
                    - Type of the LLD rule.
                    - C(telemetry_query) (API value 24) requires Zabbix 8.0 or later.
                    - Required if state is "present".
                required: false
                type: str
                choices:
                    - zabbix_agent
                    - zabbix_trapper
                    - simple_check
                    - zabbix_internal
                    - zabbix_agent_active
                    - web_item
                    - external_check
                    - database_monitor
                    - ipmi_agent
                    - ssh_agent
                    - telnet_agent
                    - calculated
                    - jmx_agent
                    - snmp_trap
                    - dependent_item
                    - http_agent
                    - snmp_agent
                    - script
                    - telemetry_query
            query:
                description:
                    - Telemetry query configuration, passed as an API object without conversion.
                    - Required when creating a C(telemetry_query) rule on Zabbix 8.0 or later.
                    - See U(https://www.zabbix.com/documentation/current/en/manual/api/reference/discoveryrule/object#telemetry-query).
                type: dict
            time_shift:
                description:
                    - Minimum gap between the query range end and the current time, from 0 to 86400 seconds.
                    - Accepts seconds, time suffixes or user macros. Zabbix defaults to C(15s).
                    - Supported for C(telemetry_query) on Zabbix 8.0 or later.
                type: str
            lookback_limit:
                description:
                    - Maximum query lookback period, from 1 to 259200 seconds.
                    - Accepts seconds, time suffixes or user macros. Zabbix defaults to C(10m).
                    - Supported for C(telemetry_query) on Zabbix 8.0 or later.
                type: str
            granularity:
                description:
                    - Query bucket duration, from 1 to 86400 seconds, no greater than C(lookback_limit).
                    - Accepts seconds, time suffixes or user macros. Zabbix defaults to C(15s).
                    - Supported for C(telemetry_query) on Zabbix 8.0 or later.
                type: str
            timeout:
                description:
                    - Polling timeout for rule types that support it, including C(telemetry_query) on Zabbix 8.0 or later.
                    - Accepts seconds, time suffixes or user macros. An empty string uses proxy/global timeout settings.
                    - If the proxy or proxy group is inaccessible, Zabbix 8.0 uses the global timeout.
                type: str
            new_name:
                description:
                    - New name for LLD rule.
                required: false
                type: str
            preprocessing:
                description:
                    - discovery rules preprocessing options.
                    - Parameters as defined at https://www.zabbix.com/documentation/current/en/manual/api/reference/discoveryrule/object#lld-rule-preprocessing
                    - Additionally supported parameters are below
                required: false
                type: list
                elements: dict
                suboptions:
                    type:
                        description:
                            - The preprocessing option type.
                        required: true
                        type: str
                        choices:
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
                    error_handler:
                        description:
                            - Action type used in case of preprocessing step failure.
                        required: false
                        type: str
                        choices:
                            - zabbix_server
                            - discard
                            - set_custom_value
                            - set_custom_error_message

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

# Create LLD rule on example_host
- name: create rule
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_discoveryrule:
    name: mounted_filesystem_discovery
    host_name: example_host
    params:
        type: zabbix_agent
        key: 'vfs.fs.discovery'
        interval: 1h
        enabled: True
    state: present

# Create LLD rule on example_template
- name: create rule
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_discoveryrule:
    name: mounted_filesystem_discovery
    template_name: example_template
    params:
        type: zabbix_agent
        key: 'vfs.fs.discovery'
        interval: 1h
        enabled: True
    state: present

# Change interval for existing Zabbix LLD rule
- name: update rule
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_discoveryrule:
    name: mounted_filesystem_discovery
    template_name: example_template
    params:
        interval: 2h
    state: present

- name: Create a telemetry query LLD rule (Zabbix >= 8.0)
  community.zabbix.zabbix_discoveryrule:
    name: Discover telemetry services
    host_name: example_host
    params:
      type: telemetry_query
      key: telemetry.services.discovery
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
          conditions: []
      time_shift: 15s
      lookback_limit: 10m
      granularity: 15s

# Delete LLD rule
- name: delete rule
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_discoveryrule:
    name: mounted_filesystem_discovery
    template_name: example_template
    state: absent

- name: Rename Zabbix LLD rule
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_discoveryrule:
    name: mounted_filesystem_discovery
    template_name: example_template
    params:
      new_name: new_mounted_filesystem_discovery
    state: present
'''

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
from ansible_collections.community.zabbix.plugins.module_utils.discoveryrule import DiscoveryRuleParams
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class Discoveryrule(DiscoveryRuleParams, ZabbixBase):
    def get_hosts_templates(self, host_name, template_name):
        if host_name is not None:
            try:
                return self._zapi.host.get({"filter": {"host": host_name}})
            except Exception as e:
                self._module.fail_json(msg="Failed to get host: %s" % e)
        else:
            try:
                return self._zapi.template.get({"filter": {"host": template_name}})
            except Exception as e:
                self._module.fail_json(msg="Failed to get template: %s" % e)

    def get_discoveryrules(self, discoveryrule_name, host_name, template_name):
        if host_name is not None:
            host = host_name
        else:
            host = template_name
        discoveryrules = []
        try:
            discoveryrules = self._zapi.discoveryrule.get({'filter': {'name': discoveryrule_name, 'host': host}})
        except Exception as e:
            self._module.fail_json(msg="Failed to get discovery rules: %s" % e)
        return discoveryrules

    def add_discoveryrule(self, params):
        if self._module.check_mode:
            self._module.exit_json(changed=True)
        try:
            results = self._zapi.discoveryrule.create(params)
        except Exception as e:
            self._module.fail_json(msg="Failed to create discoveryrule: %s" % e)
        return results

    def update_discoveryrule(self, params):
        if self._module.check_mode:
            self._module.exit_json(changed=True)
        try:
            results = self._zapi.discoveryrule.update(params)
        except Exception as e:
            self._module.fail_json(msg="Failed to update discoveryrule: %s" % e)
        return results

    def check_discoveryrule_changed(self, old_discoveryrule):
        try:
            new_discoveryrule = self._zapi.discoveryrule.get({'itemids': "%s" % old_discoveryrule['itemid']})[0]
        except Exception as e:
            self._module.fail_json(msg="Failed to get discoveryrule: %s" % e)
        return old_discoveryrule != new_discoveryrule

    def delete_discoveryrule(self, discoveryrule_id):
        if self._module.check_mode:
            self._module.exit_json(changed=True)
        try:
            results = self._zapi.discoveryrule.delete(discoveryrule_id)
        except Exception as e:
            self._module.fail_json(msg="Failed to delete discoveryrule: %s" % e)
        return results


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        name=dict(type='str', required=True),
        host_name=dict(type='str', required=False),
        template_name=dict(type='str', required=False),
        params=dict(type='dict', required=False),
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
    state = module.params['state']

    discoveryrule = Discoveryrule(module)

    if state == "absent":
        discoveryrules = discoveryrule.get_discoveryrules(name, host_name, template_name)
        if len(discoveryrules) == 0:
            module.exit_json(changed=False, result="No discoveryrule to delete.")
        else:
            delete_ids = []
            for d in discoveryrules:
                delete_ids.append(d['itemid'])
            results = discoveryrule.delete_discoveryrule(delete_ids)
            module.exit_json(changed=True, result=results)

    elif state == "present":
        discoveryrule.sanitize_params(name, params)
        discoveryrules = discoveryrule.get_discoveryrules(name, host_name, template_name)
        if 'new_name' in params:
            new_name_discoveryrule = discoveryrule.get_discoveryrules(params['new_name'], host_name, template_name)
            if len(new_name_discoveryrule) > 0:
                module.exit_json(changed=False, result=[{'itemids': [new_name_discoveryrule[0]['itemid']]}])
        results = []
        if len(discoveryrules) == 0:
            if 'new_name' in params:
                module.fail_json('Cannot rename discoveryrule:  %s is not found' % name)
            hosts_templates = discoveryrule.get_hosts_templates(host_name, template_name)
            for host_template in hosts_templates:
                if 'hostid' in host_template:
                    params['hostid'] = host_template['hostid']
                elif 'templateid' in host_template:
                    params['hostid'] = host_template['templateid']
                else:
                    module.fail_json(msg="host/template did not return id")
                results.append(discoveryrule.add_discoveryrule(params))
            module.exit_json(changed=True, result=results)
        else:
            changed = False
            for d in discoveryrules:
                params['itemid'] = d['itemid']
                if 'new_name' in params:
                    params['name'] = params['new_name']
                    params.pop("new_name")
                results.append(discoveryrule.update_discoveryrule(params))
                changed_rule = discoveryrule.check_discoveryrule_changed(d)
                if changed_rule:
                    changed = True
            module.exit_json(changed=changed, result=results)


if __name__ == '__main__':
    main()
