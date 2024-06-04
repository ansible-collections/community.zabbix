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
'''

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class Discoveryrule(ZabbixBase):
    ITEM_TYPES = {'zabbix_agent': 0,
                  'zabbix_trapper': 2,
                  'simple_check': 3,
                  'zabbix_internal': 5,
                  'zabbix_agent_active': 7,
                  'web_item': 9,
                  'external_check': 10,
                  'database_monitor': 11,
                  'ipmi_agent': 12,
                  'ssh_agent': 13,
                  'telnet_agent': 14,
                  'calculated': 15,
                  'jmx_agent': 16,
                  'snmp_trap': 17,
                  'dependent_item': 18,
                  'http_agent': 19,
                  'snmp_agent': 20,
                  'script': 21}

    PREPROCESSING_TYPES = {'regex': 5,
                           'xml_xpath': 11,
                           'jsonpath': 12,
                           'does_not_match_regular_expression': 15,
                           'not_match_regex': 15,
                           'check_for_error_in_json': 16,
                           'check_for_json_error': 16,
                           'check_for_error_in_xml': 17,
                           'check_for_xml_error': 17,
                           'discard_unchanged_with_heartbeat': 20,
                           'javascript': 21,
                           'prometheus_to_json': 23,
                           'csv_to_json': 24,
                           'replace': 25,
                           'xml_to_json': 27,
                           'snmp_walk_value': 28,
                           'snmp_walk_to_json': 29}

    PREPROCESSING_ERROR_HANDLERS = {'zabbix_server': 0,
                                    'discard': 1,
                                    'set_custom_value': 2,
                                    'set_custom_error_message': 3}

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

    def sanitize_params(self, name, params):
        params['name'] = name
        if 'key' in params:
            params['key_'] = params['key']
            params.pop("key")
        if 'type' in params:
            item_type_int = self.ITEM_TYPES[params['type']]
            params['type'] = item_type_int
        if 'interval' in params:
            params['delay'] = params['interval']
            params.pop("interval")
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
        if 'preprocessing' in params:
            for param in params['preprocessing']:
                preprocess_type_int = self.PREPROCESSING_TYPES[param['type']]
                param['type'] = preprocess_type_int
                if 'error_handler' in param:
                    error_handler_int = self.PREPROCESSING_ERROR_HANDLERS[param['error_handler']]
                    param['error_handler'] = error_handler_int

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
        results = []
        if len(discoveryrules) == 0:
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
                results.append(discoveryrule.update_discoveryrule(params))
                changed_rule = discoveryrule.check_discoveryrule_changed(d)
                if changed_rule:
                    changed = True
            module.exit_json(changed=changed, result=results)


if __name__ == '__main__':
    main()
