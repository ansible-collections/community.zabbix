#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: zabbix_itemprototype
short_description: Create/delete Zabbix item prototypes
description:
   - Create item prototypes if they do not exist.
   - Delete existing item prototypes if they exist.
author:
    - "Andrew Lathrop (@aplathrop)"
requirements:
    - "python >= 2.6"

options:
    state:
        description:
            - Create or delete item prototype.
        required: false
        type: str
        default: "present"
        choices: [ "present", "absent" ]
    name:
        description:
            - Name of item prototype to create or delete.
        required: true
        type: str
    host_name:
        description:
            - Name of host to add item prototype to.
            - Required when I(template_name) is not used.
            - Mutually exclusive with I(template_name).
        required: false
        type: str
    template_name:
        description:
            - Name of template to add item prototype to.
            - Required when I(host_name) is not used.
            - Mutually exclusive with I(host_name).
        required: false
        type: str
    discoveryrule_name:
        description:
            - Name of the LLD rule that the item belongs to.
        required: true
        type: str
    params:
        description:
            - Parameters to create/update item prototype with.
            - Required if state is "present".
            - Parameters as defined at https://www.zabbix.com/documentation/current/en/manual/api/reference/itemprototype/object
            - Additionally supported parameters are below
        required: false
        type: dict
        suboptions:
            key:
                description:
                    - Item prototype key.
                    - Alias for "key_" in API docs
                required: false
                type: str
            interval:
                description:
                    - Update interval of the item prototype.
                    - Alias for "delay" in API docs
                required: false
                type: str
            status:
                description:
                    - Status of the item prototype.
                required: false
                type: str
                choices: [ "enabled", "disabled" ]
            enabled:
                description:
                    - Status of the item prototype.
                    - Overrides "status" in API docs
                required: false
                type: bool
            type:
                description:
                    - Type of the item prototype.
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
            value_type:
                description:
                    - Type of information of the item prototype.
                    - Required if state is "present".
                required: false
                type: str
                choices:
                    - numeric_float
                    - character
                    - log
                    - numeric_unsigned
                    - text
            new_name:
                description:
                    - New name for item
                required: false
                type: str
            master_item:
                description:
                    - item that is the master of the current one
                    - Overrides "master_itemid" in API docs
                required: false
                type: dict
                suboptions:
                    item_name:
                        description:
                          - name of the master item
                        required: true
                        type: str
                    discovery_rule:
                        description:
                          - name of the discovery rule the master item belongs to
                        required: true
                        type: str
                    host_name:
                        description:
                          - name of the host the master item belongs to
                          - Required when I(template_name) is not used.
                          - Mutually exclusive with I(template_name).
                        required: false
                    template_name:
                        description:
                          - name of the template the master item belongs to
                          - Required when I(host_name) is not used.
                          - Mutually exclusive with I(host_name).
            preprocessing:
                description:
                    - Item preprocessing options.
                    - Parameters as defined at
                    - https://www.zabbix.com/documentation/current/en/manual/api/reference/itemprototype/object#item-prototype-preprocessing
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
                            - custom_multiplier
                            - right_trim
                            - left_trim
                            - trim
                            - regular_expressions
                            - regex
                            - boolean_to_decimal
                            - octal_to_decimal
                            - hexadecimal_to_decimal
                            - simple_change
                            - change_per_second
                            - xml_xpath
                            - jsonpath
                            - in_range
                            - matches_regular_expression
                            - matches_regex
                            - does_not_match_regular_expression
                            - not_match_regex
                            - check_for_error_in_json
                            - check_for_json_error
                            - check_for_error_in_xml
                            - check_for_xml_error
                            - check_for_error_using_regular_expression
                            - check_for_error_regex
                            - discard_unchanged
                            - discard_unchanged_with_heartbeat
                            - javascript
                            - prometheus_pattern
                            - prometheus_to_json
                            - csv_to_json
                            - replace
                            - check_unsupported
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

# Create item prototype on example_host using example_rule
- name: create item prototype
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_itemprototype:
    name: '{% raw %}{#FSNAME}:Used space{% endraw %}'
    discoveryrule_name: example_rule
    host_name: example_host
    params:
      type: zabbix_agent
      key: "{% raw %}vfs.fs.size[{#FSNAME},used]{% endraw %}"
      value_type: numeric_unsigned
      interval: 1m
    state: present

# Create item prototype on example_template using example_rule
- name: create item prototype
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_itemprototype:
    name: '{% raw %}{#FSNAME}:Used space{% endraw %}'
    discoveryrule_name: example_rule
    template_name: example_template
    params:
      type: zabbix_agent
      key: "{% raw %}vfs.fs.size[{#FSNAME},used]{% endraw %}"
      value_type: numeric_unsigned
      interval: 1m
    state: present


# Add tags to the existing Zabbix item prototype
- name: update item prototype
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_itemprototype:
    name: '{% raw %}{#FSNAME}:Used space{% endraw %}'
    discoveryrule_name: example_rule
    template_name: example_template
    params:
      type: zabbix_agent
      key: "{% raw %}vfs.fs.size[{#FSNAME},used]{% endraw %}"
      value_type: numeric_unsigned
      interval: 1m
      tags:
          - tag: class
            value: application
    state: present

- name: create dependent item
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_itemprototype:
    name: '{% raw %}{#FSNAME}:example_depend_item_prototype{% endraw %}'
    discoveryrule_name: example_rule
    host_name: example_host
    params:
        type: dependent_item
        key: '{% raw %}vfs.fs.size.half[{#FSNAME}]{% endraw %}'
        value_type: numeric_float
        units: B
        master_item:
          item_name: '{% raw %}{#FSNAME}:example_item_prototype{% endraw %}'
          discoveryrule_name: example_rule
          host_name: example_host
        preprocessing:
          - type: javascript
            params: 'return value / 2;'
            error_handler: zabbix_server
    state: present

- name: Delete Zabbix item prototype
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_itemprototype:
    name: '{% raw %}{#FSNAME}:Used space{% endraw %}'
    discoveryrule_name: example_rule
    template_name: example_template
    state: absent

- name: Rename Zabbix item prototype
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_itemprototype:
    name: '{% raw %}{#FSNAME}:Used space{% endraw %}'
    discoveryrule_name: example_rule
    template_name: example_template
    params:
      new_name: '{% raw %}{#FSNAME}:New Used space{% endraw %}'
    state: present
'''

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class Itemprototype(ZabbixBase):
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

    VALUE_TYPES = {'numeric_float': 0,
                   'character': 1,
                   'log': 2,
                   'numeric_unsigned': 3,
                   'text': 4}

    PREPROCESSING_TYPES = {'custom_multiplier': 1,
                           'right_trim': 2,
                           'left_trim': 3,
                           'trim': 4,
                           'regular_expressions': 5,
                           'regex': 5,
                           'boolean_to_decimal': 6,
                           'octal_to_decimal': 7,
                           'hexadecimal_to_decimal': 8,
                           'simple_change': 9,
                           'change_per_second': 10,
                           'xml_xpath': 11,
                           'jsonpath': 12,
                           'in_range': 13,
                           'matches_regular_expression': 14,
                           'matches_regex': 14,
                           'does_not_match_regular_expression': 15,
                           'not_match_regex': 15,
                           'check_for_error_in_json': 16,
                           'check_for_json_error': 16,
                           'check_for_error_in_xml': 17,
                           'check_for_xml_error': 17,
                           'check_for_error_using_regular_expression': 18,
                           'check_for_error_regex': 18,
                           'discard_unchanged': 19,
                           'discard_unchanged_with_heartbeat': 20,
                           'javascript': 21,
                           'prometheus_pattern': 22,
                           'prometheus_to_json': 23,
                           'csv_to_json': 24,
                           'replace': 25,
                           'check_unsupported': 26,
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

    def get_itemprototypes(self, itemprototype_name, discoveryrule_name, host_name, template_name):
        if host_name is not None:
            host = host_name
        else:
            host = template_name
        discoveryrules = self.get_discoveryrules(discoveryrule_name, host_name, template_name)
        rule_ids = []
        for d in discoveryrules:
            rule_ids.append(d['itemid'])
        itemprototypes = []
        try:
            itemprototypes = self._zapi.itemprototype.get({'filter': {'name': itemprototype_name, 'host': host, 'discoveryids': rule_ids}})
        except Exception as e:
            self._module.fail_json(msg="Failed to get item: %s" % e)
        return itemprototypes

    def sanitize_params(self, name, discoveryrule_name, params, host_name=None, template_name=None):
        params['name'] = name
        if 'key' in params:
            params['key_'] = params['key']
            params.pop("key")
        rules = self.get_discoveryrules(discoveryrule_name, host_name, template_name)
        if len(rules) == 0:
            self._module.fail_json(msg="Failed to get discoveryrule: %s" % discoveryrule_name)
        params['ruleid'] = self.get_discoveryrules(discoveryrule_name, host_name, template_name)[0]['itemid']
        if 'type' in params:
            item_type_int = self.ITEM_TYPES[params['type']]
            params['type'] = item_type_int
        if 'value_type' in params:
            value_type_int = self.VALUE_TYPES[params['value_type']]
            params['value_type'] = value_type_int
        if 'interval' in params:
            params['delay'] = params['interval']
            params.pop("interval")
        if 'enabled' in params:
            params['status'] = params['enabled']
            params.pop('enabled')
        if 'master_item' in params:
            if 'host_name' not in params['master_item']:
                params['master_item']['host_name'] = None
            if 'template_name' not in params['master_item']:
                params['master_item']['template_name'] = None
            master_items = self.get_itemprototypes(params['master_item']['item_name'], params['master_item']['discoveryrule_name'],
                                                   params['master_item']['host_name'], params['master_item']['template_name'])
            if len(master_items) == 0:
                self._module.fail_json(msg="No items with the name %s exist to depend on" % params['master_item']['item_name'])
            params['master_itemid'] = master_items[0]['itemid']
            params.pop('master_item')
        if 'preprocessing' in params:
            for param in params['preprocessing']:
                preprocess_type_int = self.PREPROCESSING_TYPES[param['type']]
                param['type'] = preprocess_type_int
                if 'error_handler' in param:
                    error_handler_int = self.PREPROCESSING_ERROR_HANDLERS[param['error_handler']]
                    param['error_handler'] = error_handler_int

    def add_itemprototype(self, params):
        if self._module.check_mode:
            self._module.exit_json(changed=True)
        try:
            results = self._zapi.itemprototype.create(params)
        except Exception as e:
            self._module.fail_json(msg="Failed to create itemprototype: %s" % e)
        return results

    def update_itemprototype(self, params):
        if self._module.check_mode:
            self._module.exit_json(changed=True)
        try:
            results = self._zapi.itemprototype.update(params)
        except Exception as e:
            self._module.fail_json(msg="Failed to update itemprototype: %s" % e)
        return results

    def check_itemprototype_changed(self, old_itemprototype):
        try:
            new_itemprototype = self._zapi.itemprototype.get({'itemids': '%s' % old_itemprototype['itemid']})[0]
        except Exception as e:
            self._module.fail_json(msg="Failed to get itemprototype: %s" % e)
        return old_itemprototype != new_itemprototype

    def delete_itemprototype(self, itemprototype_id):
        if self._module.check_mode:
            self._module.exit_json(changed=True)
        try:
            results = self._zapi.itemprototype.delete(itemprototype_id)
        except Exception as e:
            self._module.fail_json(msg="Failed to delete itemprototype: %s" % e)
        return results


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        name=dict(type='str', required=True),
        discoveryrule_name=dict(type='str', required=True),
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
    discoveryrule_name = module.params['discoveryrule_name']
    host_name = module.params['host_name']
    template_name = module.params['template_name']
    params = module.params['params']
    state = module.params['state']

    itemprototype = Itemprototype(module)

    if state == "absent":
        itemprototypes = itemprototype.get_itemprototypes(name, discoveryrule_name, host_name, template_name)
        if len(itemprototypes) == 0:
            module.exit_json(changed=False, result="No itemprototype to delete.")
        else:
            delete_ids = []
            for i in itemprototypes:
                delete_ids.append(i['itemid'])
            results = itemprototype.delete_itemprototype(delete_ids)
            module.exit_json(changed=True, result=results)

    elif state == "present":
        itemprototype.sanitize_params(name, discoveryrule_name, params, host_name, template_name)
        itemprototypes = itemprototype.get_itemprototypes(name, discoveryrule_name, host_name, template_name)
        if 'new_name' in params:
            new_name_itemprototype = itemprototype.get_itemprototypes(params['new_name'], discoveryrule_name, host_name, template_name)
            if len(new_name_itemprototype) > 0:
                module.exit_json(changed=False, result=[{'itemids': [new_name_itemprototype[0]['itemid']]}])
        results = []
        if len(itemprototypes) == 0:
            if 'new_name' in params:
                module.fail_json('Cannot rename item prototype:  %s is not found' % name)
            hosts_templates = itemprototype.get_hosts_templates(host_name, template_name)
            for host_template in hosts_templates:
                if 'hostid' in host_template:
                    params['hostid'] = host_template['hostid']
                elif 'templateid' in host_template:
                    params['hostid'] = host_template['templateid']
                else:
                    module.fail_json(msg="host/template did not return id")
                results.append(itemprototype.add_itemprototype(params))
            module.exit_json(changed=True, result=results)
        else:
            changed = False
            params.pop('ruleid')
            for i in itemprototypes:
                params['itemid'] = i['itemid']
                if 'new_name' in params:
                    params['name'] = params['new_name']
                    params.pop("new_name")
                results.append(itemprototype.update_itemprototype(params))
                changed_item = itemprototype.check_itemprototype_changed(i)
                if changed_item:
                    changed = True
            module.exit_json(changed=changed, result=results)


if __name__ == '__main__':
    main()
