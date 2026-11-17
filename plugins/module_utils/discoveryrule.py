# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


class DiscoveryRuleParams(object):
    """Translate the shared LLD rule and LLD rule prototype parameters."""

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
                  'script': 21,
                  'telemetry_query': 24}

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
