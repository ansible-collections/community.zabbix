#!/usr/bin/python
# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: zabbix_apm_info
short_description: Retrieve APM traces, spans, metrics, and logs
version_added: "5.0.0"
description:
    - Query telemetry data using the Zabbix 8.0 APM APIs.
    - Supports all parameters of C(apmtrace.get), C(apmspan.get), C(apmmetric.get), and C(apmlog.get).
    - Requires a configured telemetry data source and permission to call the selected API method.
author:
    - Manuel Pesenti (@manuello1996)
requirements:
    - "python >= 3.9"
options:
    signal:
        description: Type of telemetry to retrieve.
        type: str
        required: true
        choices: [traces, spans, metrics, logs]
    time_from:
        description: Start of the time window, inclusive, as a Unix timestamp in seconds.
        type: int
        required: true
    time_till:
        description: End of the time window, exclusive, as a Unix timestamp in seconds.
        type: int
        required: true
    traceids:
        description: Trace IDs to retrieve. Supported for traces, spans, and logs.
        type: list
        elements: str
    spanids:
        description: Span IDs to retrieve. Supported for spans and logs.
        type: list
        elements: str
    parent_spanids:
        description: Parent span IDs to retrieve. Supported for spans.
        type: list
        elements: str
    types:
        description: Metric data point types to retrieve. Supported for metrics.
        type: list
        elements: int
    min_duration:
        description: Minimum trace or span duration, inclusive, in nanoseconds.
        type: int
    max_duration:
        description: Maximum trace or span duration, exclusive, in nanoseconds.
        type: int
    with_flags_on:
        description: Require all specified flag bits. Supported for metrics and logs.
        type: int
    with_flags_off:
        description: Exclude all specified flag bits. Supported for metrics and logs.
        type: int
    resource_attributes:
        description: Resource attribute filters, supported for every signal.
        type: list
        elements: dict
        suboptions:
            key:
                description: Attribute name.
                type: str
                required: true
            value:
                description: Attribute value to match. May be omitted for existence operators.
                type: str
                default: ''
            operator:
                description: Comparison (0 contains, 1 equals, 2 does not contain, 3 does not equal, 4 exists, 5 does not exist).
                type: int
                choices: [0, 1, 2, 3, 4, 5]
                default: 0
    resource_attributes_evaltype:
        description: Evaluation of the corresponding attribute filters (0 for And/Or, 2 for Or).
        type: int
        choices: [0, 2]
    span_attributes:
        description: Span attribute filters, supported for traces and spans.
        type: list
        elements: dict
        suboptions:
            key:
                description: Attribute name.
                type: str
                required: true
            value:
                description: Attribute value to match. May be omitted for existence operators.
                type: str
                default: ''
            operator:
                description: Comparison (0 contains, 1 equals, 2 does not contain, 3 does not equal, 4 exists, 5 does not exist).
                type: int
                choices: [0, 1, 2, 3, 4, 5]
                default: 0
    span_attributes_evaltype:
        description: Evaluation of the corresponding attribute filters (0 for And/Or, 2 for Or).
        type: int
        choices: [0, 2]
    scope_attributes:
        description: Scope attribute filters, supported for metrics and logs.
        type: list
        elements: dict
        suboptions:
            key:
                description: Attribute name.
                type: str
                required: true
            value:
                description: Attribute value to match. May be omitted for existence operators.
                type: str
                default: ''
            operator:
                description: Comparison (0 contains, 1 equals, 2 does not contain, 3 does not equal, 4 exists, 5 does not exist).
                type: int
                choices: [0, 1, 2, 3, 4, 5]
                default: 0
    scope_attributes_evaltype:
        description: Evaluation of the corresponding attribute filters (0 for And/Or, 2 for Or).
        type: int
        choices: [0, 2]
    attributes:
        description: Data point attribute filters, supported for metrics.
        type: list
        elements: dict
        suboptions:
            key:
                description: Attribute name.
                type: str
                required: true
            value:
                description: Attribute value to match. May be omitted for existence operators.
                type: str
                default: ''
            operator:
                description: Comparison (0 contains, 1 equals, 2 does not contain, 3 does not equal, 4 exists, 5 does not exist).
                type: int
                choices: [0, 1, 2, 3, 4, 5]
                default: 0
    attributes_evaltype:
        description: Evaluation of the corresponding attribute filters (0 for And/Or, 2 for Or).
        type: int
        choices: [0, 2]
    log_attributes:
        description: Log attribute filters, supported for logs.
        type: list
        elements: dict
        suboptions:
            key:
                description: Attribute name.
                type: str
                required: true
            value:
                description: Attribute value to match. May be omitted for existence operators.
                type: str
                default: ''
            operator:
                description: Comparison (0 contains, 1 equals, 2 does not contain, 3 does not equal, 4 exists, 5 does not exist).
                type: int
                choices: [0, 1, 2, 3, 4, 5]
                default: 0
    log_attributes_evaltype:
        description: Evaluation of the corresponding attribute filters (0 for And/Or, 2 for Or).
        type: int
        choices: [0, 2]
    filter:
        description: Exact property filters. Supported property names depend on the selected signal; values can be scalars or lists.
        type: dict
    search:
        description: Property patterns to search for. Supported property names depend on the selected signal.
        type: dict
    output:
        description: Properties to return. Use C([extend]) to return all properties.
        type: list
        elements: str
        default: [extend]
    sortfield:
        description: Properties to sort by. Supported property names depend on the selected signal.
        type: list
        elements: str
    sortorder:
        description: Sort directions corresponding to O(sortfield).
        type: list
        elements: str
        choices: [ASC, DESC]
    limit:
        description: Maximum number of records to return. Must be greater than zero.
        type: int
    offset:
        description: Number of records to skip. Must not be negative.
        type: int
    count_output:
        description: Return the number of matching records instead of the records themselves.
        type: bool
        default: false
    exclude_search:
        description: Exclude records that match O(search).
        type: bool
    search_by_any:
        description: Match any of the O(search) properties instead of all of them.
        type: bool
    search_wildcards_enabled:
        description: Interpret wildcard characters in O(search) patterns.
        type: bool
    start_search:
        description: Match O(search) patterns from the start of the property value.
        type: bool
extends_documentation_fragment:
    - community.zabbix.zabbix
seealso:
    - name: apmtrace.get
      description: Trace query parameters.
      link: https://www.zabbix.com/documentation/8.0/en/manual/api/reference/apmtrace/get
    - name: apmspan.get
      description: Span query parameters.
      link: https://www.zabbix.com/documentation/8.0/en/manual/api/reference/apmspan/get
    - name: apmmetric.get
      description: Metric query parameters.
      link: https://www.zabbix.com/documentation/8.0/en/manual/api/reference/apmmetric/get
    - name: apmlog.get
      description: Log query parameters.
      link: https://www.zabbix.com/documentation/8.0/en/manual/api/reference/apmlog/get
'''

EXAMPLES = r'''
- name: Retrieve slow traces
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_host: zabbix.example.com
    ansible_user: Admin
    ansible_httpapi_pass: zabbix
  community.zabbix.zabbix_apm_info:
    signal: traces
    time_from: 1794956400
    time_till: 1794960000
    min_duration: 1000000000
    resource_attributes:
      - key: service.name
        value: checkout
        operator: 1
    output: [traceid, span_name, duration]
    limit: 100
  register: slow_traces

- name: Retrieve spans of a trace using an existing httpapi connection
  community.zabbix.zabbix_apm_info:
    signal: spans
    time_from: 1794956400
    time_till: 1794960000
    traceids: ['0123456789abcdef0123456789abcdef']

- name: Retrieve metric data points
  community.zabbix.zabbix_apm_info:
    signal: metrics
    time_from: 1794956400
    time_till: 1794960000
    filter:
      metric_name: http.server.request.duration

- name: Count error logs
  community.zabbix.zabbix_apm_info:
    signal: logs
    time_from: 1794956400
    time_till: 1794960000
    filter:
      severity_text: ERROR
    count_output: true
  register: error_logs

- name: Show the number of matching error logs
  ansible.builtin.debug:
    var: error_logs.zabbix_apm.count
'''

RETURN = r'''
zabbix_apm:
    description: Telemetry query information.
    returned: success
    type: dict
    contains:
        signal:
            description: Queried telemetry signal.
            type: str
            sample: traces
        records:
            description:
                - Retrieved records, preserving their API field names and values.
                - Empty when O(count_output=true). Record properties depend on O(signal) and O(output).
            type: list
            elements: dict
            sample: [{traceid: '0123456789abcdef0123456789abcdef', service_name: checkout, duration: '1000000000'}]
        count:
            description:
                - Number of returned records, after applying pagination.
                - When O(count_output=true), the matching count reported by the API, converted to an integer.
            type: int
            sample: 1
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.compat.version import LooseVersion

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class Apm(ZabbixBase):
    def get_apm(self, signal):
        if LooseVersion(self._zbx_api_version) < LooseVersion("8.0"):
            self._module.fail_json(msg="APM queries require Zabbix 8.0 or newer.")

        params = self._module.params
        # Reject options that belong to another signal before sending the request.
        signal_options = {
            "traceids": ("traces", "spans", "logs"),
            "spanids": ("spans", "logs"),
            "parent_spanids": ("spans",),
            "min_duration": ("traces", "spans"),
            "max_duration": ("traces", "spans"),
            "span_attributes": ("traces", "spans"),
            "span_attributes_evaltype": ("traces", "spans"),
            "types": ("metrics",),
            "with_flags_on": ("metrics", "logs"),
            "with_flags_off": ("metrics", "logs"),
            "scope_attributes": ("metrics", "logs"),
            "scope_attributes_evaltype": ("metrics", "logs"),
            "attributes": ("metrics",),
            "attributes_evaltype": ("metrics",),
            "log_attributes": ("logs",),
            "log_attributes_evaltype": ("logs",),
        }
        for name, signals in signal_options.items():
            if params.get(name) is not None and signal not in signals:
                self._module.fail_json(msg="%s is not supported for signal %s." % (name, signal))

        parameters = {
            "time_from": params["time_from"],
            "time_till": params["time_till"],
            "traceids": params.get("traceids"),
            "spanids": params.get("spanids"),
            "parent_spanids": params.get("parent_spanids"),
            "types": params.get("types"),
            "min_duration": params.get("min_duration"),
            "max_duration": params.get("max_duration"),
            "with_flags_on": params.get("with_flags_on"),
            "with_flags_off": params.get("with_flags_off"),
            "resource_attributes": params.get("resource_attributes"),
            "resource_attributes_evaltype": params.get("resource_attributes_evaltype"),
            "span_attributes": params.get("span_attributes"),
            "span_attributes_evaltype": params.get("span_attributes_evaltype"),
            "scope_attributes": params.get("scope_attributes"),
            "scope_attributes_evaltype": params.get("scope_attributes_evaltype"),
            "attributes": params.get("attributes"),
            "attributes_evaltype": params.get("attributes_evaltype"),
            "log_attributes": params.get("log_attributes"),
            "log_attributes_evaltype": params.get("log_attributes_evaltype"),
            "filter": params.get("filter"),
            "search": params.get("search"),
            "output": "extend" if params["output"] == ["extend"] else params["output"],
            "sortfield": params.get("sortfield"),
            "sortorder": params.get("sortorder"),
            "limit": params.get("limit"),
            "offset": params.get("offset"),
            "countOutput": params.get("count_output", False),
            "excludeSearch": params.get("exclude_search"),
            "searchByAny": params.get("search_by_any"),
            "searchWildcardsEnabled": params.get("search_wildcards_enabled"),
            "startSearch": params.get("start_search"),
        }
        parameters = zabbix_utils.helper_cleanup_data(parameters)
        sections = {"traces": "apmtrace", "spans": "apmspan", "metrics": "apmmetric", "logs": "apmlog"}
        try:
            result = getattr(self._zapi, sections[signal]).get(parameters)
            if params.get("count_output", False):
                return {"signal": signal, "records": [], "count": int(result)}
            return {"signal": signal, "records": result, "count": len(result)}
        except Exception as e:
            self._module.fail_json(msg="Failed to get APM %s information: %s" % (signal, e))


def main():
    attribute_options = dict(
        key=dict(type="str", required=True, no_log=False),
        value=dict(type="str", default=""),
        operator=dict(type="int", choices=[0, 1, 2, 3, 4, 5], default=0),
    )
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        signal=dict(type="str", required=True, choices=["traces", "spans", "metrics", "logs"]),
        time_from=dict(type="int", required=True),
        time_till=dict(type="int", required=True),
        traceids=dict(type="list", elements="str"),
        spanids=dict(type="list", elements="str"),
        parent_spanids=dict(type="list", elements="str"),
        types=dict(type="list", elements="int"),
        min_duration=dict(type="int"),
        max_duration=dict(type="int"),
        with_flags_on=dict(type="int"),
        with_flags_off=dict(type="int"),
        resource_attributes=dict(type="list", elements="dict", options=attribute_options),
        resource_attributes_evaltype=dict(type="int", choices=[0, 2]),
        span_attributes=dict(type="list", elements="dict", options=attribute_options),
        span_attributes_evaltype=dict(type="int", choices=[0, 2]),
        scope_attributes=dict(type="list", elements="dict", options=attribute_options),
        scope_attributes_evaltype=dict(type="int", choices=[0, 2]),
        attributes=dict(type="list", elements="dict", options=attribute_options),
        attributes_evaltype=dict(type="int", choices=[0, 2]),
        log_attributes=dict(type="list", elements="dict", options=attribute_options),
        log_attributes_evaltype=dict(type="int", choices=[0, 2]),
        filter=dict(type="dict"),
        search=dict(type="dict"),
        output=dict(type="list", elements="str", default=["extend"]),
        sortfield=dict(type="list", elements="str"),
        sortorder=dict(type="list", elements="str", choices=["ASC", "DESC"]),
        limit=dict(type="int"),
        offset=dict(type="int"),
        count_output=dict(type="bool", default=False),
        exclude_search=dict(type="bool"),
        search_by_any=dict(type="bool"),
        search_wildcards_enabled=dict(type="bool"),
        start_search=dict(type="bool"),
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    signal = module.params["signal"]
    apm = Apm(module)
    result = apm.get_apm(signal)
    module.exit_json(changed=False, zabbix_apm=result)


if __name__ == '__main__':
    main()
