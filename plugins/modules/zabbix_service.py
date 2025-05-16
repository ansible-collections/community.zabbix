#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2019, OVH SAS
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: zabbix_service
short_description: Create/update/delete Zabbix service
description:
    - Create/update/delete Zabbix service.
author:
    - "Emmanuel Riviere (@emriver)"
    - "Evgeny Yurchenko (@BGmot)"
requirements:
    - "python >= 3.9"
options:
    name:
        description:
            - Name of Zabbix service
        required: true
        type: str
    algorithm:
        description:
            - Status calculation rule. Only applicable if child services exists.
            - " - C(status_to_ok), set status to OK with"
            - " - C(most_crit_if_all_children), most critical if all children have problems"
            - " - C(most_crit_of_child_serv), most critical of child services with"
        required: false
        type: str
        choices: ["status_to_ok", "most_crit_if_all_children", "most_crit_of_child_serv"]
        default: status_to_ok
    state:
        description:
            - "State: present - create/update service; absent - delete service."
        required: false
        choices: [present, absent]
        default: "present"
        type: str
    sortorder:
        description:
            - Position of the service used for sorting.
        required: true
        type: str
    weight:
        description:
            - Service weight.
        required: false
        default: "0"
        type: str
    description:
        description:
            - Description of the service.
        required: false
        type: str
    tags:
        description:
            - Service tags to be created for the service.
        required: false
        type: list
        elements: dict
        suboptions:
            tag:
                description:
                    - Service tag name.
                required: true
                type: str
            value:
                description:
                    - Service tag value.
                required: false
                type: str
    problem_tags:
        description:
            - Problem tags to be created for the service.
        required: false
        type: list
        elements: dict
        suboptions:
            tag:
                description:
                    - Problem tag name.
                required: true
                type: str
            operator:
                description:
                    - Mapping condition operator.
                    - C(equals)
                    - C(like)
                choices: ["equals", "like"]
                required: false
                default: "equals"
                type: str
            value:
                description:
                    - Problem tag value.
                required: false
                default: ""
                type: str
    parents:
        description:
            - Parent services to be linked to the service.
        required: false
        type: list
        elements: str
    children:
        description:
            - Child services to be linked to the service.
        required: false
        type: list
        elements: str
    propagation_rule:
        description:
            - Status propagation value. Must be set together with propagation_rule.
            - C(as_is) propagate service status as is - without any changes
            - C(increase) increase the propagated status by a given propagation_value (by 1 to 5 severities)
            - C(decrease) decrease the propagated status by a given propagation_value (by 1 to 5 severities)
            - C(ignore) ignore this service - the status is not propagated to the parent service at all
            - C(fixed) set fixed service status using a given propagation_value
            - Required with C(propagation_value)
        required: false
        type: str
        default: as_is
    propagation_value:
        description:
            - Status propagation value. Must be set together with propagation_rule.
            - "Possible values when I(propagation_rule=as_is or ignore):"
            - " - C(not_classified)"
            - "Possible values when I(propagation_rule=increase or decrease):"
            - " - C(information)"
            - " - C(warning)"
            - " - C(average)"
            - " - C(high)"
            - " - C(disaster)"
            - "Possible values when I(propagation_rule=fixed):"
            - " - C(ok)"
            - " - C(not_classified)"
            - " - C(information)"
            - " - C(warning)"
            - " - C(average)"
            - " - C(high)"
            - " - C(disaster)"
            - Required with C(propagation_rule)
        required: false
        type: str
        default: not_classified
    status_rules:
        description:
            - Status rules for the service.
        required: false
        type: list
        elements: dict
        suboptions:
            type:
                description:
                    - Condition for setting (New status) status.
                    - C(at_least_n_child_services_have_status_or_above) if at least (N) child services have (Status) status or above
                    - C(at_least_npct_child_services_have_status_or_above) if at least (N%) of child services have (Status) status or above
                    - C(less_than_n_child_services_have_status_or_below) if less than (N) child services have (Status) status or below
                    - C(less_than_npct_child_services_have_status_or_below) if less than (N%) of child services have (Status) status or below
                    - C(weight_child_services_with_status_or_above_at_least_w) if weight of child services with (Status) status or above is at least (W)
                    - C(weight_child_services_with_status_or_above_at_least_npct) if weight of child services with (Status) status or above is at least (N%)
                    - C(weight_child_services_with_status_or_below_less_w) if weight of child services with (Status) status or below is less than (W)
                    - C(weight_child_services_with_status_or_below_less_npct) if weight of child services with (Status) status or below is less than (N%)
                required: true
                type: str
            limit_value:
                description:
                    - "Limit value: N, N% or W"
                    - "Possible values: 1-100000 for N and W, 1-100 for N%"
                required: true
                type: int
            limit_status:
                description:
                    - Limit status.
                    - C(ok) OK
                    - C(not_classified) Not classified
                    - C(information) Information
                    - C(warning) Warning
                    - C(average) Average
                    - C(high) High
                    - C(disaster) Disaster
                required: true
                type: str
            new_status:
                description:
                    - New status value.
                    - C(not_classified) Not classified
                    - C(information) Information
                    - C(warning) Warning
                    - C(average) Average
                    - C(high) High
                    - C(disaster) Disaster
                required: true
                type: str

extends_documentation_fragment:
- community.zabbix.zabbix

"""

EXAMPLES = """
---
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

# Creates a new Zabbix service
- name: Create Zabbix service monitoring Apache2 in DCs in Toronto area
  # set task level variables
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_service:
    name: "apache2 service Toronto"
    description: Apache2 services in Toronto area
    sortorder: 0
    propagation_rule: increase
    propagation_value: warning
    weight: 1
    state: present
    tags:
      - tag: zabbix_service
        value: apache2
      - tag: area
        value: Toronto
    problem_tags:
      - tag: service_name
        value: httpd
      - tag: area
        operator: like
        value: toronto
    status_rules:
      - type: at_least_n_child_services_have_status_or_above
        limit_value: 4242
        limit_status: ok
        new_status: average

- name: Create Zabbix service monitoring all Apache2 services
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_service:
    name: apache2 service
    description: Apache2 services
    tags:
      - tag: zabbix_service
        value: apache2
      - tag: area
        value: global
    children:
      - "apache2 service Toronto"
"""

RETURN = """
---
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class Service(ZabbixBase):
    def get_service(self, service_name):
        services = self._zapi.service.get({"selectParents": ["serviceid"], "selectChildren": ["serviceid"], "selectTags": "extend",
                                           "selectProblemTags": "extend", "selectStatusRules": "extend", "sortfield": "serviceid",
                                           "sortorder": "ASC", "filter": {"name": service_name}})
        return services

    def delete_service(self, service_ids):
        if self._module.check_mode:
            self._module.exit_json(changed=True)
        self._zapi.service.delete([service_ids])

    def dump_services(self, service_ids):
        services = self._zapi.service.get({"output": "extend", "filter": {"serviceid": service_ids}, "selectParents": "extend",
                                           "selectTags": "extend", "selectProblemTags": "extend", "selectChildren": "extend",
                                           "selectStatusRules": "extend"})

        return services

    def construct_problem_tags(self, problem_tags):
        p_operators = {"equals": "0", "like": "2"}
        for problem_tag in problem_tags:
            if problem_tag["operator"] in list(p_operators.keys()):
                problem_tag["operator"] = p_operators[problem_tag["operator"]]
            else:
                problem_tag["operator"] = int(problem_tag["operator"])
            if not problem_tag["tag"]:
                self._module.fail_json(msg='"tag" required in "problem_tags"')
        return problem_tags

    def construct_status_rules(self, status_rules):
        sr_type_map = {"at_least_n_child_services_have_status_or_above": "0",
                       "at_least_npct_child_services_have_status_or_above": "1",
                       "less_than_n_child_services_have_status_or_below": "2",
                       "less_than_npct_child_services_have_status_or_below": "3",
                       "weight_child_services_with_status_or_above_at_least_w": "4",
                       "weight_child_services_with_status_or_above_at_least_npct": "5",
                       "weight_child_services_with_status_or_below_less_w": "6",
                       "weight_child_services_with_status_or_below_less_npct": "7"}
        for s_rule in status_rules:
            if "type" in s_rule:
                if s_rule["type"] not in sr_type_map:
                    self._module.fail_json(msg="Wrong value for 'type' parameter in status rule.")
                s_rule["type"] = sr_type_map[s_rule["type"]]
            else:
                self._module.fail_json(msg="'type' is mandatory paremeter for status rule.")

            if "limit_value" in s_rule:
                lv = s_rule["limit_value"]
                if s_rule["type"] in ["0", "2", "4", "6"]:
                    if int(lv) < 1 or int(lv) > 100000:
                        self._module.fail_json(msg="'limit_value' for N and W must be between 1 and 100000 but provided %s" % lv)
                else:
                    if int(lv) < 1 or int(lv) > 100:
                        self._module.fail_json(msg="'limit_value' for N%% must be between 1 and 100 but provided %s" % lv)
                s_rule["limit_value"] = str(lv)
            else:
                self._module.fail_json(msg="'limit_value' is mandatory paremeter for status rule.")

            if "limit_status" in s_rule:
                sr_ls_map = {"ok": "-1", "not_classified": "0", "information": "1", "warning": "2",
                             "average": "3", "high": "4", "disaster": 5}
                if s_rule["limit_status"] not in sr_ls_map:
                    self._module.fail_json(msg="Wrong value for 'limit_status' parameter in status rule.")
                s_rule["limit_status"] = sr_ls_map[s_rule["limit_status"]]
            else:
                self._module.fail_json(msg="'limit_status' is mandatory paremeter for status rule.")

            if "new_status" in s_rule:
                sr_ns_map = {"not_classified": "0", "information": "1", "warning": "2",
                             "average": "3", "high": "4", "disaster": "5"}
                if s_rule["new_status"] not in sr_ns_map:
                    self._module.fail_json(msg="Wrong value for 'new_status' parameter in status rule.")
                s_rule["new_status"] = sr_ns_map[s_rule["new_status"]]
            else:
                self._module.fail_json(msg="'new_status' is mandatory paremeter for status rule.")

        return status_rules

    def create_service(self, service_name, sortorder, weight, algorithm,
                       description, tags, problem_tags, parents, children, propagation_rule, propagation_value, status_rules):
        if self._module.check_mode:
            self._module.exit_json(changed=True)
        else:
            try:
                parameters = {"name": service_name}
                if sortorder is not None:
                    parameters["sortorder"] = sortorder
                if weight is not None:
                    parameters["weight"] = weight
                if algorithm is not None:
                    parameters["algorithm"] = algorithm
                if description is not None:
                    parameters["description"] = description
                if tags is not None:
                    parameters["tags"] = tags
                if problem_tags is not None:
                    parameters["problem_tags"] = problem_tags
                if parents is not None:
                    parameters["parents"] = parents
                if children is not None:
                    parameters["children"] = children
                if propagation_rule is not None:
                    parameters["propagation_rule"] = propagation_rule
                if propagation_value is not None:
                    parameters["propagation_value"] = propagation_value
                if status_rules is not None:
                    parameters["status_rules"] = status_rules

                self._zapi.service.create(parameters)
                self._module.exit_json(changed=True, msg="Service %s created" % service_name)
            except Exception as e:
                self._module.fail_json(msg="Failed creating service %s: %s" % (service_name, e))

    def check_all_properties(self, name, sortorder, weight, algorithm, description, tags, problem_tags, parents,
                             children, propagation_rule, propagation_value, status_rules, service_exist):
        # raise Exception("%s ------ %s" % (parents, service_exist))
        if sortorder and sortorder != service_exist['sortorder']:
            return True
        if weight and weight != service_exist['weight']:
            return True
        if algorithm and algorithm != service_exist['algorithm']:
            return True
        if description and description != service_exist['description']:
            return True
        if tags and tags != service_exist['tags']:
            return True
        if problem_tags != service_exist['problem_tags']:
            return True
        if parents and parents != service_exist['parents']:
            return True
        if children and children != service_exist['children']:
            return True
        if propagation_rule and propagation_rule != service_exist['propagation_rule']:
            return True
        if propagation_value and propagation_value != service_exist['propagation_value']:
            return True
        if status_rules and status_rules != service_exist['status_rules']:
            return True
        return False

    def update_service(self, service_id, name, sortorder, weight, algorithm, description, tags, problem_tags,
                       parents, children, propagation_rule, propagation_value, status_rules, service_name):
        try:
            parameters = {"serviceid": service_id}
            if sortorder is not None:
                parameters["sortorder"] = sortorder
            if weight is not None:
                parameters["weight"] = weight
            if algorithm is not None:
                parameters["algorithm"] = algorithm
            if description is not None:
                parameters["description"] = description
            if tags is not None:
                parameters["tags"] = tags
            if problem_tags is not None:
                parameters["problem_tags"] = problem_tags
            if parents is not None:
                parameters["parents"] = parents
            if children is not None:
                parameters["children"] = children
            if propagation_rule is not None:
                parameters["propagation_rule"] = propagation_rule
            if propagation_value is not None:
                parameters["propagation_value"] = propagation_value
            if status_rules is not None:
                parameters["status_rules"] = status_rules

            self._zapi.service.update(parameters)
            self._module.exit_json(changed=True, msg="Service %s updated" % name)
        except Exception as e:
            self._module.fail_json(msg="Failed updating service %s: %s" % (service_name, e))


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        name=dict(type="str", required=True),
        algorithm=dict(default="status_to_ok", required=False, choices=["status_to_ok", "most_crit_if_all_children", "most_crit_of_child_serv"]),
        sortorder=dict(type="str", required=True),
        weight=dict(default="0", type="str", required=False),
        state=dict(default="present", choices=["present", "absent"]),
        description=dict(type="str", required=False),
        tags=dict(
            type="list",
            required=False,
            elements="dict",
            options=dict(
                tag=dict(
                    type="str",
                    required=True
                ),
                value=dict(
                    type="str",
                    required=False
                )
            )
        ),
        problem_tags=dict(
            type="list",
            required=False,
            elements="dict",
            options=dict(
                tag=dict(
                    type="str",
                    required=True
                ),
                operator=dict(
                    type="str",
                    required=False,
                    choices=[
                        "equals",
                        "like"
                    ],
                    default="equals"
                ),
                value=dict(
                    type="str",
                    required=False,
                    default=""
                )
            )
        ),
        parents=dict(type="list", required=False, elements="str"),
        children=dict(type="list", required=False, elements="str"),
        propagation_rule=dict(type="str", required=False, default="as_is"),
        propagation_value=dict(type="str", required=False, default="not_classified"),
        status_rules=dict(
            type="list",
            required=False,
            elements="dict",
            options=dict(
                type=dict(
                    type="str",
                    required=True
                ),
                limit_value=dict(
                    type="int",
                    required=True
                ),
                limit_status=dict(
                    type="str",
                    required=True
                ),
                new_status=dict(
                    type="str",
                    required=True
                )
            )
        )
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_together=[
            ('propagation_rule', 'propagation_value')
        ]
    )

    name = module.params["name"]
    algorithm = module.params["algorithm"]
    sortorder = module.params["sortorder"]
    weight = module.params["weight"]
    state = module.params["state"]
    description = module.params["description"]
    tags = module.params["tags"]
    problem_tags = module.params["problem_tags"]
    parents = module.params["parents"]
    children = module.params["children"]
    propagation_rule = module.params["propagation_rule"]
    propagation_value = module.params["propagation_value"]
    status_rules = module.params["status_rules"]

    # Load service module
    service = Service(module)
    service_exist = service.get_service(name)
    service_id = ""
    if service_exist:
        service_id = service_exist[0]["serviceid"]

    algorithms = {"status_to_ok": "0", "most_crit_if_all_children": "1", "most_crit_of_child_serv": "2"}
    algorithm = algorithms[algorithm]

    if problem_tags:
        problem_tags = service.construct_problem_tags(problem_tags)
    else:
        problem_tags = []

    if parents:
        p_service_ids = []
        p_services = service._zapi.service.get({"output": ["serviceid"], "filter": {"name": parents}})
        for p_service in p_services:
            p_service_ids.append({"serviceid": p_service["serviceid"]})
        parents = p_service_ids

    if children:
        c_service_ids = []
        c_services = service._zapi.service.get({"output": ["serviceid"], "filter": {"name": children}})
        for c_service in c_services:
            c_service_ids.append({"serviceid": c_service["serviceid"]})
        children = c_service_ids

    if status_rules:
        status_rules = service.construct_status_rules(status_rules)

    if propagation_rule:
        if propagation_value is None:
            module.fail_json(msg="If 'propagation_rule' is provided then 'propagation_value' must be provided too.")
        pr_map = {"as_is": "0", "increase": "1", "decrease": "2", "ignore": "3", "fixed": "4"}
        if propagation_rule not in pr_map:
            module.fail_json(msg="Wrong value for 'propagation_rule' parameter.")
        else:
            propagation_rule = pr_map[propagation_rule]

    if propagation_value:
        if propagation_rule is None:
            module.fail_json(msg="If 'propagation_value' is provided then 'propagation_rule' must be provided too.")
        pv_map = {"ok": "-1", "not_classified": "0", "information": "1", "warning": "2",
                  "average": "3", "high": "4", "disaster": "5"}
        if propagation_value not in pv_map:
            module.fail_json(msg="Wrong value for 'propagation_value' parameter.")
        else:
            propagation_value = pv_map[propagation_value]

    # Delete service
    if state == "absent":
        if not service_id:
            module.exit_json(changed=False, msg="Service not found, no change: %s" % name)
        service.delete_service(service_id)
        module.exit_json(changed=True, result="Successfully deleted service(s) %s" % name)

    elif state == "present":
        # Does not exists going to create it
        if not service_id:
            service.create_service(name, sortorder, weight, algorithm, description,
                                   tags, problem_tags, parents, children, propagation_rule, propagation_value, status_rules)
            module.exit_json(changed=True, msg="Service %s created" % name)
        # Else we update it if exists
        else:
            # Check if parameters have changed
            if service.check_all_properties(name, sortorder, weight, algorithm, description, tags, problem_tags, parents,
                                            children, propagation_rule, propagation_value, status_rules, service_exist[0]):
                # Update service if a parameter is different
                service.update_service(service_id, name, sortorder, weight, algorithm, description, tags, problem_tags,
                                       parents, children, propagation_rule, propagation_value, status_rules, name)
            else:
                # No parameters changed, no update required.
                module.exit_json(changed=False)


if __name__ == "__main__":
    main()
