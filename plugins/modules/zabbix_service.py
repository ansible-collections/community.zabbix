#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2019, OVH SAS
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: zabbix_service
short_description: Create/update/delete Zabbix service
description:
    - Create/update/delete Zabbix service.
author:
    - "Emmanuel Riviere (@emriver)"
    - "Evgeny Yurchenko (@BGmot)"
requirements:
    - "python >= 2.7"
    - "zabbix-api >= 0.5.4"
options:
    name:
        description:
            - Name of Zabbix service
        required: true
        type: str
    parent:
        description:
            - Name of Zabbix service parent
            - With >= Zabbix 6.0 this field is removed from the API and is dropped silently by module.
        required: false
        type: str
    sla:
        description:
            - Sla value (i.e 99.99), goodsla in Zabbix API
            - With >= Zabbix 6.0 this field is removed from the API and is dropped silently by module.
        required: false
        type: float
    calculate_sla:
        description:
            - If yes, calculate the SLA value for this service, showsla in Zabbix API
            - With >= Zabbix 6.0 this field is removed from the API and is dropped silently by module.
        required: false
        default: false
        type: bool
    algorithm:
        description:
            - Algorithm used to calculate the sla with < Zabbix 6.0
            - ' - C(no), sla is not calculated'
            - ' - C(one_child), problem if at least one child has a problem'
            - ' - C(all_children), problem if all children have problems'
            - Status calculation rule. Only applicable if child services exists with >= Zabbix 6.0
            - ' - C(status_to_ok), set status to OK with'
            - ' - C(most_crit_if_all_children), most critical if all children have problems'
            - ' - C(most_crit_of_child_serv), most critical of child services with'
        required: false
        type: str
        choices: ["no", "one_child", "all_children", "status_to_ok", "most_crit_if_all_children", "most_crit_of_child_serv"]
        default: one_child
    trigger_name:
        description:
            - Name of trigger linked to the service.
            - With >= Zabbix 6.0 this field is removed from the API and is dropped silently by module.
        required: false
        type: str
    trigger_host:
        description:
            - Name of host linked to the service.
            - With >= Zabbix 6.0 this field is removed from the API and is dropped silently by module.
        required: false
        type: str
    state:
        description:
            - 'State: present - create/update service; absent - delete service.'
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
            - New field with >= Zabbix 6.0.
        required: false
        default: '0'
        type: str
    description:
        description:
            - Description of the service.
            - New field with >= Zabbix 6.0.
        required: false
        type: str
    tags:
        description:
            - Service tags to be created for the service.
            - New field with >= Zabbix 6.0.
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
            - New field with >= Zabbix 6.0.
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
                choices: ['equals', 'like']
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
            - New field with >= Zabbix 6.0.
        required: false
        type: list
        elements: str
    children:
        description:
            - Child services to be linked to the service.
            - New field with >= Zabbix 6.0.
        required: false
        type: list
        elements: str
    propagation_rule:
        description:
            - Status propagation value. Must be set together with propagation_rule.
            - New field with >= Zabbix 6.0.
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
            - New field with >= Zabbix 6.0.
            - 'Possible values when I(propagation_rule=as_is or ignore):'
            - ' - C(not_classified)'
            - 'Possible values when I(propagation_rule=increase or decrease):'
            - ' - C(information)'
            - ' - C(warning)'
            - ' - C(average)'
            - ' - C(high)'
            - ' - C(disaster)'
            - 'Possible values when I(propagation_rule=fixed):'
            - ' - C(ok)'
            - ' - C(not_classified)'
            - ' - C(information)'
            - ' - C(warning)'
            - ' - C(average)'
            - ' - C(high)'
            - ' - C(disaster)'
            - Required with C(propagation_rule)
        required: false
        type: str
    status_rules:
        description:
            - Status rules for the service.
            - New field with >= Zabbix 6.0.
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
                    - 'Limit value: N, N% or W'
                    - 'Possible values: 1-100000 for N and W, 1-100 for N%'
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

'''

EXAMPLES = '''
---
# Creates a new Zabbix service with Zabbix < 6.0
- name: Manage services
  community.zabbix.zabbix_service:
    server_url: "http://zabbix.example.com/zabbix/"
    login_user: username
    login_password: password
    name: apache2 service
    sla: 99.99
    calculate_sla: yes
    algorithm: one_child
    trigger_name: apache2 service status
    trigger_host: webserver01
    state: present

# Creates a new Zabbix service with Zabbix >= 6.0
- name: Create Zabbix service monitoring Apache2 in DCs in Toronto area
  community.zabbix.zabbix_service:
    server_url: "zabbix.example.com/zabbix/"
    login_user: username
    login_password: password
    name: 'apache2 service Toronto'
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
  community.zabbix.zabbix_service:
    server_url: "zabbix.example.com/zabbix/"
    login_user: username
    login_password: password
    name: apache2 service
    description: Apache2 services
    tags:
      - tag: zabbix_service
        value: apache2
      - tag: area
        value: global
    children:
      - 'apache2 service Toronto'
'''

RETURN = '''
---
'''


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils
from ansible_collections.community.zabbix.plugins.module_utils.version import LooseVersion


class Service(ZabbixBase):
    def get_service_ids(self, service_name):
        service_ids = []
        services = self._zapi.service.get({'filter': {'name': service_name}})
        for service in services:
            service_ids.append(service['serviceid'])
        return service_ids

    def delete_service(self, service_ids):
        if self._module.check_mode:
            self._module.exit_json(changed=True)
        self._zapi.service.delete(service_ids)

    def dump_services(self, service_ids):
        if LooseVersion(self._zbx_api_version) < LooseVersion('6.0'):
            services = self._zapi.service.get({'output': 'extend', 'filter': {'serviceid': service_ids}, 'selectParent': '1'})
        else:
            services = self._zapi.service.get({'output': 'extend', 'filter': {'serviceid': service_ids}, 'selectParents': 'extend',
                                               'selectTags': 'extend', 'selectProblemTags': 'extend', 'selectChildren': 'extend',
                                               'selectStatusRules': 'extend'})

        return services

    def generate_service_config(self, name, parent, sla, calculate_sla, trigger_name, trigger_host, sortorder, weight,
                                algorithm, description, tags, problem_tags, parents, children, propagation_rule, propagation_value, status_rules):
        algorithms = {'no': '0', 'one_child': '1', 'all_children': '2',
                      'status_to_ok': '0', 'most_crit_if_all_children': '1', 'most_crit_of_child_serv': '2'}
        algorithm = algorithms[algorithm]

        if LooseVersion(self._zbx_api_version) < LooseVersion('6.0'):
            if calculate_sla:
                calculate_sla = 1
            else:
                calculate_sla = 0
        else:
            sla = 0  # Parameter does not exist in >= 6.0 but we needed for format() function constructing request

        # Zabbix api return when no trigger
        trigger_id = 0
        if trigger_host and trigger_name:
            # Retrieving the host to get the trigger
            hosts = self._zapi.host.get({'filter': {'host': trigger_host}})
            if not hosts:
                self._module.fail_json(msg="Target host %s not found" % trigger_host)
            host_id = hosts[0]['hostid']

            triggers = self._zapi.trigger.get({'filter': {'description': trigger_name}, 'hostids': [host_id]})
            if not triggers:
                self._module.fail_json(msg="Trigger %s not found on host %s" % (trigger_name, trigger_host))
            trigger_id = triggers[0]['triggerid']

        request = {
            'name': name,
            'algorithm': algorithm,
            'showsla': str(calculate_sla),
            'sortorder': sortorder,
            'goodsla': format(sla, '.4f'),  # Sla has 4 decimals
            'triggerid': str(trigger_id)
        }

        if LooseVersion(self._zbx_api_version) >= LooseVersion('6.0'):
            request.pop('showsla')
            request.pop('triggerid')
            request.pop('goodsla')
            request['description'] = description
            request['weight'] = weight

            if tags:
                request['tags'] = tags
            else:
                request['tags'] = []

            request['problem_tags'] = []
            if problem_tags:
                p_operators = {'equals': '0', 'like': '2'}
                for p_tag in problem_tags:
                    pt = {'tag': p_tag['tag'], 'operator': '0', 'value': ''}
                    if 'operator' in p_tag:
                        pt['operator'] = p_operators[p_tag['operator']]
                    if 'value' in p_tag:
                        pt['value'] = p_tag['value']
                    request['problem_tags'].append(pt)

            if parents:
                p_service_ids = []
                p_services = self._zapi.service.get({'filter': {'name': parents}})
                for p_service in p_services:
                    p_service_ids.append({'serviceid': p_service['serviceid']})
                request['parents'] = p_service_ids
            else:
                request['parents'] = []

            if children:
                c_service_ids = []
                c_services = self._zapi.service.get({'filter': {'name': children}})
                for c_service in c_services:
                    c_service_ids.append({'serviceid': c_service['serviceid']})
                request['children'] = c_service_ids
            else:
                request['children'] = []

            request['status_rules'] = []
            if status_rules:
                for s_rule in status_rules:
                    status_rule = {}
                    if 'type' in s_rule:
                        sr_type_map = {'at_least_n_child_services_have_status_or_above': '0',
                                       'at_least_npct_child_services_have_status_or_above': '1',
                                       'less_than_n_child_services_have_status_or_below': '2',
                                       'less_than_npct_child_services_have_status_or_below': '3',
                                       'weight_child_services_with_status_or_above_at_least_w': '4',
                                       'weight_child_services_with_status_or_above_at_least_npct': '5',
                                       'weight_child_services_with_status_or_below_less_w': '6',
                                       'weight_child_services_with_status_or_below_less_npct': '7'}
                        if s_rule['type'] not in sr_type_map:
                            self._module.fail_json(msg="Wrong value for 'type' parameter in status rule.")
                        status_rule['type'] = sr_type_map[s_rule['type']]
                    else:
                        self._module.fail_json(msg="'type' is mandatory paremeter for status rule.")

                    if 'limit_value' in s_rule:
                        lv = s_rule['limit_value']
                        if status_rule['type'] in ['0', '2', '4', '6']:
                            if int(lv) < 1 or int(lv) > 100000:
                                self._module.fail_json(msg="'limit_value' for N and W must be between 1 and 100000 but provided %s" % lv)
                        else:
                            if int(lv) < 1 or int(lv) > 100:
                                self._module.fail_json(msg="'limit_value' for N%% must be between 1 and 100 but provided %s" % lv)
                        status_rule['limit_value'] = str(lv)
                    else:
                        self._module.fail_json(msg="'limit_value' is mandatory paremeter for status rule.")

                    if 'limit_status' in s_rule:
                        sr_ls_map = {'ok': '-1', 'not_classified': '0', 'information': '1', 'warning': '2',
                                     'average': '3', 'high': '4', 'disaster': 5}
                        if s_rule['limit_status'] not in sr_ls_map:
                            self._module.fail_json(msg="Wrong value for 'limit_status' parameter in status rule.")
                        status_rule['limit_status'] = sr_ls_map[s_rule['limit_status']]
                    else:
                        self._module.fail_json(msg="'limit_status' is mandatory paremeter for status rule.")

                    if 'new_status' in s_rule:
                        sr_ns_map = {'not_classified': '0', 'information': '1', 'warning': '2',
                                     'average': '3', 'high': '4', 'disaster': '5'}
                        if s_rule['new_status'] not in sr_ns_map:
                            self._module.fail_json(msg="Wrong value for 'new_status' parameter in status rule.")
                        status_rule['new_status'] = sr_ns_map[s_rule['new_status']]
                    else:
                        self._module.fail_json(msg="'new_status' is mandatory paremeter for status rule.")

                    request['status_rules'].append(status_rule)

            request['propagation_rule'] = '0'
            if propagation_rule:
                if propagation_value is None:
                    self._module.fail_json(msg="If 'propagation_rule' is provided then 'propagation_value' must be provided too.")
                pr_map = {'as_is': '0', 'increase': '1', 'decrease': '2', 'ignore': '3', 'fixed': '4'}
                if propagation_rule not in pr_map:
                    self._module.fail_json(msg="Wrong value for 'propagation_rule' parameter.")
                else:
                    request['propagation_rule'] = pr_map[propagation_rule]

            request['propagation_value'] = '0'
            if propagation_value:
                if propagation_rule is None:
                    self._module.fail_json(msg="If 'propagation_value' is provided then 'propagation_rule' must be provided too.")
                pv_map = {'ok': '-1', 'not_classified': '0', 'information': '1', 'warning': '2',
                          'average': '3', 'high': '4', 'disaster': '5'}
                if propagation_value not in pv_map:
                    self._module.fail_json(msg="Wrong value for 'propagation_value' parameter.")
                else:
                    request['propagation_value'] = pv_map[propagation_value]
        else:
            if parent:
                parent_ids = self.get_service_ids(parent)
                if not parent_ids:
                    self._module.fail_json(msg="Parent %s not found" % parent)
                request['parentid'] = parent_ids[0]
        return request

    def create_service(self, name, parent, sla, calculate_sla, trigger_name, trigger_host, sortorder, weight, algorithm,
                       description, tags, problem_tags, parents, children, propagation_rule, propagation_value, status_rules):
        if self._module.check_mode:
            self._module.exit_json(changed=True)

        self._zapi.service.create(self.generate_service_config(name, parent, sla, calculate_sla, trigger_name, trigger_host, sortorder, weight,
                                  algorithm, description, tags, problem_tags, parents, children, propagation_rule, propagation_value, status_rules))

    def update_service(self, service_id, name, parent, sla, calculate_sla, trigger_name, trigger_host, sortorder, weight, algorithm,
                       description, tags, problem_tags, parents, children, propagation_rule, propagation_value, status_rules):
        generated_config = self.generate_service_config(name, parent, sla, calculate_sla, trigger_name, trigger_host, sortorder, weight, algorithm,
                                                        description, tags, problem_tags, parents, children, propagation_rule, propagation_value, status_rules)
        live_config = self.dump_services(service_id)[0]

        if LooseVersion(self._zbx_api_version) >= LooseVersion('6.0'):
            if len(live_config['parents']) > 0:
                # Need to rewrite parents list to only service ids
                new_parents = []
                for parent in live_config['parents']:
                    new_parents.append({'serviceid': parent['serviceid']})
                live_config['parents'] = new_parents

            if len(live_config['children']) > 0:
                # Need to rewrite children list to only service ids
                new_children = []
                for child in live_config['children']:
                    new_children.append({'serviceid': child['serviceid']})
                live_config['children'] = new_children

        else:
            if 'goodsla' in live_config:
                live_config['goodsla'] = format(float(live_config['goodsla']), '.4f')

            if 'parentid' in generated_config:
                if 'serviceid' in live_config['parent']:
                    live_config['parentid'] = live_config['parent']['serviceid']

        change_parameters = {}
        difference = zabbix_utils.helper_cleanup_data(zabbix_utils.helper_compare_dictionaries(generated_config, live_config, change_parameters))

        if difference == {}:
            self._module.exit_json(changed=False, msg="Service %s up to date" % name)

        if self._module.check_mode:
            self._module.exit_json(changed=True)
        generated_config['serviceid'] = service_id
        self._zapi.service.update(generated_config)
        self._module.exit_json(changed=True, msg="Service %s updated" % name)


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        name=dict(type='str', required=True),
        parent=dict(type='str', required=False),
        sla=dict(type='float', required=False),
        calculate_sla=dict(type='bool', required=False, default=False),
        algorithm=dict(default='one_child', required=False, choices=['no', 'one_child', 'all_children',
                                                                     'status_to_ok', 'most_crit_if_all_children', 'most_crit_of_child_serv']),
        trigger_name=dict(type='str', required=False),
        trigger_host=dict(type='str', required=False),
        sortorder=dict(type='str', required=True),
        weight=dict(default='0', type='str', required=False),
        state=dict(default="present", choices=['present', 'absent']),
        description=dict(type='str', required=False),
        tags=dict(
            type='list',
            required=False,
            elements='dict',
            options=dict(
                tag=dict(
                    type='str',
                    required=True
                ),
                value=dict(
                    type='str',
                    required=False
                )
            )
        ),
        problem_tags=dict(
            type='list',
            required=False,
            elements='dict',
            options=dict(
                tag=dict(
                    type='str',
                    required=True
                ),
                operator=dict(
                    type='str',
                    required=False,
                    choices=[
                        'equals',
                        'like'
                    ],
                    default='equals'
                ),
                value=dict(
                    type='str',
                    required=False,
                    default=''
                )
            )
        ),
        parents=dict(type='list', required=False, elements='str'),
        children=dict(type='list', required=False, elements='str'),
        propagation_rule=dict(default='as_is', type='str', required=False),
        propagation_value=dict(type='str', required=False),
        status_rules=dict(
            type='list',
            required=False,
            elements='dict',
            options=dict(
                type=dict(
                    type='str',
                    required=True
                ),
                limit_value=dict(
                    type='int',
                    required=True
                ),
                limit_status=dict(
                    type='str',
                    required=True
                ),
                new_status=dict(
                    type='str',
                    required=True
                )
            )
        )
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    name = module.params['name']
    parent = module.params['parent']
    sla = module.params['sla']
    calculate_sla = module.params['calculate_sla']
    algorithm = module.params['algorithm']
    trigger_name = module.params['trigger_name']
    trigger_host = module.params['trigger_host']
    sortorder = module.params['sortorder']
    weight = module.params['weight']
    state = module.params['state']
    description = module.params['description']
    tags = module.params['tags']
    problem_tags = module.params['problem_tags']
    parents = module.params['parents']
    children = module.params['children']
    propagation_rule = module.params['propagation_rule']
    propagation_value = module.params['propagation_value']
    status_rules = module.params['status_rules']

    # Load service module
    service = Service(module)
    service_ids = service.get_service_ids(name)

    # Delete service
    if state == "absent":
        if not service_ids:
            module.exit_json(changed=False, msg="Service not found, no change: %s" % name)
        service.delete_service(service_ids)
        module.exit_json(changed=True, result="Successfully deleted service(s) %s" % name)

    elif state == "present":
        if (trigger_name and not trigger_host) or (trigger_host and not trigger_name):
            module.fail_json(msg="Specify either both trigger_host and trigger_name or none to create or update a service")
        # Does not exists going to create it
        if not service_ids:
            service.create_service(name, parent, sla, calculate_sla, trigger_name, trigger_host, sortorder, weight, algorithm, description,
                                   tags, problem_tags, parents, children, propagation_rule, propagation_value, status_rules)
            module.exit_json(changed=True, msg="Service %s created" % name)
        # Else we update it if needed
        else:
            service.update_service(service_ids[0], name, parent, sla, calculate_sla, trigger_name, trigger_host, sortorder, weight,
                                   algorithm, description, tags, problem_tags, parents, children, propagation_rule, propagation_value, status_rules)


if __name__ == '__main__':
    main()
