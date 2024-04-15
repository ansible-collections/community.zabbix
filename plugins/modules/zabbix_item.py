#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2013-2014, Epic Games, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type



import copy

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase

import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils

class Item(ZabbixBase):
    #exist item
    def is_item_exist(self, item_name, host_name):
        host_id = self.get_hostid_by_host_name(host_name)
        result = self._zapi.item.get({"filter": {"name": item_name, "hostid": host_id}})
        return result
    
    #check if host exists
    def check_host_exist(self, host_name):
        result = self._zapi.host.get({"filter": {"name": host_name}})
        if not result:
            self._module.fail_json(msg="Host not found %s" % host_name)
        return True
    
    def add_item(self, item_name, key, host_id, type, value_type, delay): #add more parameters
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            parameters = {"name": item_name, "key_": key, "hostid": host_id, "type": type, "value_type": value_type, "delay": delay} #add more parameters
            #add conditional parameters

            item_list = self._zapi.item.create(parameters)
            if len(item_list) >= 1:
                return item_list["itemids"][0]
        except Exception as e:
            self._module.fail_json(msg="Failed to create item %s: %s" % (item_name, e))
    
    def update_item(self, item_name, item_id, key, delay, description): #add more parameters
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
        
            parameters = {"itemid": item_id}
            #add conditional parameters
            if description is not None:
                parameters["description"] = description
            if key is not None:
                parameters["key_"] = key
            if delay is not None:
                parameters["delay"] = delay

            self._zapi.item.update(parameters)
        except Exception as e:
            self._module.fail_json(msg="Failed to update item %s: %s" % (item_name, e))
    
    def delete_item(self, item_id, item_name):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            self._zapi.item.delete([item_id])
        except Exception as e:
            self._module.fail_json(msg="Failed to delete item %s: %s" % (item_name, e))

    def get_item_by_item_name(self, item_name):
        params = { # add more parameters
            "output": [
                "itemid"
            ],
            "filter": {
                "name": [item_name]
            }
        }

        item_list = self._zapi.item.get(params)
        if len(item_list) < 1:
            self._module.fail_json(msg="Item not found: %s" % item_name)
    
    def get_hostid_by_host_name(self, host_name):
        host_list = self._zapi.host.get({"output": "extend", "filter": {"host": [host_name]}})
        if len(host_list) < 1:
            self._module.fail_json(msg="Host not found: %s" % host_name)
        else:
            return int(host_list[0]["hostid"])
        
    def check_all_properties(self, item_id, key, host_id, host_name, delay):
        exist_item = self._zapi.item.get({"output": "extend", "filter": {"itemid": item_id}})[0]
        exist_host = self.get_hostid_by_host_name(host_name)
        if host_id != exist_host:
            return True
        
        if key != exist_item["key_"]:
            return True
        if delay != exist_item["delay"]:
            return True

        return False
    
def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        item_name=dict(type="str", required=True),
        key=dict(type="str", required=True),
        host_name=dict(type="str", required=True),
        state=dict(type="str", default="present", choices=["present", "absent"]),
        status=dict(type="str", default="enabled", choices=["enabled", "disabled"]),
        type=dict(type="str", choices=["zabbix_agent", "1", "zabbix_trapper", "2", "simple_check", "3", "zabbix_internal", "4", "zabbix_agent_active", "5", "web_item", "6", "external_check", "7", "database_monitor", "8", "ipmi", "9", "ssh", "10", "telnet", "11", "calculated", "12", "jmx", "13", "snmp_trap", "14", "dependent", "15", "http", "16", "snmp_agent", "17", "script", "18"], required=True),
        description=dict(type="str"),
        value_type=dict(type="str", choices=["float", "0", "character", "1", "log", "2", "unsigned", "3", "text", "4"], required=True),
        delay=dict(type="str", default="10s")
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
        )
    
    item_name = module.params["item_name"]
    key = module.params["key"]
    host_name = module.params["host_name"]
    state = module.params["state"]
    status = module.params["status"]
    type = module.params["type"]
    description = module.params["description"]
    value_type = module.params["value_type"]
    delay = module.params["delay"]


    status = 1 if status == "disabled" else 0

    type_types = {"zabbix_agent": 1, "zabbix_trapper": 2, "simple_check": 3, "zabbix_internal": 4, "zabbix_agent_active": 5, "web_item": 6, "external_check": 7, "database_monitor": 8, "ipmi": 9, "ssh": 10, "telnet": 11, "calculated": 12, "jmx": 13, "snmp_trap": 14, "dependent": 15, "http": 16, "snmp_agent": 17, "script": 18}
    if type in list(type_types.keys()):
        type_int = type_types[type]

    value_type_types = {"float": 0, "character": 1, "log": 2, "unsigned": 3, "text": 4}
    if value_type in list(value_type_types.keys()):
        value_type_int = value_type_types[value_type]

    item = Item(module)

    # find host id
    host_id = ""
    if host_name is not None:
        host_id = item.get_hostid_by_host_name(host_name)
        if host_id is None:
            module.fail_json(msg="host %s does not exist." % host_name)
    else:
        module.fail_json(msg="host_name must not be empty.")
    
    # check if item exist
    is_item_exist = item.is_item_exist(item_name, host_name)

    if is_item_exist:
        item_id = is_item_exist[0]["itemid"]

        if state == "absent":
            # remove item
            item.delete_item(item_id, item_name)
            module.exit_json(changed=True, result="Successfully deleted item %s" % item_name)
        else:
            

            # update item
            if item.check_all_properties(item_id, key, host_id, host_name, delay):
                item.update_item(item_name, item_id, key, delay, description)

                module.exit_json(changed=True, result="Successfully updated item %s on host %s" % (item_name, host_name))
            else:
                module.exit_json(changed=False)
    
    else:
        if state == "absent":
            # the item is already deleted.
            module.exit_json(changed=False)
        
        if not host_id:
            module.fail_json(msg="Specify a host when creating item '%s'" % item_name)

        # create item
        item_id = item.add_item(item_name, key, host_id, type_int, value_type_int, delay)

        module.exit_json(changed=True, result="Successfully added item %s on host %s" % (item_name, host_name))

if __name__ == "__main__":
    main()
