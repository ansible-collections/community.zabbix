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
    
    def get_itemid_by_item_and_hostid(self, item_name, host_id):
        return self._zapi.item.get({"filter": {"name": item_name, "hostid": host_id}})

    #check if host exists
    def check_host_exist(self, host_name):
        result = self._zapi.host.get({"filter": {"host": host_name}})
        if not result:
            self._module.fail_json(msg="Host not found %s" % host_name)
        return True
    
    def get_host_interfaceid_by_host(self, interface, host_id):
        if interface:
            ip, port = interface.split(":")
            parameters = {"output": "extend", "hostid": host_id, "filter": {"port": port}}
            if re.search(r"\w", ip):
                parameters["filter"]["dns"] = ip
            else:
                parameters["filter"]["ip"] = ip
            return self._zapi.hostinterface.get(parameters)[0]["interfaceid"]
        return "0"

    def construct_preprocessing(self, preprocessing):
        preprocessing_type_types = {"custom_multiplier": 1, "right_trim": 2, "left_trim": 3, "trim": 4, "regex": 5, "bool_to_dec": 6, "oct_to_dec": 7, "hex_to_dec": 8, "simple_change": 9, "change_per_sec": 10, "xml_xpath": 11, "jsonpath": 12, "in_range": 13, "regex_match": 14, "regex_not_match": 15, "json_error_check": 16, "xml_error_check": 17, "regex_error_check": 18, "discard_unchanged": 19, "discard_unchanged_with_heartbeat": 20, "javascript": 21, "prometheus_pattern": 22, "prometheus_to_json": 23, "csv_to_json": 24, "replace": 25, "check_unsupported": 26, "xml_to_json": 27, "snmp_walk_value": 28, "snmp_walk_to_json": 29}
        preprocessing_error_handler_types = {"zabbix": 0, "discard": 1, "custom_value": 2, "custom_message": 3}

        for rule in preprocessing:
            if rule["type"] in list(preprocessing_type_types.keys()):
                rule["type"] = preprocessing_type_types[rule["type"]]
            else:
                rule["type"] = int(rule["type"])
            
            if rule["error_handler"] in list(preprocessing_error_handler_types.keys()):
                rule["error_handler"] = preprocessing_error_handler_types[rule["error_handler"]]
            else:
                rule["error_handler"] = int(rule["error_handler"])
        
            if rule["type"] in list(1, 2, 3, 4, 5, 11, 12, 13, 14, 15, 16, 17, 18, 20, 21, 22, 23, 24, 25, 28, 29):
                if not rule["params"]:
                    self._module.fail_json(msg="Option 'params' required in combination with the preprocessing type %s" % list(preprocessing_type_types.keys())[rule["type"]])
            
            if rule["error_handler"] in list(2, 3):
                if not rule["error_handler_params"]:
                    self._module.fail_json(msg="Option 'error_handler_params' required in combination with the preprocessing error handling type %s" % list(preprocessing_type_types.keys())[rule["error_handler_type"]])

        return preprocessing

    def add_item(self, item_name, key, host_id, type, value_type, update_interval, interfaceid, url, allow_traps, authtype, description, follow_redirects, headers, history, http_proxy, inventory_link, ipmi_sensor, jmx_endpoint, logtimefmt, master_itemid, params, item_parameters, password, body_type, body, privatekey, url_query, http_method, retrieve_mode, snmp_oid, ssl_cert_file, ssl_key_file, ssl_key_password, status_codes, timeout, trapper_hosts, trends, units, username, verify_host, verify_peer, tags, preprocessing):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            else:
                parameters = {"name": item_name, "key_": key, "hostid": host_id, "type": type, "value_type": value_type, "delay": update_interval} #add more parameters
                #add conditional parameters
                if interfaceid is not None:
                    parameters["interfaceid"] = interfaceid
                if url is not None:
                    parameters["url"] = url
                if allow_traps is not None:
                    parameters["allow_traps"] = allow_traps
                if authtype is not None:
                    parameters["authtype"] = authtype
                if description is not None:
                    parameters["description"] = description
                if follow_redirects is not None:
                    parameters["follow_redirects"] = follow_redirects
                if headers is not None:
                    parameters["headers"] = headers
                if history is not None:
                    parameters["history"] = history
                if http_proxy is not None:
                    parameters["http_proxy"] = http_proxy
                if inventory_link is not None:
                    parameters["inventory_link"] = inventory_link
                if ipmi_sensor is not None:
                    parameters["ipmi_sensor"] = ipmi_sensor
                if jmx_endpoint is not None:
                    parameters["jmx_endpoint"] = jmx_endpoint
                if logtimefmt is not None:
                    parameters["logtimefmt"] = logtimefmt
                if master_itemid is not None:
                    parameters["master_itemid"] = master_itemid
                if params is not None:
                    parameters["params"] = params
                if item_parameters is not None:
                    parameters["parameters"] = item_parameters
                if password is not None:
                    parameters["password"] = password
                if body_type is not None:
                    parameters["post_type"] = body_type
                if body is not None:
                    parameters["posts"] = body
                if privatekey is not None:
                    parameters["privatekey"] = privatekey
                if url_query is not None:
                    parameters["query_fields"] = url_query
                if http_method is not None:
                    parameters["request_method"] = http_method
                if retrieve_mode is not None:
                    parameters["retrieve_mode"] = retrieve_mode
                if snmp_oid is not None:
                    parameters["snmp_oid"] = snmp_oid
                if ssl_cert_file is not None:
                    parameters["ssl_cert_file"] = ssl_cert_file
                if ssl_key_file is not None:
                    parameters["ssl_key_file"] = ssl_key_file
                if ssl_key_password is not None:
                    parameters["ssl_key_password"] = ssl_key_password
                if status_codes is not None:
                    parameters["status_codes"] = status_codes
                if timeout is not None:
                    parameters["timeout"] = timeout
                if trapper_hosts is not None:
                    parameters["trapper_hosts"] = trapper_hosts
                if trends is not None:
                    parameters["trends"] = trends
                if units is not None:
                    parameters["units"] = units
                if username is not None:
                    parameters["username"] = username
                if verify_host is not None:
                    parameters["verify_host"] = verify_host
                if verify_peer is not None:
                    parameters["verify_peer"] = verify_peer
                if tags is not None:
                    parameters["tags"] = tags
                if preprocessing is not None:
                    parameters["preprocessing"] = preprocessing                
                # raise Exception(parameters)
                item_list = self._zapi.item.create(parameters)
                if len(item_list["itemids"]) >= 1:
                    return item_list["itemids"][0]
        except Exception as e:
            self._module.fail_json(msg="Failed to create item %s: %s" % (item_name, e))
    
    def update_item(self, item_name, item_id, key, update_interval, interfaceid, url, allow_traps, authtype, description, follow_redirects, headers, history, http_proxy, inventory_link, ipmi_sensor, jmx_endpoint, logtimefmt, master_itemid, params, item_parameters, password, body_type, body, privatekey, url_query, http_method, retrieve_mode, snmp_oid, ssl_cert_file, ssl_key_file, ssl_key_password, status_codes, timeout, trapper_hosts, trends, units, username, verify_host, verify_peer, tags, preprocessing):  
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            else:
                parameters = {"itemid": item_id}
                if item_name is not None:
                    parameters["name"] = item_name
                if key is not None:
                    parameters["key_"] = key
                if update_interval is not None:
                    parameters["delay"] = update_interval
                if interfaceid is not None:
                    parameters["interfaceid"] = interfaceid
                if url is not None:
                    parameters["url"] = url
                if allow_traps is not None:
                    parameters["allow_traps"] = allow_traps
                if authtype is not None:
                    parameters["authtype"] = authtype
                if description is not None:
                    parameters["description"] = description
                if follow_redirects is not None:
                    parameters["follow_redirects"] = follow_redirects
                if headers is not None:
                    parameters["headers"] = headers
                if history is not None:
                    parameters["history"] = history
                if http_proxy is not None:
                    parameters["http_proxy"] = http_proxy
                if inventory_link is not None:
                    parameters["inventory_link"] = inventory_link
                if ipmi_sensor is not None:
                    parameters["ipmi_sensor"] = ipmi_sensor
                if jmx_endpoint is not None:
                    parameters["jmx_endpoint"] = jmx_endpoint
                if logtimefmt is not None:
                    parameters["logtimefmt"] = logtimefmt
                if master_itemid is not None:
                    parameters["master_itemid"] = master_itemid
                if params is not None:
                    parameters["params"] = params
                if item_parameters is not None:
                    parameters["parameters"] = item_parameters
                if password is not None:
                    parameters["password"] = password
                if body_type is not None:
                    parameters["post_type"] = body_type
                if body is not None:
                    parameters["posts"] = body
                if privatekey is not None:
                    parameters["privatekey"] = privatekey
                if url_query is not None:
                    parameters["query_fields"] = url_query
                if http_method is not None:
                    parameters["request_method"] = http_method
                if retrieve_mode is not None:
                    parameters["retrieve_mode"] = retrieve_mode
                if snmp_oid is not None:
                    parameters["snmp_oid"] = snmp_oid
                if ssl_cert_file is not None:
                    parameters["ssl_cert_file"] = ssl_cert_file
                if ssl_key_file is not None:
                    parameters["ssl_key_file"] = ssl_key_file
                if ssl_key_password is not None:
                    parameters["ssl_key_password"] = ssl_key_password
                if status_codes is not None:
                    parameters["status_codes"] = status_codes
                if timeout is not None:
                    parameters["timeout"] = timeout
                if trapper_hosts is not None:
                    parameters["trapper_hosts"] = trapper_hosts
                if trends is not None:
                    parameters["trends"] = trends
                if units is not None:
                    parameters["units"] = units
                if username is not None:
                    parameters["username"] = username
                if verify_host is not None:
                    parameters["verify_host"] = verify_host
                if verify_peer is not None:
                    parameters["verify_peer"] = verify_peer
                if tags is not None:
                    parameters["tags"] = tags
                if preprocessing is not None:
                    parameters["preprocessing"] = preprocessing                
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

    def get_hostid_by_host_name(self, host_name):
        host_list = self._zapi.host.get({"output": "extend", "filter": {"host": [host_name]}})
        if len(host_list) < 1:
            self._module.fail_json(msg="Host not found: %s" % host_name)
        else:
            return int(host_list[0]["hostid"])
        
    def check_all_properties(self, item_id, key, host_id, host_name, update_interval, interfaceid, url, allow_traps, authtype, description, follow_redirects, headers, history, http_proxy, inventory_link, ipmi_sensor, jmx_endpoint, logtimefmt, master_itemid, params, parameters, password, body_type, body, privatekey, url_query, http_method, retrieve_mode, snmp_oid, ssl_cert_file, ssl_key_file, ssl_key_password, status_codes, timeout, trapper_hosts, trends, units, username, verify_host, verify_peer, tags, preprocessing):
        exist_item = self._zapi.item.get({"output": "extend", "filter": {"itemid": item_id}})[0]
        if host_id and host_id != int(exist_item["hostid"]):
            return True
        if key and key != exist_item["key_"]:
            return True
        if update_interval and update_interval != exist_item["delay"]:
            return True
        if interfaceid and interfaceid != exist_item["interfaceid"]:
            return True
        if url and url != exist_item["url"]:
            return True
        if allow_traps and allow_traps != exist_item["allow_traps"]:
            return True
        if authtype and authtype != exist_item["authtype"]:
            return True
        if description and description != exist_item["description"]:
            return True
        if follow_redirects and follow_redirects != exist_item["follow_redirects"]:
            return True
        if headers and headers != exist_item["headers"]:
            return True
        if history and history != exist_item["history"]:
            return True
        if http_proxy and http_proxy != exist_item["http_proxy"]:
            return True
        if inventory_link and inventory_link != exist_item["inventory_link"]:
            return True
        if ipmi_sensor and ipmi_sensor != exist_item["ipmi_sensor"]:
            return True
        if jmx_endpoint and jmx_endpoint != exist_item["jmx_endpoint"]:
            return True
        if logtimefmt and logtimefmt != exist_item["logtimefmt"]:
            return True
        if master_itemid and master_itemid != exist_item["master_itemid"]:
            return True
        if params and params != exist_item["params"]:
            return True
        if parameters and parameters != exist_item["parameters"]:
            return True
        if password and password != exist_item["password"]:
            return True
        if body_type and body_type != exist_item["post_type"]:
            return True
        if body and body != exist_item["posts"]:
            return True
        if privatekey and privatekey != exist_item["privatekey"]:
            return True
        if url_query and url_query != exist_item["query_fields"]:
            return True
        if http_method and http_method != exist_item["request_method"]:
            return True
        if retrieve_mode and retrieve_mode != exist_item["retrieve_mode"]:
            return True
        if snmp_oid and snmp_oid != exist_item["snmp_oid"]:
            return True
        if ssl_cert_file and ssl_cert_file != exist_item["ssl_cert_file"]:
            return True
        if ssl_key_file and ssl_key_file != exist_item["ssl_key_file"]:
            return True
        if ssl_key_password and ssl_key_password != exist_item["ssl_key_password"]:
            return True
        if status_codes and status_codes != exist_item["status_codes"]:
            return True
        if timeout and timeout != exist_item["timeout"]:
            return True
        if trapper_hosts and trapper_hosts != exist_item["trapper_hosts"]:
            return True
        if trends and trends != exist_item["trends"]:
            return True
        if units and units != exist_item["units"]:
            return True
        if username and username != exist_item["username"]:
            return True
        if verify_host and verify_host != exist_item["verify_host"]:
            return True
        if verify_peer and verify_peer != exist_item["verify_peer"]:
            return True
        if tags and tags != exist_item["tags"]:
            return True
        if preprocessing and preprocessing != exist_item["preprocessing"]:
            return True        

        return False
    
def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        item_name=dict(type="str", required=True),
        key=dict(type="str", required_if=[["state", 1, ["present"]]]),
        host_name=dict(type="str", required_if=[["state", 1, ["present"]]]),
        state=dict(type="str", default="present", choices=["present", "absent"]),
        status=dict(type="str", default="enabled", choices=["enabled", "disabled"]),
        type=dict(type="str", choices=["zabbix_agent", "0", "zabbix_trapper", "2", "simple_check", "3", "zabbix_internal", "5", "zabbix_agent_active", "7", "web_item", "9", "external_check", "10", "database_monitor", "11", "ipmi", "12", "ssh", "13", "telnet", "14", "calculated", "15", "jmx", "16", "snmp_trap", "17", "dependent", "18", "http", "19", "snmp_agent", "20", "script", "21"], required_if=[["state", 1, ["present"]]]),
        value_type=dict(type="str", choices=["float", "0", "character", "1", "log", "2", "unsigned", "3", "text", "4"], required_if=[["state", 1, ["present"]]]),
        update_interval=dict(type="str", default="10s", required_if=[
            ["type", 3, ["simple_check"]],
            ["type", 5, ["zabbix_internal"]],
            ["type", 7, ["zabbix_agent_active"]],
            ["type", 10, ["external_check"]],
            ["type", 11, ["database_monitor"]],
            ["type", 12, ["ipmi"]],
            ["type", 13, ["ssh"]],
            ["type", 14, ["telnet"]],
            ["type", 15, ["calculated"]],
            ["type", 16, ["jmx"]],
            ["type", 19, ["http"]],
            ["type", 20, ["snmp_agent"]],
            ["type", 21, ["script"]]
            ]),
        interface=dict(type="str", required_if=[
            ["type", 0, ["zabbix_agent"]],
            ["type", 12, ["ipmi"]],
            ["type", 16, ["jmx"]],
            ["type", 17, ["snmp_trap"]],
            ["type", 20, ["snmp_agent"]],
            ]),
        url=dict(type="str", required_if=[
            ["type", 19, ["http"]]
            ]),
        allow_traps=dict(type="bool"),
        authtype=dict(type="str", choices=["password", "0", "publickey", "1", "none", "0", "basic", "1", "ntlm", "2", "kerberos", "3"], default="none"),
        description=dict(type="str"),
        follow_redirects=dict(type="bool"),
        headers=dict(type="dict", elements="dict"),
        history=dict(type="str"),
        http_proxy=dict(type="str"),
        inventory_link=dict(type="str"),
        ipmi_sensor=dict(type="str", required_if=[
            ["type", 12, ["ipmi"]],
        ]),
        jmx_endpoint=dict(type="str"),
        logtimefmt=dict(type="str"),
        master_item=dict(type="str", required_if=[
            ["type", 18, ["dependent"]],
        ]),
        output_format=dict(type="str", choices=["raw", "0", "json", "1"]),
        params=dict(type="str", required_if=[
            ["type", 11, ["database_monitor"]],
            ["type", 13, ["ssh"]],
            ["type", 14, ["telnet"]],
            ["type", 15, ["calculated"]],
            ["type", 21, ["script"]]
        ]),
        parameters=dict(type="str"),
        password=dict(type="str", no_log=True),
        body_type=dict(type="str", choices=["raw", "0", "json", "2", "xml", "3"]),
        body=dict(type="str", required_if=[
            ["body_type", 1, ["json"]],
            ["body_type", 2, ["xml"]],
        ]),
        privatekey=dict(type="str", no_log=True, required_if=[
            ["auth_type", 1, ["publickey"]]
        ]),
        url_query=dict(type="dict", elements="dict"),
        http_method=dict(type="str", choices=["GET", "0", "POST", "1", "PUT", "2", "HEAD", "3"]),
        retrieve_mode=dict(type="str", choices=["body", "0", "headers", "1", "both", "2"]),
        snmp_oid=dict(type="str", required_if=[
            ["type", 20, ["snmp_agent"]],
        ]),
        ssl_cert_file=dict(type="str", no_log=True),
        ssl_key_file=dict(type="str", no_log=True),
        ssl_key_password=dict(type="str", no_log=True),
        status_codes=dict(type="list", elements="str", default=["200"]),
        timeout=dict(type="str"),
        trapper_hosts=dict(type="str"),
        trends=dict(type="str"),
        units=dict(type="str"),
        username=dict(type="str", no_log=True, required_if=[
            ["type", 13, ["ssh"]],
            ["type", 14, ["telnet"]],
            ["type", 16, ["jmx"]],
        ]),
        verify_host=dict(type="bool"),
        verify_peer=dict(type="bool"),
        tags=dict(type="list", elements="dict", default=[], options=dict(
            tag=dict(type="str", required=True),
            value=dict(type="str", required=True)
            )),
        preprocessing=dict(type="list", elements="dict", default=[], options=dict(
            type=dict(type="str", required=True, choices=["custom_multiplier", "1", "right_trim", "2", "left_trim", "3", "trim", "4", "regex", "5", "bool_to_dec", "6", "oct_to_dec", "7", "hex_to_dec", "8", "simple_change", "9", "change_per_sec", "10", "xml_xpath", "11", "jsonpath", "12", "in_range", "13", "regex_match", "14", "regex_not_match", "15", "json_error_check", "16", "xml_error_check", "17", "regex_error_check", "18", "discard_unchanged", "19", "discard_unchanged_with_heartbeat", "20", "javascript", "21", "prometheus_pattern", "22", "prometheus_to_json", "23", "csv_to_json", "24", "replace", "25", "check_unsupported", "26", "xml_to_json", "27", "snmp_walk_value", "28", "snmp_walk_to_json", "29" ]),
            params=dict(type="str", required_if=[
                ["type", 1, ["custom_multiplier"]],
                ["type", 2, ["right_trim"]],
                ["type", 3, ["left_trim"]],
                ["type", 4, ["trim"]],
                ["type", 5, ["regex"]],
                ["type", 11, ["xml_xpath"]],
                ["type", 12, ["jsonpath"]],
                ["type", 13, ["in_range"]],
                ["type", 14, ["regex_match"]],
                ["type", 15, ["regex_not_match"]],
                ["type", 16, ["json_error_check"]],
                ["type", 17, ["xml_error_check"]],
                ["type", 18, ["regex_error_check"]],
                ["type", 20, ["discard_unchanged_with_heartbeat"]],
                ["type", 21, ["javascript"]],
                ["type", 22, ["prometheus_pattern"]],
                ["type", 23, ["prometheus_to_json"]],
                ["type", 24, ["csv_to_json"]],
                ["type", 25, ["replace"]],
                ["type", 28, ["snmp_walk_value"]],
                ["type", 29, ["snmp_walk_to_json"]]
                ]),
            error_handler=dict(type="str", required=True, default="0", choices=["zabbix", "0", "discard", "1", "custom_value", "2", "custom_message", "3"]),
            error_handler_params=dict(type="str", required_if=[
                ["error_handler", 2, "custom_value"], 
                ["error_handler", 3, "custom_message"]
                ])
        ))
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
    update_interval = module.params["update_interval"]
    interface = module.params["interface"]
    url = module.params["url"]
    allow_traps = module.params["allow_traps"]
    authtype = module.params["authtype"]
    description = module.params["description"]
    follow_redirects = module.params["follow_redirects"]
    headers = module.params["headers"]
    history = module.params["history"]
    http_proxy = module.params["http_proxy"]
    inventory_link = module.params["inventory_link"]
    ipmi_sensor = module.params["ipmi_sensor"]
    jmx_endpoint = module.params["jmx_endpoint"]
    logtimefmt = module.params["logtimefmt"]
    master_item = module.params["master_item"]
    output_format = module.params["output_format"]
    params = module.params["params"]
    parameters = module.params["parameters"]
    password = module.params["password"]
    body_type = module.params["body_type"]
    body = module.params["body"]
    privatekey = module.params["privatekey"]
    url_query = module.params["url_query"]
    http_method = module.params["http_method"]
    retrieve_mode = module.params["retrieve_mode"]
    snmp_oid = module.params["snmp_oid"]
    ssl_cert_file = module.params["ssl_cert_file"]
    ssl_key_file = module.params["ssl_key_file"]
    ssl_key_password = module.params["ssl_key_password"]
    status_codes = module.params["status_codes"]
    timeout = module.params["timeout"]
    trapper_hosts = module.params["trapper_hosts"]
    trends = module.params["trends"]
    units = module.params["units"]
    username = module.params["username"]
    verify_host = module.params["verify_host"]
    verify_peer = module.params["verify_peer"]
    tags = module.params["tags"]
    preprocessing = module.params["preprocessing"]


    status = 1 if status == "disabled" else 0

    item = Item(module)

    preprocessing = item.construct_preprocessing(preprocessing)

    # find host id
    host_id = ""
    if host_name is not None:
        host_id = item.get_hostid_by_host_name(host_name)
        if host_id is None:
            module.fail_json(msg="host %s does not exist." % host_name)
    else:
        module.fail_json(msg="host_name must not be empty.")
    
    # get interface id
    if interface:
        interface = item.get_host_interfaceid_by_host(interface, host_id)

    # convert bools/choices to integers
    if allow_traps:
        allow_traps = 1 if allow_traps == True else 0
    if authtype:
        authtype_types = {"password": 0, "publickey": 1, "none": 0, "basic": 1, "ntlm": 2, "kerberos": 3}
        if authtype in list(authtype_types.keys()):
            authtype = authtype_types[authtype]
        else:
            authtype = int(authtype)
    if follow_redirects:
        follow_redirects = 1 if follow_redirects == True else 0
    if output_format:
        output_format_types = {"raw": 0, "json": 1}
        if output_format in list(output_format_types.keys()):
            output_format = output_format_types[output_format]
        else:
            output_format = int(output_format)
    if body_type:
        body_type_types = {"raw": 0, "json": 2, "xml": 3}
        if body_type in list(body_type_types.keys()):
            body_type = body_type_types[body_type]
        else:
            body_type = int(body_type)
    if http_method:
        http_method_types = {"GET": 0, "POST": 1, "PUT": 2, "HEAD": 3}
        if http_method in list(http_method_types.keys()):
            http_method = http_method_types[http_method]
        else:
            http_method = int(http_method)
    if retrieve_mode:
        retrieve_mode_types = {"body": 0, "headers": 1, "both": 2}
        if retrieve_mode in list(retrieve_mode_types.keys()):
            retrieve_mode = retrieve_mode_types[retrieve_mode]
        else:
            retrieve_mode = int(retrieve_mode)
    if verify_host:
        verify_host = 1 if verify_host == True else 0
    if verify_peer:
        verify_peer = 1 if verify_peer == True else 0
    # convert list to comma-seperated string
    if status_codes:
        status_codes = ",".join(status_codes)

    if master_item:
        master_item = item.get_itemid_by_item_and_hostid(master_item, host_id)
    type_types = {"zabbix_agent": 0, "zabbix_trapper": 2, "simple_check": 3, "zabbix_internal": 5, "zabbix_agent_active": 7, "web_item": 9, "external_check": 10, "database_monitor": 11, "ipmi": 12, "ssh": 13, "telnet": 14, "calculated": 15, "jmx": 16, "snmp_trap": 17, "dependent": 18, "http": 19, "snmp_agent": 20, "script": 21}
    value_type_types = {"float": 0, "character": 1, "log": 2, "unsigned": 3, "text": 4}
    
    if state == "present":
        if type in list(type_types.keys()):
            type = type_types[type]
        else:
            type = int(type)

        if value_type in list(value_type_types.keys()):
            value_type = value_type_types[value_type]
        else:
            value_type = int(value_type)    

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
            if item.check_all_properties(item_id, key, host_id, host_name, update_interval, interface, url, allow_traps, authtype, description, follow_redirects, headers, history, http_proxy, inventory_link, ipmi_sensor, jmx_endpoint, logtimefmt, master_item, params, parameters, password, body_type, body, privatekey, url_query, http_method, retrieve_mode, snmp_oid, ssl_cert_file, ssl_key_file, ssl_key_password, status_codes, timeout, trapper_hosts, trends, units, username, verify_host, verify_peer, tags, preprocessing):
                # update the item
                item.update_item(item_name, item_id, key, update_interval, interface, url, allow_traps, authtype, description, follow_redirects, headers, history, http_proxy, inventory_link, ipmi_sensor, jmx_endpoint, logtimefmt, master_item, params, parameters, password, body_type, body, privatekey, url_query, http_method, retrieve_mode, snmp_oid, ssl_cert_file, ssl_key_file, ssl_key_password, status_codes, timeout, trapper_hosts, trends, units, username, verify_host, verify_peer, tags, preprocessing)

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
        item_id = item.add_item(item_name, key, host_id, type, value_type, update_interval, interface, url, allow_traps, authtype, description, follow_redirects, headers, history, http_proxy, inventory_link, ipmi_sensor, jmx_endpoint, logtimefmt, master_item, params, parameters, password, body_type, body, privatekey, url_query, http_method, retrieve_mode, snmp_oid, ssl_cert_file, ssl_key_file, ssl_key_password, status_codes, timeout, trapper_hosts, trends, units, username, verify_host, verify_peer, tags, preprocessing)

        module.exit_json(changed=True, result="Successfully added item %s on host %s" % (item_name, host_name))

if __name__ == "__main__":
    main()
