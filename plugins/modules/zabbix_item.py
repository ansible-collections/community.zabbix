#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2013-2014, Epic Games, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
module: zabbix_item
short_description: Create/update/delete Zabbix items on hosts
description:
    - This module allows you to create, modify and delete Zabbix item entries associated on hosts.
author:
    - "Cove (@cove)"
    - Tony Minfei Ding (!UNKNOWN)
    - Harrison Gu (@harrisongu)
    - Werner Dijkerman (@dj-wasabi)
    - Eike Frost (@eikef)
    - Lars van der Hooft (@ljvdhooft)
requirements:
    - "python >= 3.9"
options:
    item_name:
        description:
            - Name of the item in Zabbix.
        type: str
        required: true
    key:
        description:
            - Key of the item in Zabbix.
            - Key must be unique from other items.
        type: str
    description:
        description:
            - Description of the item in Zabbix.
        type: str
    host_name:
        description:
            - Name of the host associated to the item.
            - Required if I(state="present")
        type: str
    state:
        description:
            - State of the item.
            - On C(present), it will create if item does not exist or update the item if the associated data is different.
            - On C(absent), it will remove an item if it exists.
        choices: ["present", "absent"]
        default: "present"
        type: str
    status:
        description:
            - Monitoring status of the item.
        choices: ["enabled", "disabled"]
        default: "enabled"
        type: str
    type:
        description:
            - Type of the check performed.
            - Numerical values are also accepted for type.
            - Required if I(state="present")
            - 0 = zabbix_agent 
            - 2 = zabbix_trapper 
            - 3 = simple_check 
            - 5 = zabbix_internal 
            - 7 = zabbix_agent_active 
            - 10 = external_check 
            - 11 = database_monitor 
            - 12 = ipmi 
            - 13 = ssh 
            - 14 = telnet 
            - 15 = calculated 
            - 16 = jmx 
            - 17 = snmp_trap 
            - 18 = dependent 
            - 19 = http 
            - 20 = snmp_agent 
            - 21 = script        
        choices: ["zabbix_agent", "0", "zabbix_trapper", "2", "simple_check", "3", "zabbix_internal", "5", "zabbix_agent_active", "7", "web_item", "9", "external_check", "10", "database_monitor", "11", "ipmi", "12", "ssh", "13", "telnet", "14", "calculated", "15", "jmx", "16", "snmp_trap", "17", "dependent", "18", "http", "19", "snmp_agent", "20", "script", "21"]
        type: str
    value_type:
        description:
            - Type of the data stored during the check.
            - Required if I(state="present")
            - Numerical values are also accepted for value_type.
            - 0 = float
            - 1 = character
            - 2 = log
            - 3 = unsigned
            - 4 = text
        choices: ["float", "0", "character", "1", "log", "2", "unsigned", "3", "text", "4"]
        type: str
    update_interval:
        description:
            - The interval at which the item should perform checks.
            - Required if I(state="present")
        type: str
    interface:
        description:
            - The host's interface specified for checks.
            - Formatted in [ip/dns]:[port]
            - Required if I(type="zabbix_agent")
            - Required if I(type="ipmi")
            - Required if I(type="jmx")
            - Required if I(type="snmp_trap")
            - Required if I(type="snmp_agent")
        type: str
    url:
        description:
            - The URL to perform checks at.
            - Required if I(type="http")
        type: str
    allow_traps:
        description:
            - Allow to populate value similarly to the trapper item.
        type: bool
    authtype:
        description:
            - Authentication method
            - If I(type="ssh"): 0 = password (default)
            - If I(type="ssh"): 1 = publickey
            - If I(type="http"): 0 = none (default)
            - If I(type="http"): 1 = basic
            - If I(type="http"): 2 = ntlm
            - If I(type="http"): 3 = kerberos
        type: str
        choices: ["password", "0", "publickey", "1", "none", "0", "basic", "1", "ntlm", "2", "kerberos", "3"]
    follow_redirects:
        description:
            - Follow response redirects while polling http data.
        type: bool
    formula:
        description:
            - Formula for the calculated items when .
        type: str
    headers:
        description:
            - Headers used for a HTTP request.
            - Headers must be formatted as a dict.
        type: dict
    history:
        description:
            - Defines the time that history data is stored.
        type: str
    http_proxy:
        description:
            - Proxy connection used in a HTTP request.
        type: str
    inventory_link:
        description:
            - Defines the property used to populate the inventory field with the check result
            - Supported if I(value_type="float")
            - Supported if I(value_type="character")
            - Supported if I(value_type="unsigned")
            - Supported if I(value_type="text")
            - 1 = type
            - 2 = type_full
            - 3 = name
            - 4 = alias
            - 5 = os
            - 6 = os_full
            - 7 = os_short
            - 8 = serialno_a
            - 9 = serialno_b
            - 10 = tag
            - 11 = asset_tag
            - 12 = macaddress_a
            - 13 = macaddress_b
            - 14 = hardware
            - 15 = hardware_full
            - 16 = software
            - 17 = software_full
            - 18 = software_app_a
            - 19 = software_app_b
            - 20 = software_app_c
            - 21 = software_app_d
            - 22 = software_app_e
            - 23 = contact
            - 24 = location
            - 25 = location_lat
            - 26 = location_lon
            - 27 = notes
            - 28 = chassis
            - 29 = model
            - 30 = hw_arch
            - 31 = vendor
            - 32 = contract_number
            - 33 = installer_name
            - 34 = deployment_status
            - 35 = url_a
            - 36 = url_b
            - 37 = url_c
            - 38 = host_networks
            - 39 = host_netmask
            - 40 = host_router
            - 41 = oob_ip
            - 42 = oob_netmask
            - 43 = oob_router
            - 44 = date_hw_purchase
            - 45 = date_hw_install
            - 46 = date_hw_expiry
            - 47 = date_hw_decomm
            - 48 = site_address_a
            - 49 = site_address_b
            - 50 = site_address_c
            - 51 = site_city
            - 52 = site_state
            - 53 = site_country
            - 54 = site_zip
            - 55 = site_rack
            - 56 = site_notes
            - 57 = poc_1_name
            - 58 = poc_1_email
            - 59 = poc_1_phone_a
            - 60 = poc_1_phone_b
            - 61 = poc_1_cell
            - 62 = poc_1_screen
            - 63 = poc_1_notes
            - 64 = poc_2_name
            - 65 = poc_2_email
            - 66 = poc_2_phone_a
            - 67 = poc_2_phone_b
            - 68 = poc_2_cell
            - 69 = poc_2_screen
            - 70 = poc_2_notes
        choices: ["type", "1", "type_full", "2", "name", "3", "alias", "4", "os", "5", "os_full", "6", "os_short", "7", "serialno_a", "8", "serialno_b", "9", "tag", "10", "asset_tag", "11", "macaddress_a", "12", "macaddress_b", "13", "hardware", "14", "hardware_full", "15", "software", "16", "software_full", "17", "software_app_a", "18", "software_app_b", "19", "software_app_c", "20", "software_app_d", "21", "software_app_e", "22", "contact", "23", "location", "24", "location_lat", "25", "location_lon", "26", "notes", "27", "chassis", "28", "model", "29", "hw_arch", "30", "vendor", "31", "contract_number", "32", "installer_name", "33", "deployment_status", "34", "url_a", "35", "url_b", "36", "url_c", "37", "host_networks", "38", "host_netmask", "39", "host_router", "40", "oob_ip", "41", "oob_netmask", "42", "oob_router", "43", "date_hw_purchase", "44", "date_hw_install", "45", "date_hw_expiry", "46", "date_hw_decomm", "47", "site_address_a", "48", "site_address_b", "49", "site_address_c", "50", "site_city", "51", "site_state", "52", "site_country", "53", "site_zip", "54", "site_rack", "55", "site_notes", "56", "poc_1_name", "57", "poc_1_email", "58", "poc_1_phone_a", "59", "poc_1_phone_b", "60", "poc_1_cell", "61", "poc_1_screen", "62", "poc_1_notes", "63", "poc_2_name", "64", "poc_2_email", "65", "poc_2_phone_a", "66", "poc_2_phone_b", "67", "poc_2_cell", "68", "poc_2_screen", "69", "poc_2_notes", "70"]
        type: str
    ipmi_sensor:
        description:
            - Defines IPMI sensor.
        type: str
    jmx_endpoint:
        description:
            - Defines custom connection string for JMX agent.
        type: str
    logtimefmt:
        description:
            - Defines the format of the time in log entries.
        type: str
    master_item:
        description:
            - Defines the master item used in dependent checks.
            - Required if I(type="dependent")
        type: str
    convert_json:
        description:
            - Defines if the response body should be converted to a JSON object.
        type: bool
    script:
        description:
            - The script used when I(type="script"), I(type="ssh") or I(type="telnet").
        type: str
    parameters:
        description:
            - Additional parameters for script type.
        type: str
    password:
        description:
            - Password used when I(type="jmx"), I(type="simple_check"), I(type="ssh"), I(type="telnet"), I(type="database_monitor"), I(type="http").
            - Required if I(type="jmx") and username is set.
        type: str
    body_type:
        description:
            - Defines the body type of the HTTP request.
            - 0 = raw
            - 1 = json
            - 2 = xml
        choices: ["raw", "0", "json", "2", "xml", "3"]
        type: str
    body:
        description:
            - Defines the body used for the HTTP request.
        type: str
    privatekey:
        description:
            - Defines the path to the private key file used for the SSH agent when using public key authentication.
            - Required if I(type="ssh") and I(authtype="publickey")
        type: str
    publickey:
        description:
            - Defines the path to the public key file used for the SSH agent when using public key authentication.
            - Required if I(type="ssh") and I(authtype="publickey")
        type: str
    url_query:
        description:
            - Defines the query parameters used for the HTTP request.
            - Query entries must be formatted in object form (dict).
        type: dict
    http_method:
        description:
            - Defines the HTTP method used for the request.
            - 0 = GET
            - 1 = POST
            - 2 = PUT
            - 3 = HEAD
        choices: ["GET", "0", "POST", "1", "PUT", "2", "HEAD", "3"]
        type: str
    retrieve_mode:
        description:
            - Defines if either the body, headers or both are processed in response of the HTTP request.
            - 0 = body (default)
            - 1 = headers
            - 2 = both
        choices: ["body", "0", "headers", "1", "both", "2"]
        type: str
    snmp_oid:
        description:
            - Defines the OID filtered on with the SMTP agent.
            - Required if I(type="snmp_agent")
        type: str
    db_query:
        description:
            - Defines the query used for the database_monitor check.
            - Required if I(type="database_monitor")
        type: str
    ssl_cert_file:
        description:
            - Defines the path of the public SSL key file used with the HTTP check.
        type: str
    ssl_key_file:
        description:
            - Defines the path of the private SSL key file used with the HTTP check.
        type: str
    ssl_key_password:
        description:
            - Defines the password of the SSL key file used with the HTTP check.
        type: str
    status_codes:
        description:
            - Defines the response status codes filtered on with the HTTP check.
            - Entries must be formatted in list
        type: list
    timeout:
        description:
            - Defines the timeout for item polling.
        type: str
    allowed_hosts:
        description:
            - Allowed hosts.
        type: str
    trends:
        description:
            - Defines the time of how long data should be stored.
        type: str
    units:
        description:
            - Defines the unit of the check's value.
        type: str
    username:
        description:
            - Username for check authentication.
            - Required if I(type="ssh")
            - Required if I(type="telnet")
            - Required if I(type="jmx")
        type: str
    verify_host:
        description:
            - Defines an extra check if the host's name matches the certificate.
        type: bool
    verify_peer:
        description:
            - Defines an extra check if the host's certificate is authentic.
        type: bool
    tags:
        description:
            - Defines tags used by Zabbix.
            - Entries must be formatted as a list with objects that contain 'tag' and 'value'
        type: list
        elements: dict
        suboptions:
            tag:
                description:
                    - The name of the tag
                type: str
            value:
                description:
                    - The value of the tag
                type: str
    preprocessing:
        description:
            - Defines the Zabbix preprocessing rules used for the item.
            - Entries must be formatted as a list with objects that contain 'type', 
        type: list
        elements: dict
        suboptions:
            type:
                description:
                    - The type of Zabbix preprocessing used.
                    - 1 = custom_multiplier
                    - 2 = right_trim
                    - 3 = left_trim
                    - 4 = trim
                    - 5 = regex
                    - 6 = bool_to_dec
                    - 7 = oct_to_dec
                    - 8 = hex_to_dec
                    - 9 = simple_change
                    - 10 = change_per_sec
                    - 11 = xml_xpath
                    - 12 = jsonpath
                    - 13 = in_range
                    - 14 = regex_match
                    - 15 = regex_not_match
                    - 16 = json_error_check
                    - 17 = xml_error_check
                    - 18 = regex_error_check
                    - 19 = discard_unchanged
                    - 20 = discard_unchanged_with_heartbeat
                    - 21 = javascript
                    - 22 = prometheus_pattern
                    - 23 = prometheus_to_json
                    - 24 = csv_to_json
                    - 25 = replace
                    - 26 = check_unsupported
                    - 27 = xml_to_json
                    - 28 = snmp_walk_value
                    - 29 = snmp_walk_to_json
                choices: ["custom_multiplier", "1", "right_trim", "2", "left_trim", "3", "trim", "4", "regex", "5", "bool_to_dec", "6", "oct_to_dec", "7", "hex_to_dec", "8", "simple_change", "9", "change_per_sec", "10", "xml_xpath", "11", "jsonpath", "12", "in_range", "13", "regex_match", "14", "regex_not_match", "15", "json_error_check", "16", "xml_error_check", "17", "regex_error_check", "18", "discard_unchanged", "19", "discard_unchanged_with_heartbeat", "20", "javascript", "21", "prometheus_pattern", "22", "prometheus_to_json", "23", "csv_to_json", "24", "replace", "25", "check_unsupported", "26", "xml_to_json", "27", "snmp_walk_value", "28", "snmp_walk_to_json", "29"]
                type: str
            params:
                description:
                    - Additional parameters depending on the type of preprocessing.
                    - Required if I(type="custom_multiplier")
                    - Required if I(type="right_trim")
                    - Required if I(type="left_trim")
                    - Required if I(type="trim")
                    - Required if I(type="regex")
                    - Required if I(type="xml_xpath")
                    - Required if I(type="jsonpath")
                    - Required if I(type="in_range")
                    - Required if I(type="regex_match")
                    - Required if I(type="regex_not_match")
                    - Required if I(type="json_error_check")
                    - Required if I(type="xml_error_check")
                    - Required if I(type="regex_error_check")
                    - Required if I(type="discard_unchanged_with_heartbeat")
                    - Required if I(type="javascript")
                    - Required if I(type="prometheus_pattern")
                    - Required if I(type="prometheus_to_json")
                    - Required if I(type="csv_to_json")
                    - Required if I(type="replace")
                    - Required if I(type="snmp_walk_value")
                    - Required if I(type="snmp_walk_to_jso")
                type: str
            error_handling:
                description:
                    - Defines the preprocessing error handling.
                    - 0 = zabbix
                    - 1 = discard
                    - 2 = custom_value
                    - 3 = custom_message
                    - Required if I(type="custom_multiplier")
                    - Required if I(type="regex")
                    - Required if I(type="bool_to_dec")
                    - Required if I(type="oct_to_dec")
                    - Required if I(type="hex_to_dec")
                    - Required if I(type="simple_change")
                    - Required if I(type="change_per_sec")
                    - Required if I(type="xml_xpath")
                    - Required if I(type="jsonpath")
                    - Required if I(type="in_range")
                    - Required if I(type="regex_match")
                    - Required if I(type="regex_not_match")
                    - Required if I(type="json_error_check")
                    - Required if I(type="xml_error_check")
                    - Required if I(type="regex_error_check")
                    - Required if I(type="prometheus_pattern")
                    - Required if I(type="prometheus_to_json")
                    - Required if I(type="csv_to_json")
                    - Required if I(type="check_unsupported")
                    - Required if I(type="xml_to_json")
                    - Required if I(type="snmp_walk_value")
                    - Required if I(type="snmp_walk_to_json)
                choices: ["zabbix", "0", "discard", "1", "custom_value", "2", "custom_message", "3"]
                type: str
            error_handling_params:
                description:
                    - The parameters used when 'error_handling' is set to 'custom_value' or 'custom_message'
                    - Required if I(error_handling="custom_value")
                    - Required if I(error_handling="custom_message")
                type: str


"""

EXAMPLES = r"""
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

- name: Create a new item or rewrite an existing item's info
# Set task level following variables for Zabbix Server host in task
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
  become: false
  delegate_to: zabbix-example-fqdn.org# you can use delegate_to or task level ansible_host like next example
  community.zabbix.zabbix_item:
    host_name: ExampleHost
    item_name: ExampleItem
    key: ExampleItem
    description: My ExampleItem Description
    type: zabbix_internal
    value_type: text
    status: enabled
    state: present
    tags:
      - tag: ExampleItemTag
        value: ExampleTagValue
      - tag: ExampleItemTag2
        value: ExampleTagValue

- name: Update an existing item's check type
# Set current task level variables for Zabbix Server host in task
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org # you can use task level ansible_host or delegate_to like in previous example
  become: false
  community.zabbix.zabbix_item:
    host_name: ExampleHost
    item_name: ExampleItem
    type: simple_check
"""

import re

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
    
    def get_hostid_by_host_name(self, host_name):
        host_list = self._zapi.host.get({"output": "extend", "filter": {"host": [host_name]}})
        if len(host_list) < 1:
            self._module.fail_json(msg="Host not found: %s" % host_name)
        else:
            return int(host_list[0]["hostid"])
        
    def get_host_interfaceid_by_host(self, interface, host_id, host_name):
        if interface:
            ip, port = interface.split(":")
            parameters = {"output": "extend", "hostid": host_id, "filter": {"port": port}}
            if re.search(r"[a-zA-Z]", ip):
                parameters["filter"]["dns"] = ip
            else:
                parameters["filter"]["ip"] = ip
            result = self._zapi.hostinterface.get(parameters)
            if len(result) > 0:
                return result[0]["interfaceid"]
            else:
                self._module.fail_json(msg="Host interface %s not found on host %s" % (interface, host_name))
        return "0"        

    def construct_preprocessing(self, preprocessing):
        preprocessing_type_types = {"custom_multiplier": 1, "right_trim": 2, "left_trim": 3, "trim": 4, "regex": 5, "bool_to_dec": 6, "oct_to_dec": 7, "hex_to_dec": 8, "simple_change": 9, "change_per_sec": 10, "xml_xpath": 11, "jsonpath": 12, "in_range": 13, "regex_match": 14, "regex_not_match": 15, "json_error_check": 16, "xml_error_check": 17, "regex_error_check": 18, "discard_unchanged": 19, "discard_unchanged_with_heartbeat": 20, "javascript": 21, "prometheus_pattern": 22, "prometheus_to_json": 23, "csv_to_json": 24, "replace": 25, "check_unsupported": 26, "xml_to_json": 27, "snmp_walk_value": 28, "snmp_walk_to_json": 29}
        preprocessing_error_handler_types = {"zabbix": 0, "discard": 1, "custom_value": 2, "custom_message": 3}

        for rule in preprocessing:
            if rule["type"] in list(preprocessing_type_types.keys()):
                rule["type"] = str(preprocessing_type_types[rule["type"]])
            else:
                rule["type"] = str(int(rule["type"]))
                    
            if int(rule["type"]) in list([1, 2, 3, 4, 5, 11, 12, 13, 14, 15, 16, 17, 18, 20, 21, 22, 23, 24, 25, 28, 29]):
                if not rule["params"]:
                    self._module.fail_json(msg="Option 'params' required in combination with the preprocessing type %s" % list(preprocessing_type_types.keys())[rule["type"] + 1])
            else:
                rule["params"] = ""

            if int(rule["type"]) in list([1,5,6,7,8,9,10,11,12,13,14,15,16,17,18,22,23,24,26,27,28,29]):
                if not rule["error_handler"]:
                    self._module.fail_json(msg="Option 'error_handler' required in combination with the preprocessing type %s" % list(preprocessing_type_types.keys())[int(rule["type"])])
                else:
                    if rule["error_handler"] in list(preprocessing_error_handler_types.keys()):
                        rule["error_handler"] = str(preprocessing_error_handler_types[rule["error_handler"]])
                    else:
                        rule["error_handler"] = str(int(rule["error_handler"]))
            else:
                rule["error_handler"] = "0"
                rule["error_handler_params"] = ""

            if int(rule["error_handler"]) in list([2, 3]):
                if not rule["error_handler_params"]:
                    self._module.fail_json(msg="Option 'error_handler_params' required in combination with the preprocessing error handling type %s" % list(preprocessing_error_handler_types.keys())[rule["error_handler_type"]])
            else:
                rule["error_handler_params"] = ""

        return preprocessing

    def add_item(self, item_name, key, host_id, type, status, value_type, update_interval, interfaceid, url, allow_traps, authtype, convert_json, description, follow_redirects, formula, headers, history, http_proxy, inventory_link, ipmi_sensor, jmx_endpoint, logtimefmt, master_itemid, script, item_parameters, password, body_type, body, privatekey, publickey, url_query, http_method, retrieve_mode, snmp_oid, db_query, ssl_cert_file, ssl_key_file, ssl_key_password, status_codes, timeout, allowed_hosts, trends, units, username, verify_host, verify_peer, tags, preprocessing):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            else:
                parameters = {"name": item_name, "key_": key, "hostid": host_id, "status": status, "type": type, "value_type": value_type, "delay": update_interval} #add more parameters
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
                if convert_json is not None:
                    parameters["output_format"] = convert_json
                if follow_redirects is not None:
                    parameters["follow_redirects"] = follow_redirects
                if formula is not None:
                    parameters["params"] = formula
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
                if script is not None:
                    parameters["params"] = script
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
                if publickey is not None:
                    parameters["publickey"] = publickey
                if url_query is not None:
                    parameters["query_fields"] = url_query
                if http_method is not None:
                    parameters["request_method"] = http_method
                if retrieve_mode is not None:
                    parameters["retrieve_mode"] = retrieve_mode
                if snmp_oid is not None:
                    parameters["snmp_oid"] = snmp_oid
                if db_query is not None:
                    parameters["params"] = db_query
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
                if allowed_hosts is not None:
                    parameters["trapper_hosts"] = allowed_hosts
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
                item_list = self._zapi.item.create(parameters)
                if len(item_list["itemids"]) >= 1:
                    return item_list["itemids"][0]
        except Exception as e:
            self._module.fail_json(msg="Failed to create item %s: %s" % (item_name, e))
    
    def update_item(self, item_name, item_id, key, type, status, update_interval, interfaceid, url, allow_traps, authtype, convert_json, description, follow_redirects, formula, headers, history, http_proxy, inventory_link, ipmi_sensor, jmx_endpoint, logtimefmt, master_itemid, script, item_parameters, password, body_type, body, privatekey, publickey, url_query, http_method, retrieve_mode, snmp_oid, db_query, ssl_cert_file, ssl_key_file, ssl_key_password, status_codes, timeout, allowed_hosts, trends, units, username, verify_host, verify_peer, tags, preprocessing):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            else:
                parameters = {"itemid": item_id, "status": status}
                if item_name is not None:
                    parameters["name"] = item_name
                if key is not None:
                    parameters["key_"] = key
                if type is not None:
                    parameters["type"] = type                
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
                if convert_json is not None:
                    parameters["output_format"] = convert_json
                if description is not None:
                    parameters["description"] = description
                if follow_redirects is not None:
                    parameters["follow_redirects"] = follow_redirects
                if formula is not None:
                    parameters["params"] = formula
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
                if script is not None:
                    parameters["params"] = script
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
                if publickey is not None:
                    parameters["publickey"] = publickey
                if url_query is not None:
                    parameters["query_fields"] = url_query
                if http_method is not None:
                    parameters["request_method"] = http_method
                if retrieve_mode is not None:
                    parameters["retrieve_mode"] = retrieve_mode
                if snmp_oid is not None:
                    parameters["snmp_oid"] = snmp_oid
                if db_query is not None:
                    parameters["params"] = db_query
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
                if allowed_hosts is not None:
                    parameters["trapper_hosts"] = allowed_hosts
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

    def check_all_properties(self, item_id, key, host_id, host_name, type, status, update_interval, interfaceid, url, allow_traps, authtype, convert_json, description, follow_redirects, formula, headers, history, http_proxy, inventory_link, ipmi_sensor, jmx_endpoint, logtimefmt, master_itemid, script, parameters, password, body_type, body, privatekey, publickey, url_query, http_method, retrieve_mode, snmp_oid, db_query, ssl_cert_file, ssl_key_file, ssl_key_password, status_codes, timeout, allowed_hosts, trends, units, username, verify_host, verify_peer, tags, preprocessing):
        exist_item = self._zapi.item.get({"output": "extend", "selectPreprocessing": "extend", "selectTags": "extend", "filter": {"itemid": item_id}})[0]
        if host_id and host_id != int(exist_item["hostid"]):
            return True
        if key and key != exist_item["key_"]:
            return True
        if type and int(type) != int(exist_item["type"]):
            return True
        if status and int(status) != int(exist_item["status"]):
            return True
        if update_interval and update_interval != exist_item["delay"]:
            return True
        if interfaceid and int(interfaceid) != int(exist_item["interfaceid"]):
            return True
        if url and url != exist_item["url"]:
            return True
        if allow_traps and int(allow_traps) != int(exist_item["allow_traps"]):
            return True
        if authtype and int(authtype) != int(exist_item["authtype"]):
            return True
        if convert_json and int(convert_json) != int(exist_item["output_format"]):
            return True
        if description and description != exist_item["description"]:
            return True
        if follow_redirects and int(follow_redirects) != int(exist_item["follow_redirects"]):
            return True
        if formula and formula != exist_item["params"]:
            return True
        if headers and headers != exist_item["headers"]:
            return True
        if history and history != exist_item["history"]:
            return True
        if http_proxy and http_proxy != exist_item["http_proxy"]:
            return True
        if inventory_link and int(inventory_link) != int(exist_item["inventory_link"]):
            return True
        if ipmi_sensor and ipmi_sensor != exist_item["ipmi_sensor"]:
            return True
        if jmx_endpoint and jmx_endpoint != exist_item["jmx_endpoint"]:
            return True
        if logtimefmt and logtimefmt != exist_item["logtimefmt"]:
            return True
        if master_itemid and int(master_itemid) != int(exist_item["master_itemid"]):
            return True
        if script and script != exist_item["params"]:
            return True
        if parameters and parameters != exist_item["parameters"]:
            return True
        if password and password != exist_item["password"]:
            return True
        if body_type and int(body_type) != int(exist_item["post_type"]):
            return True
        if body and body != exist_item["posts"]:
            return True
        if privatekey and privatekey != exist_item["privatekey"]:
            return True
        if publickey and publickey != exist_item["publickey"]:
            return True
        if url_query and url_query != exist_item["query_fields"]:
            return True
        if http_method and int(http_method) != int(exist_item["request_method"]):
            return True
        if retrieve_mode and int(retrieve_mode) != int(exist_item["retrieve_mode"]):
            return True
        if snmp_oid and snmp_oid != exist_item["snmp_oid"]:
            return True
        if db_query and db_query != exist_item["params"]:
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
        if allowed_hosts and allowed_hosts != exist_item["trapper_hosts"]:
            return True
        if trends and trends != exist_item["trends"]:
            return True
        if units and units != exist_item["units"]:
            return True
        if username and username != exist_item["username"]:
            return True
        if verify_host and int(verify_host) != int(exist_item["verify_host"]):
            return True
        if verify_peer and int(verify_peer) != int(exist_item["verify_peer"]):
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
        update_interval=dict(type="str", required_if=[
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
        authtype=dict(type="str", choices=["password", "0", "publickey", "1", "none", "0", "basic", "1", "ntlm", "2", "kerberos", "3"]),
        description=dict(type="str"),
        follow_redirects=dict(type="bool"),
        formula=dict(type="str", required_if=[
            ["type", 15, ["calculated"]],
        ]),
        headers=dict(type="dict"),
        history=dict(type="str"),
        http_proxy=dict(type="str"),
        inventory_link=dict(type="str", choices=["type", "1", "type_full", "2", "name", "3", "alias", "4", "os", "5", "os_full", "6", "os_short", "7", "serialno_a", "8", "serialno_b", "9", "tag", "10", "asset_tag", "11", "macaddress_a", "12", "macaddress_b", "13", "hardware", "14", "hardware_full", "15", "software", "16", "software_full", "17", "software_app_a", "18", "software_app_b", "19", "software_app_c", "20", "software_app_d", "21", "software_app_e", "22", "contact", "23", "location", "24", "location_lat", "25", "location_lon", "26", "notes", "27", "chassis", "28", "model", "29", "hw_arch", "30", "vendor", "31", "contract_number", "32", "installer_name", "33", "deployment_status", "34", "url_a", "35", "url_b", "36", "url_c", "37", "host_networks", "38", "host_netmask", "39", "host_router", "40", "oob_ip", "41", "oob_netmask", "42", "oob_router", "43", "date_hw_purchase", "44", "date_hw_install", "45", "date_hw_expiry", "46", "date_hw_decomm", "47", "site_address_a", "48", "site_address_b", "49", "site_address_c", "50", "site_city", "51", "site_state", "52", "site_country", "53", "site_zip", "54", "site_rack", "55", "site_notes", "56", "poc_1_name", "57", "poc_1_email", "58", "poc_1_phone_a", "59", "poc_1_phone_b", "60", "poc_1_cell", "61", "poc_1_screen", "62", "poc_1_notes", "63", "poc_2_name", "64", "poc_2_email", "65", "poc_2_phone_a", "66", "poc_2_phone_b", "67", "poc_2_cell", "68", "poc_2_screen", "69", "poc_2_notes", "70"]),
        ipmi_sensor=dict(type="str", required_if=[
            ["type", 12, ["ipmi"]],
        ]),
        jmx_endpoint=dict(type="str"),
        logtimefmt=dict(type="str"),
        master_item=dict(type="str", required_if=[
            ["type", 18, ["dependent"]],
        ]),
        convert_json=dict(type="bool"),
        parameters=dict(type="dict"),
        password=dict(type="str", no_log=True),
        body_type=dict(type="str", choices=["raw", "0", "json", "2", "xml", "3"]),
        body=dict(type="str", required_if=[
            ["body_type", 1, ["json"]],
            ["body_type", 2, ["xml"]],
        ]),
        privatekey=dict(type="str", no_log=True, required_if=[
            ["auth_type", 1, ["publickey"]]
        ]),
        publickey=dict(type="str", no_log=True, required_if=[
            ["auth_type", 1, ["publickey"]]
        ]),
        url_query=dict(type="dict"),
        http_method=dict(type="str", choices=["GET", "0", "POST", "1", "PUT", "2", "HEAD", "3"]),
        retrieve_mode=dict(type="str", choices=["body", "0", "headers", "1", "both", "2"]),
        snmp_oid=dict(type="str", required_if=[
            ["type", 20, ["snmp_agent"]],
        ]),
        script=dict(type="str", required_if=[
            ["type", 15, ["calculated"]],
            ["type", 21, ["script"]],
            ["type", 13, ["ssh"]],
            ["type", 14, ["telnet"]]
        ]),
        db_query=dict(type="str", required_if=[
            ["type", 11, ["database_monitor"]]
        ]),
        ssl_cert_file=dict(type="str", no_log=True),
        ssl_key_file=dict(type="str", no_log=True),
        ssl_key_password=dict(type="str", no_log=True),
        status_codes=dict(type="list", elements="str", default=["200"]),
        timeout=dict(type="str"),
        allowed_hosts=dict(type="str"),
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
            error_handler=dict(type="str", choices=["zabbix", "0", "discard", "1", "custom_value", "2", "custom_message", "3"], required_if=[
                ["type", 1, ["custom_multiplier"]],
                ["type", 5, ["regex"]],
                ["type", 6, ["bool_to_dec"]],
                ["type", 7, ["oct_to_dec"]],
                ["type", 8, ["hex_to_dec"]],
                ["type", 9, ["simple_change"]],
                ["type", 10, ["change_per_sec"]],
                ["type", 11, ["xml_xpath"]],
                ["type", 12, ["jsonpath"]],
                ["type", 13, ["in_range"]],
                ["type", 14, ["regex_match"]],
                ["type", 15, ["regex_not_match"]],
                ["type", 16, ["json_error_check"]],
                ["type", 17, ["xml_error_check"]],
                ["type", 18, ["regex_error_check"]],
                ["type", 22, ["prometheus_pattern"]],
                ["type", 23, ["prometheus_to_json"]],
                ["type", 24, ["csv_to_json"]],
                ["type", 26, ["check_unsupported"]],
                ["type", 27, ["xml_to_json"]],
                ["type", 28, ["snmp_walk_value"]],
                ["type", 29, ["snmp_walk_to_json"]]
                ]),
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
    formula = module.params["formula"]
    headers = module.params["headers"]
    history = module.params["history"]
    http_proxy = module.params["http_proxy"]
    inventory_link = module.params["inventory_link"]
    ipmi_sensor = module.params["ipmi_sensor"]
    jmx_endpoint = module.params["jmx_endpoint"]
    logtimefmt = module.params["logtimefmt"]
    master_item = module.params["master_item"]
    convert_json = module.params["convert_json"]
    script = module.params["script"]
    db_query = module.params["db_query"]
    parameters = module.params["parameters"]
    password = module.params["password"]
    body_type = module.params["body_type"]
    body = module.params["body"]
    privatekey = module.params["privatekey"]
    publickey = module.params["publickey"]
    url_query = module.params["url_query"]
    http_method = module.params["http_method"]
    retrieve_mode = module.params["retrieve_mode"]
    snmp_oid = module.params["snmp_oid"]
    ssl_cert_file = module.params["ssl_cert_file"]
    ssl_key_file = module.params["ssl_key_file"]
    ssl_key_password = module.params["ssl_key_password"]
    status_codes = module.params["status_codes"]
    timeout = module.params["timeout"]
    allowed_hosts = module.params["allowed_hosts"]
    trends = module.params["trends"]
    units = module.params["units"]
    username = module.params["username"]
    verify_host = module.params["verify_host"]
    verify_peer = module.params["verify_peer"]
    tags = module.params["tags"]
    preprocessing = module.params["preprocessing"]

    # convert enabled to 0; disabled to 1
    status = 1 if status == "disabled" else 0


    item = Item(module)

    # check if item exist
    is_item_exist = item.is_item_exist(item_name, host_name)

    preprocessing = item.construct_preprocessing(preprocessing)

    if type:
        type_types = {"zabbix_agent": 0, "zabbix_trapper": 2, "simple_check": 3, "zabbix_internal": 5, "zabbix_agent_active": 7, "web_item": 9, "external_check": 10, "database_monitor": 11, "ipmi": 12, "ssh": 13, "telnet": 14, "calculated": 15, "jmx": 16, "snmp_trap": 17, "dependent": 18, "http": 19, "snmp_agent": 20, "script": 21}
        if type in list(type_types.keys()):
            type = type_types[type]
        else:
            type = int(type)
    else:
        if not is_item_exist:
            module.fail_json(msg='"type" required when creating an item')
    if value_type:
        value_type_types = {"float": 0, "character": 1, "log": 2, "unsigned": 3, "text": 4}
        if value_type in list(value_type_types.keys()):
            value_type = value_type_types[value_type]
        else:
            value_type = int(value_type)
    else:
        if not is_item_exist:
            module.fail_json(msg='"value_type" required when creating an item')
   
    if state == "present":
        if not is_item_exist:
            # check mandatory parameters
            if not item_name:
                module.fail_json(msg="Item name must be set.")
            if not host_name:
                module.fail_json(msg="Host name must be set.")
            if type is None:
                module.fail_json(msg="Type cannot be empty.")
            
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
        interface = item.get_host_interfaceid_by_host(interface, host_id, host_name)

    if inventory_link:
        if value_type in list([0, 1, 3, 4]):
            inventory = {"type":1,"type_full":2,"name":3,"alias":4,"os":5,"os_full":6,"os_short":7,"serialno_a":8,"serialno_b":9,"tag":10,"asset_tag":11,"macaddress_a":12,"macaddress_b":13,"hardware":14,"hardware_full":15,"software":16,"software_full":17,"software_app_a":18,"software_app_b":19,"software_app_c":20,"software_app_d":21,"software_app_e":22,"contact":23,"location":24,"location_lat":25,"location_lon":26,"notes":27,"chassis":28,"model":29,"hw_arch":30,"vendor":31,"contract_number":32,"installer_name":33,"deployment_status":34,"url_a":35,"url_b":36,"url_c":37,"host_networks":38,"host_netmask":39,"host_router":40,"oob_ip":41,"oob_netmask":42,"oob_router":43,"date_hw_purchase":44,"date_hw_install":45,"date_hw_expiry":46,"date_hw_decomm":47,"site_address_a":48,"site_address_b":49,"site_address_c":50,"site_city":51,"site_state":52,"site_country":53,"site_zip":54,"site_rack":55,"site_notes":56,"poc_1_name":57,"poc_1_email":58,"poc_1_phone_a":59,"poc_1_phone_b":60,"poc_1_cell":61,"poc_1_screen":62,"poc_1_notes":63,"poc_2_name":64,"poc_2_email":65,"poc_2_phone_a":66,"poc_2_phone_b":67,"poc_2_cell":68,"poc_2_screen":69,"poc_2_notes":70}
            if inventory_link in list(inventory):
                inventory_link = inventory[inventory_link]
            else:
                inventory_link = int(inventory_link)
        else:
            inventory_link = "0"

    # convert bools/choices to integers
    if allow_traps:
        allow_traps = 1 if allow_traps == True else 0
    if type == 13:
        if authtype:
            authtype_types = {"password": 0, "publickey": 1}
            if authtype in list(authtype_types.keys()):
                authtype = authtype_types[authtype]
            else:
                authtype = int(authtype)
        else:
            authtype = 0
    elif type == 19:
        if authtype:
            authtype_types = {"none": 0, "basic": 1, "ntlm": 2, "kerberos": 3}
            if authtype in list(authtype_types.keys()):
                authtype = authtype_types[authtype]
            else:
                authtype = int(authtype)
        else:
            authtype = 0
    else:
        authtype = 0

    if follow_redirects:
        follow_redirects = 1 if follow_redirects == True else 0
    if convert_json:
        convert_json = 1 if convert_json == True else 0
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
    
    # convert to compatible object types
    if url_query:
        array = []
        for q in url_query:
            array.append({q: url_query[q]})
        url_query = array
    if parameters:
        array = []
        for p in parameters:
            array.append({"name": p, "value": parameters[p]})
        parameters = array
     
    # conditional parameter filtering
    if type in list([2, 17, 18]):
        update_interval: "0"
    else:
        if not update_interval:
            update_interval = "10s"

    if master_item:
        master_item = item.get_itemid_by_item_and_hostid(master_item, host_id)[0]["itemid"]

    if body_type == 2:
        body = body.replace("\'", '\"')

    if is_item_exist:
        item_id = is_item_exist[0]["itemid"]

        if state == "absent":
            # remove item
            item.delete_item(item_id, item_name)
            module.exit_json(changed=True, result="Successfully deleted item %s" % item_name)
        else:            
            # update item
            if item.check_all_properties(item_id, key, host_id, host_name, type, status, update_interval, interface, url, allow_traps, authtype, convert_json, description, follow_redirects, formula, headers, history, http_proxy, inventory_link, ipmi_sensor, jmx_endpoint, logtimefmt, master_item, script, parameters, password, body_type, body, privatekey, publickey, url_query, http_method, retrieve_mode, snmp_oid, db_query, ssl_cert_file, ssl_key_file, ssl_key_password, status_codes, timeout, allowed_hosts, trends, units, username, verify_host, verify_peer, tags, preprocessing):
                # update the item
                item.update_item(item_name, item_id, key, type, status, update_interval, interface, url, allow_traps, authtype, convert_json, description, follow_redirects, formula, headers, history, http_proxy, inventory_link, ipmi_sensor, jmx_endpoint, logtimefmt, master_item, script, parameters, password, body_type, body, privatekey, publickey, url_query, http_method, retrieve_mode, snmp_oid, db_query, ssl_cert_file, ssl_key_file, ssl_key_password, status_codes, timeout, allowed_hosts, trends, units, username, verify_host, verify_peer, tags, preprocessing)

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
        item_id = item.add_item(item_name, key, host_id, type, status, value_type, update_interval, interface, url, allow_traps, authtype, convert_json, description, follow_redirects, formula, headers, history, http_proxy, inventory_link, ipmi_sensor, jmx_endpoint, logtimefmt, master_item, script, parameters, password, body_type, body, privatekey, publickey, url_query, http_method, retrieve_mode, snmp_oid, db_query, ssl_cert_file, ssl_key_file, ssl_key_password, status_codes, timeout, allowed_hosts, trends, units, username, verify_host, verify_peer, tags, preprocessing)

        module.exit_json(changed=True, result="Successfully added item %s on host %s" % (item_name, host_name))

if __name__ == "__main__":
    main()
