#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2013-2014, Epic Games, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: zabbix_host
short_description: Create/update/delete Zabbix hosts
description:
   - This module allows you to create, modify and delete Zabbix host entries and associated group and template data.
author:
    - "Cove (@cove)"
    - Tony Minfei Ding (!UNKNOWN)
    - Harrison Gu (@harrisongu)
    - Werner Dijkerman (@dj-wasabi)
    - Eike Frost (@eikef)
requirements:
    - "python >= 2.6"
    - "zabbix-api >= 0.5.4"
options:
    host_name:
        description:
            - Name of the host in Zabbix.
            - I(host_name) is the unique identifier used and cannot be updated using this module.
        required: true
        type: str
    visible_name:
        description:
            - Visible name of the host in Zabbix.
        type: str
    description:
        description:
            - Description of the host in Zabbix.
        type: str
    host_groups:
        description:
            - List of host groups the host is part of.
            - Make sure the Zabbix user used for Ansible can read these groups.
        type: list
        elements: str
    link_templates:
        description:
            - List of templates linked to the host.
        type: list
        elements: str
    inventory_mode:
        description:
            - Configure the inventory mode.
        choices: ['automatic', 'manual', 'disabled']
        type: str
    inventory_zabbix:
        description:
            - Add Facts for a zabbix inventory (e.g. Tag) (see example below).
            - Please review the interface documentation for more information on the supported properties
            - U(https://www.zabbix.com/documentation/3.2/manual/api/reference/host/object#host_inventory)
        type: dict
    status:
        description:
            - Monitoring status of the host.
        choices: ['enabled', 'disabled']
        default: 'enabled'
        type: str
    state:
        description:
            - State of the host.
            - On C(present), it will create if host does not exist or update the host if the associated data is different.
            - On C(absent) will remove a host if it exists.
        choices: ['present', 'absent']
        default: 'present'
        type: str
    proxy:
        description:
            - The name of the Zabbix proxy to be used.
        type: str
    interfaces:
        type: list
        elements: dict
        description:
            - List of interfaces to be created for the host (see example below).
            - For more information, review host interface documentation at
            - U(https://www.zabbix.com/documentation/4.0/manual/api/reference/hostinterface/object)
        default: []
        suboptions:
            type:
                type: str
                description:
                    - Interface type to add
                    - Numerical values are also accepted for interface type
                    - 1 = agent
                    - 2 = snmp
                    - 3 = ipmi
                    - 4 = jmx
                choices: ['agent', '1', 'snmp', '2', 'ipmi', '3', 'jmx', '4']
                required: true
            main:
                type: int
                description:
                    - Whether the interface is used as default.
                    - If multiple interfaces with the same type are provided, only one can be default.
                    - 0 (not default), 1 (default)
                default: 0
                choices: [0, 1]
            useip:
                type: int
                description:
                    - Connect to host interface with IP address instead of DNS name.
                    - 0 (don't use ip), 1 (use ip)
                default: 0
                choices: [0, 1]
            ip:
                type: str
                description:
                    - IP address used by host interface.
                    - Required if I(useip=1).
                default: ''
            dns:
                type: str
                description:
                    - DNS name of the host interface.
                    - Required if I(useip=0).
                default: ''
            port:
                type: str
                description:
                    - Port used by host interface.
                    - If not specified, default port for each type of interface is used
                    - 10050 if I(type='agent')
                    - 161 if I(type='snmp')
                    - 623 if I(type='ipmi')
                    - 12345 if I(type='jmx')
            bulk:
                type: int
                description:
                    - Whether to use bulk SNMP requests.
                    - Only valid when interface I(type='snmp').
                    - 0 (don't use bulk requests), 1 (use bulk requests)
                    - Works only with Zabbix <= 4.4 and is silently ignored in higher versions.
                    - Use I(details) with Zabbix >= 5.0.
                choices: [0, 1]
                default: 1
            details:
                type: dict
                description:
                    - Additional details for SNMP host interfaces.
                    - Required when I(type='snmp').
                    - Works only with Zabbix >= 5.0.
                default: {}
                suboptions:
                    version:
                        type: int
                        description:
                            - SNMP version.
                            - 1 (SNMPv1), 2 (SNMPv2c), 3 (SNMPv3)
                        choices: [1, 2, 3]
                        default: 2
                    bulk:
                        type: int
                        description:
                            - Whether to use bulk SNMP requests.
                            - 0 (don't use bulk requests), 1 (use bulk requests)
                        choices: [0, 1]
                        default: 1
                    community:
                        type: str
                        description:
                            - SNMPv1 and SNMPv2 community string.
                            - Required when I(version=1) or I(version=2).
                    securityname:
                        type: str
                        description:
                            - SNMPv3 security name.
                        default: ''
                    contextname:
                        type: str
                        description:
                            - SNMPv3 context name.
                        default: ''
                    securitylevel:
                        type: int
                        description:
                            - SNMPv3 security level.
                            - 0 (noAuthNoPriv), 1 (authNoPriv), 2 (authPriv).
                        choices: [0, 1, 2]
                        default: 0
                    authprotocol:
                        type: int
                        description:
                            - SNMPv3 authentication protocol.
                            - Used when I(securitylevel=1)(authNoPriv) or I(securitylevel=2)(AuthPriv).
                            - 0 (MD5), 1 (SHA)
                        default: 0
                        choices: [0, 1]
                    authpassphrase:
                        type: str
                        description:
                            - SNMPv3 authentication passphrase.
                            - Used when I(securitylevel=1)(authNoPriv) or I(securitylevel=2)(AuthPriv).
                        default: ''
                    privprotocol:
                        type: int
                        description:
                            - SNMPv3 privacy protocol.
                            - Used when I(securitylevel=2)(authPriv).
                            - 0 (DES), 1 (AES)
                        default: 0
                        choices: [0, 1]
                    privpassphrase:
                        type: str
                        description:
                            - SNMPv3 privacy passphrase.
                            - Used when I(securitylevel=2)(AuthPriv).
                        default: ''
    tls_connect:
        description:
            - Specifies what encryption to use for outgoing connections.
            - Possible values, 1 (no encryption), 2 (PSK), 4 (certificate).
            - Works only with >= Zabbix 3.0
        default: 1
        type: int
    tls_accept:
        description:
            - Specifies what types of connections are allowed for incoming connections.
            - The tls_accept parameter accepts values of 1 to 7
            - Possible values, 1 (no encryption), 2 (PSK), 4 (certificate).
            - Values can be combined.
            - Works only with >= Zabbix 3.0
        default: 1
        type: int
    tls_psk_identity:
        description:
            - It is a unique name by which this specific PSK is referred to by Zabbix components
            - Do not put sensitive information in the PSK identity string, it is transmitted over the network unencrypted.
            - Works only with >= Zabbix 3.0
        type: str
    tls_psk:
        description:
            - PSK value is a hard to guess string of hexadecimal digits.
            - The preshared key, at least 32 hex digits. Required if either I(tls_connect) or I(tls_accept) has PSK enabled.
            - Works only with >= Zabbix 3.0
        type: str
    ca_cert:
        description:
            - Required certificate issuer.
            - Works only with >= Zabbix 3.0
        aliases: [ tls_issuer ]
        type: str
    tls_subject:
        description:
            - Required certificate subject.
            - Works only with >= Zabbix 3.0
        type: str
    ipmi_authtype:
        description:
            - IPMI authentication algorithm.
            - Please review the Host object documentation for more information on the supported properties
            - 'https://www.zabbix.com/documentation/3.4/manual/api/reference/host/object'
            - Possible values are, C(0) (none), C(1) (MD2), C(2) (MD5), C(4) (straight), C(5) (OEM), C(6) (RMCP+),
              with -1 being the API default.
            - Please note that the Zabbix API will treat absent settings as default when updating
              any of the I(ipmi_)-options; this means that if you attempt to set any of the four
              options individually, the rest will be reset to default values.
        type: int
    ipmi_privilege:
        description:
            - IPMI privilege level.
            - Please review the Host object documentation for more information on the supported properties
            - 'https://www.zabbix.com/documentation/3.4/manual/api/reference/host/object'
            - Possible values are C(1) (callback), C(2) (user), C(3) (operator), C(4) (admin), C(5) (OEM), with C(2)
              being the API default.
            - also see the last note in the I(ipmi_authtype) documentation
        type: int
    ipmi_username:
        description:
            - IPMI username.
            - also see the last note in the I(ipmi_authtype) documentation
        type: str
    ipmi_password:
        description:
            - IPMI password.
            - also see the last note in the I(ipmi_authtype) documentation
        type: str
    force:
        description:
            - Overwrite the host configuration, even if already present.
        type: bool
        default: 'yes'
    macros:
        description:
            - List of user macros to assign to the zabbix host.
            - Providing I(macros=[]) with I(force=yes) will clean all of the existing user macros from the host.
        type: list
        elements: dict
        suboptions:
            macro:
                description:
                    - Name of the user macro.
                    - Can be in zabbix native format "{$MACRO}" or short format "MACRO".
                type: str
                required: true
            value:
                description:
                    - Value of the user macro.
                type: str
                required: true
            description:
                description:
                    - Description of the user macro.
                    - Works only with >= Zabbix 4.4.
                type: str
                required: false
                default: ''
            type:
                description:
                    - Type of the macro.
                    - Works only with >= Zabbix 5.0.
                    - Since value is not returned by API for secret macros, there is no reliable way to
                      detect changes in the content of secret macro value.
                    - To update secret macro value, please update description alongside it so it passes
                      the check.
                choices: [text, secret]
                type: str
                required: false
                default: text
        aliases: [ user_macros ]
    tags:
        description:
            - List of host tags to assign to the zabbix host.
            - Works only with >= Zabbix 4.2.
            - Providing I(tags=[]) with I(force=yes) will clean all of the tags from the host.
        type: list
        elements: dict
        suboptions:
            tag:
                description:
                    - Name of the host tag.
                type: str
                required: true
            value:
                description:
                    - Value of the host tag.
                type: str
                default: ''
        aliases: [ host_tags ]

extends_documentation_fragment:
- community.zabbix.zabbix

'''

EXAMPLES = r'''
- name: Create a new host or update an existing host's info
  local_action:
    module: community.zabbix.zabbix_host
    server_url: http://monitor.example.com
    login_user: username
    login_password: password
    host_name: ExampleHost
    visible_name: ExampleName
    description: My ExampleHost Description
    host_groups:
      - Example group1
      - Example group2
    link_templates:
      - Example template1
      - Example template2
    status: enabled
    state: present
    inventory_mode: manual
    inventory_zabbix:
      tag: "{{ your_tag }}"
      alias: "{{ your_alias }}"
      notes: "Special Informations: {{ your_informations | default('None') }}"
      location: "{{ your_location }}"
      site_rack: "{{ your_site_rack }}"
      os: "{{ your_os }}"
      hardware: "{{ your_hardware }}"
    ipmi_authtype: 2
    ipmi_privilege: 4
    ipmi_username: username
    ipmi_password: password
    interfaces:
      - type: 1
        main: 1
        useip: 1
        ip: 10.xx.xx.xx
        dns: ""
        port: "10050"
      - type: 4
        main: 1
        useip: 1
        ip: 10.xx.xx.xx
        dns: ""
        port: "12345"
    proxy: a.zabbix.proxy
    macros:
      - macro: '{$EXAMPLEMACRO}'
        value: ExampleMacroValue
      - macro: EXAMPLEMACRO2
        value: ExampleMacroValue2
        description: Example desc that work only with Zabbix 4.4 and higher
    tags:
      - tag: ExampleHostsTag
      - tag: ExampleHostsTag2
        value: ExampleTagValue

- name: Update an existing host's TLS settings
  local_action:
    module: community.zabbix.zabbix_host
    server_url: http://monitor.example.com
    login_user: username
    login_password: password
    host_name: ExampleHost
    visible_name: ExampleName
    host_groups:
      - Example group1
    tls_psk_identity: test
    tls_connect: 2
    tls_psk: 123456789abcdef123456789abcdef12
'''


import copy

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
from ansible_collections.community.zabbix.plugins.module_utils.version import LooseVersion

import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class Host(ZabbixBase):
    # exist host
    def is_host_exist(self, host_name):
        result = self._zapi.host.get({'filter': {'host': host_name}})
        return result

    # check if host group exists
    def check_host_group_exist(self, group_names):
        for group_name in group_names:
            result = self._zapi.hostgroup.get({'filter': {'name': group_name}})
            if not result:
                self._module.fail_json(msg="Hostgroup not found: %s" % group_name)
        return True

    def get_template_ids(self, template_list):
        template_ids = []
        if template_list is None or len(template_list) == 0:
            return template_ids
        for template in template_list:
            template_list = self._zapi.template.get({'output': 'extend', 'filter': {'host': template}})
            if len(template_list) < 1:
                self._module.fail_json(msg="Template not found: %s" % template)
            else:
                template_id = template_list[0]['templateid']
                template_ids.append(template_id)
        return template_ids

    def add_host(self, host_name, group_ids, status, interfaces, proxy_id, visible_name, description, tls_connect,
                 tls_accept, tls_psk_identity, tls_psk, tls_issuer, tls_subject, ipmi_authtype, ipmi_privilege,
                 ipmi_username, ipmi_password, macros, tags):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            parameters = {'host': host_name, 'interfaces': interfaces, 'groups': group_ids, 'status': status,
                          'tls_connect': tls_connect, 'tls_accept': tls_accept}
            if proxy_id:
                parameters['proxy_hostid'] = proxy_id
            if visible_name:
                parameters['name'] = visible_name
            if tls_psk_identity is not None:
                parameters['tls_psk_identity'] = tls_psk_identity
            if tls_psk is not None:
                parameters['tls_psk'] = tls_psk
            if tls_issuer is not None:
                parameters['tls_issuer'] = tls_issuer
            if tls_subject is not None:
                parameters['tls_subject'] = tls_subject
            if description:
                parameters['description'] = description
            if ipmi_authtype is not None:
                parameters['ipmi_authtype'] = ipmi_authtype
            if ipmi_privilege is not None:
                parameters['ipmi_privilege'] = ipmi_privilege
            if ipmi_username is not None:
                parameters['ipmi_username'] = ipmi_username
            if ipmi_password is not None:
                parameters['ipmi_password'] = ipmi_password
            if macros is not None:
                parameters['macros'] = macros
            if tags is not None:
                parameters['tags'] = tags

            host_list = self._zapi.host.create(parameters)
            if len(host_list) >= 1:
                return host_list['hostids'][0]
        except Exception as e:
            self._module.fail_json(msg="Failed to create host %s: %s" % (host_name, e))

    def update_host(self, host_name, group_ids, status, host_id, interfaces, exist_interface_list, proxy_id,
                    visible_name, description, tls_connect, tls_accept, tls_psk_identity, tls_psk, tls_issuer,
                    tls_subject, ipmi_authtype, ipmi_privilege, ipmi_username, ipmi_password, macros, tags):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            parameters = {'hostid': host_id, 'groups': group_ids, 'status': status, 'tls_connect': tls_connect,
                          'tls_accept': tls_accept}
            if proxy_id >= 0:
                parameters['proxy_hostid'] = proxy_id
            if visible_name:
                parameters['name'] = visible_name
            if tls_psk_identity:
                parameters['tls_psk_identity'] = tls_psk_identity
            if tls_psk:
                parameters['tls_psk'] = tls_psk
            if tls_issuer:
                parameters['tls_issuer'] = tls_issuer
            if tls_subject:
                parameters['tls_subject'] = tls_subject
            if description:
                parameters['description'] = description
            if ipmi_authtype:
                parameters['ipmi_authtype'] = ipmi_authtype
            if ipmi_privilege:
                parameters['ipmi_privilege'] = ipmi_privilege
            if ipmi_username:
                parameters['ipmi_username'] = ipmi_username
            if ipmi_password:
                parameters['ipmi_password'] = ipmi_password
            if macros is not None:
                parameters['macros'] = macros
            if tags is not None:
                parameters['tags'] = tags

            self._zapi.host.update(parameters)
            interface_list_copy = exist_interface_list
            if interfaces:
                for interface in interfaces:
                    flag = False
                    interface_str = interface
                    for exist_interface in exist_interface_list:
                        interface_type = int(interface['type'])
                        exist_interface_type = int(exist_interface['type'])
                        if interface_type == exist_interface_type:
                            # update
                            interface_str['interfaceid'] = exist_interface['interfaceid']
                            self._zapi.hostinterface.update(interface_str)
                            flag = True
                            interface_list_copy.remove(exist_interface)
                            break
                    if not flag:
                        # add
                        interface_str['hostid'] = host_id
                        self._zapi.hostinterface.create(interface_str)
                        # remove
                remove_interface_ids = []
                for remove_interface in interface_list_copy:
                    interface_id = remove_interface['interfaceid']
                    remove_interface_ids.append(interface_id)
                if len(remove_interface_ids) > 0:
                    self._zapi.hostinterface.delete(remove_interface_ids)
        except Exception as e:
            self._module.fail_json(msg="Failed to update host %s: %s" % (host_name, e))

    def delete_host(self, host_id, host_name):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            self._zapi.host.delete([host_id])
        except Exception as e:
            self._module.fail_json(msg="Failed to delete host %s: %s" % (host_name, e))

    # get host by host name
    def get_host_by_host_name(self, host_name):
        params = {
            'output': 'extend',
            'selectInventory': 'extend',
            'selectMacros': 'extend',
            'filter': {
                'host': [host_name]
            }
        }

        if LooseVersion(self._zbx_api_version) >= LooseVersion('4.2.0'):
            params.update({'selectTags': 'extend'})

        if LooseVersion(self._zbx_api_version) >= LooseVersion('5.4.0'):
            params.update({
                'output': [
                    "inventory_mode",
                    "hostid",
                    "proxy_hostid",
                    "host",
                    "status",
                    "lastaccess",
                    "ipmi_authtype",
                    "ipmi_privilege",
                    "ipmi_username",
                    "ipmi_password",
                    "maintenanceid",
                    "maintenance_status",
                    "maintenance_type",
                    "maintenance_from",
                    "name",
                    "flags",
                    "templateid",
                    "description",
                    "tls_connect",
                    "tls_accept",
                    "tls_issuer",
                    "tls_subject",
                    "proxy_address",
                    "auto_compress",
                    "custom_interfaces",
                    "uuid"
                ]
            })

        host_list = self._zapi.host.get(params)
        if len(host_list) < 1:
            self._module.fail_json(msg="Host not found: %s" % host_name)
        else:
            return host_list[0]

    # get proxyid by proxy name
    def get_proxyid_by_proxy_name(self, proxy_name):
        proxy_list = self._zapi.proxy.get({'output': 'extend', 'filter': {'host': [proxy_name]}})
        if len(proxy_list) < 1:
            self._module.fail_json(msg="Proxy not found: %s" % proxy_name)
        else:
            return int(proxy_list[0]['proxyid'])

    # get group ids by group names
    def get_group_ids_by_group_names(self, group_names):
        if self.check_host_group_exist(group_names):
            return self._zapi.hostgroup.get({'output': 'groupid', 'filter': {'name': group_names}})

    # get host groups ids by host id
    def get_group_ids_by_host_id(self, host_id):
        return self._zapi.hostgroup.get({'output': 'groupid', 'hostids': host_id})

    # get host templates by host id
    def get_host_templates_by_host_id(self, host_id):
        template_ids = []
        template_list = self._zapi.template.get({'output': 'extend', 'hostids': host_id})
        for template in template_list:
            template_ids.append(template['templateid'])
        return template_ids

    def construct_host_interfaces(self, interfaces):
        """Ensures interfaces object is properly formatted before submitting it to API.

        Args:
            interfaces (list): list of dictionaries for each interface present on the host.

        Returns:
            (interfaces, ip) - where interfaces is original list reformated into a valid format
                and ip is any IP address found on interface of type agent (printing purposes only).
        """
        ip = ""
        interface_types = {'agent': 1, 'snmp': 2, 'ipmi': 3, 'jmx': 4}
        type_to_port = {1: '10050', 2: '161', 3: '623', 4: '12345'}

        for interface in interfaces:
            if interface['type'] in list(interface_types.keys()):
                interface['type'] = interface_types[interface['type']]
            else:
                interface['type'] = int(interface['type'])

            if interface['type'] == 1:
                ip = interface.get('ip', '')

            if 'port' not in interface or interface['port'] is None:
                interface['port'] = type_to_port.get(interface['type'], '')

            if LooseVersion(self._zbx_api_version) >= LooseVersion('5.0.0'):
                if 'bulk' in interface:
                    del interface['bulk']

                # Not handled in argument_spec with required_if since only SNMP interfaces are using details
                if interface['type'] == 2:
                    if not interface['details']:
                        self._module.fail_json(msg='Option "details" required for SNMP interface {0}'.format(interface))

                    i_details = interface['details']
                    if i_details['version'] < 3 and not i_details.get('community', False):
                        self._module.fail_json(
                            msg='Option "community" is required in "details" for SNMP interface {0}'.format(interface))

                else:
                    interface['details'] = {}

            else:
                if 'details' in interface:
                    del interface['details']

        return (interfaces, ip)

    # check the exist_interfaces whether it equals the interfaces or not
    def check_interface_properties(self, exist_interfaces, interfaces):
        # hostinterface.details looks different based on the version of SNMP currently configured
        snmp_ver_keys = {
            1: ['version', 'bulk', 'community'],
            2: ['version', 'bulk', 'community'],
            3: [
                'version', 'bulk', 'securityname', 'securitylevel', 'authprotocol',
                'authpassphrase', 'privprotocol', 'privpassphrase', 'contextname'
            ]
        }

        i_ports = []
        for interface in interfaces:
            i_ports.append(interface['port'])

        exist_i_ports = []
        for interface in exist_interfaces:
            exist_i_ports.append(interface['port'])

        if sorted(i_ports) != sorted(exist_i_ports):
            return True

        _matched_intfs = []

        for exist_interface in exist_interfaces:
            exist_interface_port = str(exist_interface['port'])

            # Zabbix API should return empty dictionary instead of list, workaround:
            if 'details' in exist_interface and not exist_interface['details']:
                exist_interface['details'] = {}

            for interface in interfaces:
                # ensure one interface is not matched multiple times
                if interface in _matched_intfs:
                    continue

                if str(interface['port']) == exist_interface_port:
                    for key in interface.keys():
                        # since 5.0, zabbix API returns details for each host interface, but only SNMP is not empty
                        if key == 'details':
                            if interface['details']:
                                # only data relevant to a particular version are returned and rest should be filtered
                                snmp_ver = int(interface['details']['version'])
                                for dkey in list(interface['details'].keys()):
                                    if dkey not in snmp_ver_keys[snmp_ver]:
                                        interface['details'].pop(dkey)
                                    else:
                                        interface['details'][dkey] = str(interface['details'][dkey])

                            # either compare empty or filtered dictionaries
                            if interface['details'] != exist_interface['details']:
                                return True

                        elif str(exist_interface[key]) != str(interface[key]):
                            return True

                # if the code got here, that means interfaces did match, remove the one matched and break loop for
                # current intf, otherwise it would start comparing to next intf of the same type and not match
                _matched_intfs.append(interface)
                break

        return False

    # get the status of host by host
    def get_host_status_by_host(self, host):
        return host['status']

    # check all the properties before link or clear template
    def check_all_properties(self, host_id, group_ids, status, interfaces, template_ids,
                             exist_interfaces, host, proxy_id, visible_name, description, host_name,
                             inventory_mode, inventory_zabbix, tls_accept, tls_psk_identity, tls_psk,
                             tls_issuer, tls_subject, tls_connect, ipmi_authtype, ipmi_privilege,
                             ipmi_username, ipmi_password, macros, tags):
        # get the existing host's groups
        exist_host_groups = sorted(self.get_group_ids_by_host_id(host_id), key=lambda k: k['groupid'])
        if sorted(group_ids, key=lambda k: k['groupid']) != exist_host_groups:
            return True

        # get the existing status
        exist_status = self.get_host_status_by_host(host)
        if int(status) != int(exist_status):
            return True

        # check the exist_interfaces whether it equals the interfaces or not
        if self.check_interface_properties(exist_interfaces, interfaces):
            return True

        # get the existing templates
        exist_template_ids = self.get_host_templates_by_host_id(host_id)
        if set(list(template_ids)) != set(exist_template_ids):
            return True

        if int(host['proxy_hostid']) != int(proxy_id):
            return True

        # Check whether the visible_name has changed; Zabbix defaults to the technical hostname if not set.
        if visible_name:
            if host['name'] != visible_name:
                return True

        # Only compare description if it is given as a module parameter
        if description:
            if host['description'] != description:
                return True

        if inventory_mode:
            if LooseVersion(self._zbx_api_version) <= LooseVersion('4.4.0'):
                if host['inventory']:
                    if int(host['inventory']['inventory_mode']) != self.inventory_mode_numeric(inventory_mode):
                        return True
                elif inventory_mode != 'disabled':
                    return True
            else:
                if int(host['inventory_mode']) != self.inventory_mode_numeric(inventory_mode):
                    return True

        if inventory_zabbix:
            proposed_inventory = copy.deepcopy(host['inventory'])
            proposed_inventory.update(inventory_zabbix)
            if proposed_inventory != host['inventory']:
                return True

        if tls_accept is not None and 'tls_accept' in host:
            if int(host['tls_accept']) != tls_accept:
                return True

        if LooseVersion(self._zbx_api_version) <= LooseVersion('5.4.0'):
            if tls_psk_identity is not None and 'tls_psk_identity' in host:
                if host['tls_psk_identity'] != tls_psk_identity:
                    return True

        if LooseVersion(self._zbx_api_version) <= LooseVersion('5.4.0'):
            if tls_psk is not None and 'tls_psk' in host:
                if host['tls_psk'] != tls_psk:
                    return True

        if tls_issuer is not None and 'tls_issuer' in host:
            if host['tls_issuer'] != tls_issuer:
                return True

        if tls_subject is not None and 'tls_subject' in host:
            if host['tls_subject'] != tls_subject:
                return True

        if tls_connect is not None and 'tls_connect' in host:
            if int(host['tls_connect']) != tls_connect:
                return True
        if ipmi_authtype is not None:
            if int(host['ipmi_authtype']) != ipmi_authtype:
                return True
        if ipmi_privilege is not None:
            if int(host['ipmi_privilege']) != ipmi_privilege:
                return True
        if ipmi_username is not None:
            if host['ipmi_username'] != ipmi_username:
                return True
        if ipmi_password is not None:
            if host['ipmi_password'] != ipmi_password:
                return True

        # hostmacroid and hostid are present in every item of host['macros'] and need to be removed
        if macros is not None and 'macros' in host:
            t_macros = copy.deepcopy(macros)  # make copy to prevent change in original data
            existing_macros = sorted(host['macros'], key=lambda k: k['macro'])
            for macro in existing_macros:
                macro.pop('hostid', False)
                macro.pop('hostmacroid', False)
                if 'type' in macro:
                    macro['type'] = int(macro['type'])

            # 'secret' type macros don't return 'value' from API
            if LooseVersion(self._zbx_api_version) >= LooseVersion('5.0'):
                for macro in t_macros:
                    if macro['type'] == 1:
                        macro.pop('value', False)

            if sorted(t_macros, key=lambda k: k['macro']) != existing_macros:
                return True

        if tags is not None and 'tags' in host:
            if sorted(tags, key=lambda k: k['tag']) != sorted(host['tags'], key=lambda k: k['tag']):
                return True

        return False

    # link or clear template of the host
    def link_or_clear_template(self, host_id, template_id_list, tls_connect, tls_accept, tls_psk_identity, tls_psk,
                               tls_issuer, tls_subject, ipmi_authtype, ipmi_privilege, ipmi_username, ipmi_password):
        # get host's exist template ids
        exist_template_id_list = self.get_host_templates_by_host_id(host_id)

        exist_template_ids = set(exist_template_id_list)
        template_ids = set(template_id_list)
        template_id_list = list(template_ids)

        # get unlink and clear templates
        templates_clear = exist_template_ids.difference(template_ids)
        templates_clear_list = list(templates_clear)
        request_str = {'hostid': host_id, 'templates': template_id_list, 'templates_clear': templates_clear_list,
                       'tls_connect': tls_connect, 'tls_accept': tls_accept, 'ipmi_authtype': ipmi_authtype,
                       'ipmi_privilege': ipmi_privilege, 'ipmi_username': ipmi_username, 'ipmi_password': ipmi_password}
        if tls_psk_identity is not None:
            request_str['tls_psk_identity'] = tls_psk_identity
        if tls_psk is not None:
            request_str['tls_psk'] = tls_psk
        if tls_issuer is not None:
            request_str['tls_issuer'] = tls_issuer
        if tls_subject is not None:
            request_str['tls_subject'] = tls_subject
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            self._zapi.host.update(request_str)
        except Exception as e:
            self._module.fail_json(msg="Failed to link template to host: %s" % e)

    def inventory_mode_numeric(self, inventory_mode):
        if inventory_mode == "automatic":
            return int(1)
        elif inventory_mode == "manual":
            return int(0)
        elif inventory_mode == "disabled":
            return int(-1)
        return inventory_mode

    # Update the host inventory_mode
    def update_inventory_mode(self, host_id, inventory_mode):

        # nothing was set, do nothing
        if not inventory_mode:
            return

        inventory_mode = self.inventory_mode_numeric(inventory_mode)

        # watch for - https://support.zabbix.com/browse/ZBX-6033
        request_str = {'hostid': host_id, 'inventory_mode': inventory_mode}
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            self._zapi.host.update(request_str)
        except Exception as e:
            self._module.fail_json(msg="Failed to set inventory_mode to host: %s" % e)

    def update_inventory_zabbix(self, host_id, inventory):

        if not inventory:
            return

        request_str = {'hostid': host_id, 'inventory': inventory}
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            self._zapi.host.update(request_str)
        except Exception as e:
            self._module.fail_json(msg="Failed to set inventory to host: %s" % e)


def normalize_macro_name(macro_name):
    # Zabbix handles macro names in upper case characters
    if ':' in macro_name:
        macro_name = ':'.join([macro_name.split(':')[0].upper(), ':'.join(macro_name.split(':')[1:])])
    else:
        macro_name = macro_name.upper()

    # Valid format for macro is {$MACRO}
    if not macro_name.startswith('{$'):
        macro_name = '{$' + macro_name
    if not macro_name.endswith('}'):
        macro_name = macro_name + '}'

    return macro_name


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        host_name=dict(type='str', required=True),
        host_groups=dict(type='list', required=False),
        link_templates=dict(type='list', required=False),
        status=dict(type='str', default="enabled", choices=['enabled', 'disabled']),
        state=dict(type='str', default="present", choices=['present', 'absent']),
        inventory_mode=dict(type='str', required=False, choices=['automatic', 'manual', 'disabled']),
        ipmi_authtype=dict(type='int', default=None),
        ipmi_privilege=dict(type='int', default=None),
        ipmi_username=dict(type='str', required=False, default=None),
        ipmi_password=dict(type='str', required=False, default=None, no_log=True),
        tls_connect=dict(type='int', default=1),
        tls_accept=dict(type='int', default=1),
        tls_psk_identity=dict(type='str', required=False),
        tls_psk=dict(type='str', required=False),
        ca_cert=dict(type='str', required=False, aliases=['tls_issuer']),
        tls_subject=dict(type='str', required=False),
        inventory_zabbix=dict(type='dict', required=False),
        interfaces=dict(
            type='list',
            elements='dict',
            default=[],
            options=dict(
                type=dict(type='str', required=True, choices=['agent', '1', 'snmp', '2', 'ipmi', '3', 'jmx', '4']),
                main=dict(type='int', choices=[0, 1], default=0),
                useip=dict(type='int', choices=[0, 1], default=0),
                ip=dict(type='str', default=''),
                dns=dict(type='str', default=''),
                port=dict(type='str'),
                bulk=dict(type='int', choices=[0, 1], default=1),
                details=dict(
                    type='dict',
                    default={},
                    options=dict(
                        version=dict(type='int', choices=[1, 2, 3], default=2),
                        bulk=dict(type='int', choices=[0, 1], default=1),
                        community=dict(type='str'),
                        securityname=dict(type='str', default=''),
                        contextname=dict(type='str', default=''),
                        securitylevel=dict(type='int', choices=[0, 1, 2], default=0),
                        authprotocol=dict(type='int', choices=[0, 1], default=0),
                        authpassphrase=dict(type='str', default='', no_log=True),
                        privprotocol=dict(type='int', choices=[0, 1], default=0),
                        privpassphrase=dict(type='str', default='', no_log=True)
                    )
                )
            ),
            required_if=[
                ['useip', 0, ['dns']],
                ['useip', 1, ['ip']]
            ]
        ),
        force=dict(type='bool', default=True),
        proxy=dict(type='str', required=False),
        visible_name=dict(type='str', required=False),
        description=dict(type='str', required=False),
        macros=dict(
            type='list',
            elements='dict',
            aliases=['user_macros'],
            options=dict(
                macro=dict(type='str', required=True),
                value=dict(type='str', required=True),
                description=dict(type='str', default=''),
                type=dict(type='str', default='text', choices=['text', 'secret'])
            )
        ),
        tags=dict(
            type='list',
            elements='dict',
            aliases=['host_tags'],
            options=dict(
                tag=dict(type='str', required=True),
                value=dict(type='str', default='')
            )
        )
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    host_name = module.params['host_name']
    visible_name = module.params['visible_name']
    description = module.params['description']
    host_groups = module.params['host_groups']
    link_templates = module.params['link_templates']
    inventory_mode = module.params['inventory_mode']
    ipmi_authtype = module.params['ipmi_authtype']
    ipmi_privilege = module.params['ipmi_privilege']
    ipmi_username = module.params['ipmi_username']
    ipmi_password = module.params['ipmi_password']
    tls_connect = module.params['tls_connect']
    tls_accept = module.params['tls_accept']
    tls_psk_identity = module.params['tls_psk_identity']
    tls_psk = module.params['tls_psk']
    tls_issuer = module.params['ca_cert']
    tls_subject = module.params['tls_subject']
    inventory_zabbix = module.params['inventory_zabbix']
    status = module.params['status']
    state = module.params['state']
    interfaces = module.params['interfaces']
    force = module.params['force']
    proxy = module.params['proxy']
    macros = module.params['macros']
    tags = module.params['tags']

    # convert enabled to 0; disabled to 1
    status = 1 if status == "disabled" else 0

    host = Host(module)

    template_ids = []
    if link_templates:
        template_ids = host.get_template_ids(link_templates)

    group_ids = []

    if host_groups:
        group_ids = host.get_group_ids_by_group_names(host_groups)

    interfaces, ip = host.construct_host_interfaces(interfaces)

    if macros:
        # convert macros to zabbix native format - {$MACRO}
        for macro in macros:
            macro['macro'] = normalize_macro_name(macro['macro'])

            if LooseVersion(host._zbx_api_version) <= LooseVersion('4.4.0'):
                if 'description' in macro:
                    macro.pop('description', False)

            if 'type' in macro:
                if LooseVersion(host._zbx_api_version) < LooseVersion('5.0.0'):
                    macro.pop('type')
                else:
                    if macro['type'] == 'text':
                        macro['type'] = 0
                    elif macro['type'] == 'secret':
                        macro['type'] = 1

    # Use proxy specified, or set to 0
    if proxy:
        proxy_id = host.get_proxyid_by_proxy_name(proxy)
    else:
        proxy_id = 0

    # check if host exist
    is_host_exist = host.is_host_exist(host_name)

    if is_host_exist:
        # get host id by host name
        zabbix_host_obj = host.get_host_by_host_name(host_name)
        host_id = zabbix_host_obj['hostid']

        # If proxy is not specified as a module parameter, use the existing setting
        if proxy is None:
            proxy_id = int(zabbix_host_obj['proxy_hostid'])

        if state == "absent":
            # remove host
            host.delete_host(host_id, host_name)
            module.exit_json(changed=True, result="Successfully delete host %s" % host_name)
        else:
            if not host_groups:
                # if host_groups have not been specified when updating an existing host, just
                # get the group_ids from the existing host without updating them.
                group_ids = host.get_group_ids_by_host_id(host_id)

            # get existing host's interfaces
            exist_interfaces = host._zapi.hostinterface.get({'output': 'extend', 'hostids': host_id})
            exist_interfaces.sort(key=lambda x: int(x['interfaceid']))

            # When force=no is specified, append existing interfaces to interfaces to update. When
            # no interfaces have been specified, copy existing interfaces as specified from the API.
            # Do the same with templates and host groups.
            if not force or not interfaces:
                for interface in copy.deepcopy(exist_interfaces):
                    for key in tuple(interface.keys()):
                        # remove values not used during hostinterface.add/update calls
                        if key not in ["type", "dns", "main", "useip", "ip", "port", "details", "bulk"]:
                            interface.pop(key, None)
                        # fix values for properties
                        if key in ['useip', 'main', 'type', 'bulk']:
                            interface[key] = int(interface[key])
                        elif key == 'details' and not interface[key]:
                            interface[key] = {}

                    if interface not in interfaces:
                        interfaces.append(interface)

            if not force or link_templates is None:
                template_ids = list(set(template_ids + host.get_host_templates_by_host_id(host_id)))

            if not force:
                for group_id in host.get_group_ids_by_host_id(host_id):
                    if group_id not in group_ids:
                        group_ids.append(group_id)

                # Macros not present in host.update will be removed if we dont copy them when force=no
                if macros is not None and 'macros' in zabbix_host_obj.keys():
                    provided_macros = [m['macro'] for m in macros]
                    existing_macros = zabbix_host_obj['macros']
                    for macro in existing_macros:
                        if macro['macro'] not in provided_macros:
                            macros.append(macro)

                # Tags not present in host.update will be removed if we dont copy them when force=no
                if tags is not None and 'tags' in zabbix_host_obj.keys():
                    provided_tags = [t['tag'] for t in tags]
                    existing_tags = zabbix_host_obj['tags']
                    for tag in existing_tags:
                        if tag['tag'] not in provided_tags:
                            tags.append(tag)

            # update host
            if host.check_all_properties(
                    host_id, group_ids, status, interfaces, template_ids, exist_interfaces, zabbix_host_obj, proxy_id,
                    visible_name, description, host_name, inventory_mode, inventory_zabbix, tls_accept, tls_psk_identity, tls_psk,
                    tls_issuer, tls_subject, tls_connect, ipmi_authtype, ipmi_privilege,
                    ipmi_username, ipmi_password, macros, tags):

                host.update_host(
                    host_name, group_ids, status, host_id, interfaces, exist_interfaces, proxy_id, visible_name,
                    description, tls_connect, tls_accept, tls_psk_identity, tls_psk, tls_issuer, tls_subject,
                    ipmi_authtype, ipmi_privilege, ipmi_username, ipmi_password, macros, tags)

                host.link_or_clear_template(
                    host_id, template_ids, tls_connect, tls_accept, tls_psk_identity, tls_psk, tls_issuer,
                    tls_subject, ipmi_authtype, ipmi_privilege, ipmi_username, ipmi_password)

                host.update_inventory_mode(host_id, inventory_mode)
                host.update_inventory_zabbix(host_id, inventory_zabbix)

                module.exit_json(changed=True,
                                 result="Successfully update host %s (%s) and linked with template '%s'"
                                        % (host_name, ip, link_templates))
            else:
                module.exit_json(changed=False)

    else:
        if state == "absent":
            # the host is already deleted.
            module.exit_json(changed=False)

        if not group_ids:
            module.fail_json(msg="Specify at least one group for creating host '%s'." % host_name)

        if not interfaces or (interfaces and len(interfaces) == 0):
            if LooseVersion(host._zbx_api_version) < LooseVersion('5.2.0'):
                module.fail_json(msg="Specify at least one interface for creating host '%s'." % host_name)

        # create host
        host_id = host.add_host(
            host_name, group_ids, status, interfaces, proxy_id, visible_name, description, tls_connect, tls_accept,
            tls_psk_identity, tls_psk, tls_issuer, tls_subject, ipmi_authtype, ipmi_privilege, ipmi_username,
            ipmi_password, macros, tags)

        host.link_or_clear_template(
            host_id, template_ids, tls_connect, tls_accept, tls_psk_identity, tls_psk, tls_issuer, tls_subject,
            ipmi_authtype, ipmi_privilege, ipmi_username, ipmi_password)

        host.update_inventory_mode(host_id, inventory_mode)
        host.update_inventory_zabbix(host_id, inventory_zabbix)

        module.exit_json(changed=True, result="Successfully added host %s (%s) and linked with template '%s'" % (
            host_name, ip, link_templates))


if __name__ == '__main__':
    main()
