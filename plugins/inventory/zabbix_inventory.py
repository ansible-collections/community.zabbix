#
# Copyright: (c), Ansible Project
#
# (c) 2013, Greg Buehler
# (c) 2018, Filippo Ferrazini
# (c) 2021, Timothy Test
# Modified from ServiceNow Inventory Plugin and Zabbix inventory Script
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
name: community.zabbix.zabbix_inventory
plugin_type: inventory
author:
    - Timothy Test (@ttestscripting)
short_description: Zabbix Inventory Plugin
version_added: 1.4.0
description:
    - Zabbix Inventory plugin
    - All vars from zabbix are prefixed with zbx_
requirements:
    - "python >= 2.6"
    - "zabbix-api >= 0.5.4"
options:
    server_url:
        description:
            - URL of Zabbix server, with protocol (http or https).
              C(url) is an alias for C(server_url).
        required: true
        type: str
        aliases: [ url ]
        env:
          - name: ZABBIX_SERVER
    proxy:
        description: Proxy server to use for reaching zabbix API
        type: string
        default: ''
    host_zapi_query:
        description:
            - API query for hosts - see zabbix documentation for more details U(https://www.zabbix.com/documentation/current/manual/api/reference/host/get)
        type: dict
        elements: dict
        default: {}
        suboptions:
            selectApplications:
                type: str
                description:
                    - query
                    - Return an applications property with host applications.
                    - To return all values specify 'extend'
                    - Can be limited to different fields for example setting the vaule to ['name'] will only return the name
                    - Additional fields can be specified by comma seperated value ['name', 'field2']
                    - Please see U(https://www.zabbix.com/documentation/current/manual/api/reference/application/object) for more details on field names
            selectDiscoveries:
                type: str
                description:
                    - query
                    - Return a discoveries property with host low-level discovery rules.
                    - To return all values specify 'extend'
                    - Can be limited to different fields for example setting the vaule to ['name'] will only return the name
                    - Additional fields can be specified by comma seperated value ['name', 'field2']
                    - Please see U(https://www.zabbix.com/documentation/current/manual/api/reference/discoveryrule/object) for more details on field names
            selectDiscoveryRule:
                type: str
                description:
                    - query
                    - Return a discoveryRule property with the low-level discovery rule that created the host (from host prototype in VMware monitoring).
                    - To return all values specify 'extend'
                    - Can be limited to different fields for example setting the vaule to ['name'] will only return the name
                    - Additional fields can be specified by comma seperated value ['name', 'field2']
                    - please see U(https://www.zabbix.com/documentation/current/manual/api/reference/discoveryrule/object)  for more details on field names
            selectGraphs:
                type: str
                description:
                    - query
                    - Return a discoveries property with host low-level discovery rules.
                    - To return all values specify 'extend'
                    - Can be limited to different fields for example setting the vaule to ['name'] will only return the name
                    - Additional fields can be specified by comma seperated value ['name', 'field2']
                    - Please see U(https://www.zabbix.com/documentation/current/manual/api/reference/graph/object) for more details on field names
            selectGroups:
                type: str
                description:
                    - query
                    - Return a groups property with host groups data that the host belongs to.
                    - To return all values specify 'extend'
                    - Can be limited to different fields for example setting the vaule to ['name'] will only return the name
                    - Additional fields can be specified by comma seperated value ['name', 'field2']
                    - Please see U(https://www.zabbix.com/documentation/current/manual/api/reference/hostgroup/object) for more details on field names
            selectHostDiscovery:
                type: str
                description:
                    - query
                    - Return a hostDiscovery property with host discovery object data.
                    - To return all values specify 'extend'
                    - Can be limited to different fields for example setting the vaule to ['name'] will only return the name
                    - Additional fields can be specified by comma seperated value ['name', 'field2']
                    - Please see U(https://www.zabbix.com/documentation/current/manual/api/reference/host/get) for more details on field names
            selectHttpTests:
                type: str
                description:
                    - query
                    - Return an httpTests property with host web scenarios.
                    - To return all values specify 'extend'
                    - Can be limited to different fields for example setting the vaule to ['name'] will only return the name
                    - Additional fields can be specified by comma seperated value ['name', 'field2']
                    - Please see U(https://www.zabbix.com/documentation/current/manual/api/reference/httptest/object) for more details on field names
            selectInterfaces:
                type: str
                description:
                    - query
                    - Return an interfaces property with host interfaces.
                    - To return all values specify 'extend'
                    - Can be limited to different fields for example setting the vaule to ['name'] will only return the name
                    - Additional fields can be specified by comma seperated value ['name', 'field2']
                    - Please see U(https://www.zabbix.com/documentation/current/manual/api/reference/hostinterface/object) for more details on field names
            selectInventory:
                type: str
                description:
                    - query
                    - Return an inventory property with host inventory data.
                    - To return all values specify 'extend'
                    - Can be limited to different fields for example setting the vaule to ['name'] will only return the name
                    - Additional fields can be specified by comma seperated value ['name', 'field2']
                    - Please see U(https://www.zabbix.com/documentation/current/manual/api/reference/host/object#host_inventory) for more details on field names
            selectItems:
                type: str
                description:
                    - query
                    - Return an items property with host items.
                    - To return all values specify 'extend'
                    - Can be limited to different fields for example setting the vaule to ['name'] will only return the name
                    - Additional fields can be specified by comma seperated value ['name', 'field2']
                    - Please see U(https://www.zabbix.com/documentation/current/manual/api/reference/item/object) for more details on field names
            selectMacros:
                type: str
                description:
                    - query
                    - Return a macros property with host macros.
                    - To return all values specify 'extend'
                    - Can be limited to different fields for example setting the vaule to ['name'] will only return the name
                    - Additional fields can be specified by comma seperated value ['name', 'field2']
                    - Please see U(https://www.zabbix.com/documentation/current/manual/api/reference/usermacro/object) for more details on field names
            selectParentTemplates:
                type: str
                description:
                    - query
                    - Return a parentTemplates property with templates that the host is linked to
                    - To return all values specify 'extend'
                    - Can be limited to different fields for example setting the vaule to ['name'] will only return the name
                    - Additional fields can be specified by comma seperated value ['name', 'field2']
                    - Please see U(https://www.zabbix.com/documentation/current/manual/api/reference/template/object) for more details on field names
            selectDashboards:
                type: str
                description:
                    - query
                    - Return a dashboards property.
                    - To return all values specify 'extend'
                    - Can be limited to different fields for example setting the vaule to ['name'] will only return the name
                    - Additional fields can be specified by comma seperated value ['name', 'field2']
                    - Please see U(https://www.zabbix.com/documentation/current/manual/api/reference/templatedashboard/object) for more details on field names
            selectTags:
                type: str
                description:
                    - query
                    - Return a tags property with host tags.
                    - To return all values specify 'extend'
                    - Can be limited to different fields for example setting the vaule to ['name'] will only return the name
                    - Additional fields can be specified by comma seperated value ['name', 'field2']
                    - Please see U(https://www.zabbix.com/documentation/current/manual/api/reference/host/object#host_tag) for more details on field names
            selectInheritedTags:
                type: str
                description:
                    - query
                    - Return an inheritedTags property with tags that are on all templates which are linked to host.
                    - To return all values specify 'extend'
                    - Can be limited to different fields for example setting the vaule to ['name'] will only return the name
                    - Additional fields can be specified by comma seperated value ['name', 'field2']
                    - Please see U(https://www.zabbix.com/documentation/current/manual/api/reference/host/object#host_tag) for more details on field names
            selectTriggers:
                type: str
                description:
                    - query
                    - Return a triggers property with host triggers.
                    - To return all values specify 'extend'
                    - Can be limited to different fields for example setting the vaule to ['name'] will only return the name
                    - Additional fields can be specified by comma seperated value ['name', 'field2']
                    - Please see U(https://www.zabbix.com/documentation/current/manual/api/reference/host/object#host_tag) for more details on field names
    login_user:
        description:
            - Zabbix user name.
        type: str
        required: true
        env:
          - name: ZABBIX_USERNAME
    login_password:
        description:
            - Zabbix user password.
        type: str
        required: true
        env:
          - name: ZABBIX_PASSWORD
    http_login_user:
        description:
            - Basic Auth login
        type: str
    http_login_password:
        description:
            - Basic Auth password
        type: str
    timeout:
        description:
            - The timeout of API request (seconds).
        type: int
        default: 10
    validate_certs:
      description:
       - If set to False, SSL certificates will not be validated. This should only be used on personally controlled sites using self-signed certificates.
      type: bool
      default: true
      env:
        - name: ZABBIX_VALIDATE_CERTS
    add_zabbix_groups:
      description:
       - If set to True, hosts will be added to groups based on their zabbix groups
      type: bool
      default: false
extends_documentation_fragment:
    - constructed
    - inventory_cache
'''

EXAMPLES = r'''
# Simple Inventory Plugin example
# This will create an inventory with details from zabbix such as applications name, applicaitonids, Parent Template Name, and group membership name
#It will also create 2 ansible inventory groups for enabled and disabled hosts in zabbix based on the status field.
plugin: community.zabbix.zabbix_inventory
server_url: https://zabbix.com
login_user: Admin
login_password: password
host_zapi_query:
  selectApplications: ['name', 'applicationid']
  selectParentTemplates: ['name']
  selectGroups: ['name']
validate_certs: false
groups:
  enabled: zbx_status == "0"
  disabled: zbx_status == "1"


#Using Keyed Groups
plugin: community.zabbix.zabbix_inventory
server_url: https://zabbix.com
login_user: Admin
login_password: password
validate_certs: false
keyed_groups:
  - key: zbx_status | lower
    prefix: 'env'
  - key: zbx_description | lower
    prefix: 'test'
    separator: ''

#Using proxy format of proxy is 'http://<user>:<pass>@<proxy>:<port>' or 'http://<proxy>:<port>'
plugin: community.zabbix.zabbix_inventory
server_url: https://zabbix.com
proxy: http://someproxy:8080
login_user: Admin
login_password: password
validate_certs: false

#Organize inventory groups based on zabbix host groups
plugin: community.zabbix.zabbix_inventory
server_url: https://zabbix.com
add_zabbix_groups: true
login_user: Admin
login_password: password
validate_certs: false

#Using compose to modify vars
plugin: community.zabbix.zabbix_inventory
server_url: https://zabbix.com
login_user: Admin
login_password: password
validate_certs: false
compose:
  zbx_testvar: zbx_status.replace("1", "Disabled")


'''

from ansible.plugins.inventory import BaseInventoryPlugin, Constructable, Cacheable, to_safe_group_name
import os
import atexit
import traceback

try:
    from zabbix_api import ZabbixAPI
    HAS_ZABBIX_API = True
except ImportError:
    ZBX_IMP_ERR = traceback.format_exc()
    HAS_ZABBIX_API = False


class InventoryModule(BaseInventoryPlugin, Constructable, Cacheable):

    NAME = 'community.zabbix.zabbix_inventory'

    def login_zabbix(self):
        # set proxy information if required
        proxy = self.get_option('proxy')
        os.environ['http_proxy'] = proxy
        os.environ['HTTP_PROXY'] = proxy
        os.environ['https_proxy'] = proxy
        os.environ['HTTPS_PROXY'] = proxy

        server_url = self.get_option('server_url')
        http_login_user = self.get_option('login_user')
        http_login_password = self.get_option('login_password')
        validate_certs = self.get_option('validate_certs')
        timeout = self.get_option('timeout')
        self._zapi = ZabbixAPI(server_url, timeout=timeout, user=http_login_user, passwd=http_login_password, validate_certs=validate_certs)
        self.login()
        self._zbx_api_version = self._zapi.api_version()[:5]

    def login(self):
        # check if api already logged in
        if not self._zapi.auth != '':
            try:
                login_user = self.get_option('login_user')
                login_password = self.get_option('login_password')
                self._zapi.login(login_user, login_password)
                atexit.register(self._zapi.logout)
            except Exception as e:
                self.display.vvv(msg="Failed to connect to Zabbix server: %s" % e)

    def verify_file(self, path):
        valid = False
        if super(InventoryModule, self).verify_file(path):
            if path.endswith(('zabbix_inventory.yaml', 'zabbix_inventory.yml')):
                valid = True
            else:
                self.display.vvv(
                    'Skipping due to inventory source not ending in "zabbix_inventory.yaml" nor "zabbix_inventory.yml"')
        return valid

    def parse(self, inventory, loader, path,
              cache=True):  # Plugin interface (2)
        super(InventoryModule, self).parse(inventory, loader, path)

        self._read_config_data(path)
        self.cache_key = self.get_cache_key(path)

        self.use_cache = self.get_option('cache') and cache
        self.update_cache = self.get_option('cache') and not cache

        self.login_zabbix()
        zapi_query = self.get_option('host_zapi_query')
        content = self._zapi.host.get(zapi_query)

        strict = self.get_option('strict')

        for record in content:
            # add host to inventory
            host_name = self.inventory.add_host(record['host'])
            # set variables for host
            for k in record.keys():
                self.inventory.set_variable(host_name, 'zbx_%s' % k, record[k])

            # added for compose vars and keyed groups
            self._set_composite_vars(
                self.get_option('compose'),
                self.inventory.get_host(host_name).get_vars(), host_name, strict)

            self._add_host_to_composed_groups(self.get_option('groups'), dict(), host_name, strict)
            self._add_host_to_keyed_groups(self.get_option('keyed_groups'), dict(), host_name, strict)

        # organize inventory by zabbix groups
        if self.get_option('add_zabbix_groups'):
            content = self._zapi.host.get({'selectGroups': ['name']})
            for record in content:
                host_name = record['host']
                if len(record['groups']) >= 1:
                    for group in record['groups']:
                        group_name = to_safe_group_name(group['name'])
                        self.inventory.add_group(group_name)
                        self.inventory.add_child(group_name, host_name)
