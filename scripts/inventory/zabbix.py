#!/usr/bin/env python

# (c) 2013, Greg Buehler
# (c) 2018, Filippo Ferrazini
#
# This file is part of Ansible,
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

######################################################################

"""
Zabbix Server external inventory script.
========================================

Returns hosts and hostgroups from Zabbix Server.
If you want to run with --limit against a host group with space in the
name, use asterisk. For example --limit="Linux*servers".

Configuration is read from `zabbix.ini`.

Tested with Zabbix Server 2.0.6, 3.2.3 and 3.4.
"""

from __future__ import print_function

import os
import sys
import argparse
import json
import atexit
from ansible.module_utils.six.moves import configparser
from ansible.module_utils.compat.version import LooseVersion
from ansible.module_utils.urls import Request
from ansible.module_utils.six.moves.urllib.error import URLError, HTTPError


class ZabbixInventory(object):

    def read_settings(self):
        config = configparser.ConfigParser()
        conf_path = "./zabbix.ini"
        if not os.path.exists(conf_path):
            conf_path = os.path.dirname(os.path.realpath(__file__)) + "/zabbix.ini"
        if os.path.exists(conf_path):
            config.read(conf_path)
        # server
        if config.has_option("zabbix", "server"):
            self.zabbix_server = config.get("zabbix", "server")

        # login
        if config.has_option("zabbix", "username"):
            self.zabbix_username = config.get("zabbix", "username")
        if config.has_option("zabbix", "password"):
            self.zabbix_password = config.get("zabbix", "password")
        if config.has_option("zabbix", "auth_token"):
            self.auth_token = config.get("zabbix", "auth_token")
        # ssl certs
        if config.has_option("zabbix", "validate_certs"):
            if config.get("zabbix", "validate_certs") in ["false", "False", False]:
                self.validate_certs = False
        # timeout
        if config.has_option("zabbix", "timeout"):
            self.timeout = config.get("zabbix", "timeout")
        # host inventory
        if config.has_option("zabbix", "read_host_inventory"):
            if config.get("zabbix", "read_host_inventory") in ["true", "True", True]:
                self.read_host_inventory = True
        # host interface
        if config.has_option("zabbix", "use_host_interface"):
            if config.get("zabbix", "use_host_interface") in ["false", "False", False]:
                self.use_host_interface = False

    def read_cli(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("--host")
        parser.add_argument("--list", action="store_true")
        self.options = parser.parse_args()

    def hoststub(self):
        return {
            "hosts": []
        }

    def api_request(self, method, params=None):
        server_url = self.zabbix_server
        validate_certs = self.validate_certs
        timeout = self.timeout

        headers = {"Content-Type": "application/json-rpc"}
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "id": "1"
        }
        if params is None:
            payload["params"] = {}
        else:
            payload["params"] = params

        if self.auth != "":
            if (LooseVersion(self.zabbix_version) >= LooseVersion("7.0")):
                headers["Authorization"] = "Bearer " + self.auth
            else:
                payload["auth"] = self.auth

        api_url = server_url + "/api_jsonrpc.php"
        req = Request(
            headers=headers,
            timeout=timeout,
            validate_certs=validate_certs
        )
        try:
            response = req.post(api_url, data=json.dumps(payload))
        except ValueError:
            print("Error: Something went wrong with JSON loading.", file=sys.stderr)
            sys.exit(1)
        except (URLError, HTTPError) as error:
            print(error, file=sys.stderr)

        return response

    def get_version(self):
        response = self.api_request(
            "apiinfo.version"
        )
        res = json.load(response)
        self.zabbix_version = res["result"]

    def login_zabbix(self):
        auth_token = self.auth_token
        if auth_token:
            self.auth = auth_token
            return

        atexit.register(self.logout_zabbix)

        login_user = self.zabbix_username
        login_password = self.zabbix_password
        response = self.api_request(
            "user.login",
            {
                "username": login_user,
                "password": login_password
            }
        )
        res = json.load(response)
        self.auth = res["result"]

    def logout_zabbix(self):
        self.api_request(
            "user.logout",
            []
        )

    def get_host(self, name):
        api_query = {"output": "extend", "selectGroups": "extend", "filter": {"host": [name]}}
        if self.use_host_interface:
            api_query["selectInterfaces"] = ["useip", "ip", "dns"]
        if self.read_host_inventory:
            api_query["selectInventory"] = "extend"

        data = {"ansible_ssh_host": name}
        if self.use_host_interface or self.read_host_inventory:
            response = self.api_request("host.get", api_query)
            response_obj = json.load(response)
            if len(response_obj['result']) > 0:
                host_data = response_obj['result'][0]
                # check if zabbix api returned interfaces element
                if "interfaces" in host_data:
                    # check for a interfaces list that contains at least interface
                    if len(host_data["interfaces"]) >= 1:
                        # use first interface only
                        if host_data["interfaces"][0]["useip"] == '0':
                            data["ansible_ssh_host"] = host_data["interfaces"][0]["dns"]
                        else:
                            data["ansible_ssh_host"] = host_data["interfaces"][0]["ip"]
                if ("inventory" in host_data) and (host_data["inventory"]):
                    data.update(host_data["inventory"])
        return data

    def get_list(self):
        api_query = {"output": "extend", "selectGroups": "extend"}
        if self.use_host_interface:
            api_query["selectInterfaces"] = ["useip", "ip", "dns"]
        if self.read_host_inventory:
            api_query["selectInventory"] = "extend"

        response = self.api_request("host.get", api_query)
        hosts_data = json.load(response)["result"]
        data = {"_meta": {"hostvars": {}}}
        data[self.defaultgroup] = self.hoststub()
        for host in hosts_data:
            hostname = host["name"]
            hostvars = dict()
            data[self.defaultgroup]["hosts"].append(hostname)

            for group in host["groups"]:
                groupname = group["name"]

                if groupname not in data:
                    data[groupname] = self.hoststub()

                data[groupname]["hosts"].append(hostname)
            # check if zabbix api returned a interfaces element
            if "interfaces" in host:
                # check for a interfaces list that contains at least interface
                if len(host["interfaces"]) >= 1:
                    # use first interface only
                    if host["interfaces"][0]["useip"] == 0:
                        hostvars["ansible_ssh_host"] = host["interfaces"][0]["dns"]
                    else:
                        hostvars["ansible_ssh_host"] = host["interfaces"][0]["ip"]
            if ("inventory" in host) and (host["inventory"]):
                hostvars.update(host["inventory"])
            data["_meta"]["hostvars"][hostname] = hostvars

        return data

    def __init__(self):

        self.defaultgroup = "group_all"
        self.zabbix_server = None
        self.zabbix_username = None
        self.zabbix_password = None
        self.auth_token = None
        self.auth = ""
        self.validate_certs = True
        self.timeout = 30
        self.read_host_inventory = False
        self.use_host_interface = True
        self.zabbix_version = ""

        self.meta = {}

        self.read_settings()
        self.read_cli()

        if self.zabbix_server and self.zabbix_username:
            try:
                self.get_version()
                self.login_zabbix()
            # zabbix_api tries to exit if it cannot parse what the zabbix server returned
            # so we have to use SystemExit here
            except (Exception, SystemExit) as e:
                print("Error: got the exception '%s'. Check your zabbix.ini." % e, file=sys.stderr)
                sys.exit(1)

            if self.options.host:
                data = self.get_host(self.options.host)
                print(json.dumps(data, indent=2))

            elif self.options.list:
                data = self.get_list()
                print(json.dumps(data, indent=2))

            else:
                print("usage: --list  ..OR.. --host <hostname>", file=sys.stderr)
                sys.exit(1)

        else:
            print("Error: Configuration of server and credentials are required. See zabbix.ini.", file=sys.stderr)
            sys.exit(1)


ZabbixInventory()
