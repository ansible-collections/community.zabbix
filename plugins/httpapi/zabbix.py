# (c) 2021, Markus Fischbacher (fischbacher.markus@gmail.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# Quick Link to Zabbix API docs: https://www.zabbix.com/documentation/current/manual/api

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
name: zabbix
author:
  - Markus Fischbacher (@rockaut)
  - Evgeny Yurchenko (@BGmot)
short_description: HttpApi Plugin for Zabbix
description:
  - This HttpApi plugin provides methods to connect to Zabbix over their HTTP(S)-based api.
version_added: 1.8.0
options:
  zabbix_auth_key:
    type: str
    description:
      - Specifies API authentication key
    env:
      - name: ANSIBLE_ZABBIX_AUTH_KEY
    vars:
      - name: ansible_zabbix_auth_key
  zabbix_url_path:
    type: str
    description:
      - Specifies path portion in Zabbix WebUI URL, e.g. for https://myzabbixfarm.com/zabbixeu zabbix_url_path=zabbixeu
    default: zabbix
    env:
      - name: ANSIBLE_ZABBIX_URL_PATH
    vars:
      - name: ansible_zabbix_url_path
"""

import json

from uuid import uuid4

from ansible.module_utils.basic import to_text
from ansible.errors import AnsibleConnectionFailure
from ansible.plugins.httpapi import HttpApiBase
from ansible.module_utils.connection import ConnectionError


BASE_HEADERS = {
    'Content-Type': 'application/json-rpc',
    'Accept': 'application/json',
}


class HttpApi(HttpApiBase):
    zbx_api_version = None
    auth_key = None
    url_path = '/zabbix'  # By default Zabbix WebUI is on http(s)://FQDN/zabbix

    def set_become(self, become_context):
        """As this is an http rpc call there is no elevation available
        """
        pass

    def update_auth(self, response, response_text):
        return None

    def login(self, username, password):
        self.auth_key = self.get_option('zabbix_auth_key')
        if self.auth_key:
            self.connection._auth = {'auth': self.auth_key}
            return

        payload = self.payload_builder("user.login", user=username, password=password)
        code, response = self.send_request(data=payload)

        if code == 200 and response != '':
            self.connection._auth = {'auth': response}

    def logout(self):
        if self.connection._auth and not self.auth_key:
            payload = self.payload_builder("user.logout")
            self.send_request(data=payload)

    def api_version(self):
        url_path = self.get_option('zabbix_url_path')
        if isinstance(url_path, str):
            # zabbix_url_path provided (even if it is an empty string)
            self.url_path = '/' + url_path
        if not self.zbx_api_version:
            if not hasattr(self.connection, 'zbx_api_version'):
                code, version = self.send_request(data=self.payload_builder('apiinfo.version'))
                if code == 200 and version != '':
                    self.connection.zbx_api_version = version
            self.zbx_api_version = self.connection.zbx_api_version
        return self.zbx_api_version

    def send_request(self, data=None, request_method="POST", path="/api_jsonrpc.php"):
        path = self.url_path + path
        if not data:
            data = {}

        if self.connection._auth:
            data['auth'] = self.connection._auth['auth']

        data = json.dumps(data)
        try:
            self._display_request(request_method, path)
            response, response_data = self.connection.send(
                path,
                data,
                method=request_method,
                headers=BASE_HEADERS
            )
            value = to_text(response_data.getvalue())

            try:
                json_data = json.loads(value) if value else {}
                if "result" in json_data:
                    json_data = json_data["result"]
            # JSONDecodeError only available on Python 3.5+
            except ValueError:
                raise ConnectionError("Invalid JSON response: %s" % value)

            try:
                # Some methods return bool not a dict in "result"
                iter(json_data)
            except TypeError:
                # Do not try to find "error" if it is not a dict
                return response.getcode(), json_data

            if "error" in json_data:
                raise ConnectionError("REST API returned %s when sending %s" % (json_data["error"], data))

            return response.getcode(), json_data
        except AnsibleConnectionFailure as e:
            self.connection.queue_message("vvv", "AnsibleConnectionFailure: %s" % e)
            if to_text("Could not connect to") in to_text(e):
                raise
            if to_text("401") in to_text(e):
                return 401, "Authentication failure"
            else:
                return 404, "Object not found"
        except Exception as e:
            raise e

    def _display_request(self, request_method, path):
        self.connection.queue_message(
            "vvvv",
            "Web Services: %s %s/%s" % (request_method, self.connection._url, path),
        )

    def _get_response_value(self, response_data):
        return to_text(response_data.getvalue())

    def _response_to_json(self, response_text):
        try:
            return json.loads(response_text) if response_text else {}
        # JSONDecodeError only available on Python 3.5+
        except ValueError:
            raise ConnectionError("Invalid JSON response: %s" % response_text)

    @staticmethod
    def payload_builder(method_, auth_=None, **kwargs):
        reqid = str(uuid4())
        req = {'jsonrpc': '2.0', 'method': method_, 'id': reqid}
        req['params'] = (kwargs)

        return req
