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
      - Specifies path portion in Zabbix WebUI URL, e.g. for https://myzabbixfarm.com/zabbixeu zabbix_url_path=zabbixeu.
      - "If Zabbix WebUI is running at the root, i.e. https://myzabbixfarm.com/, then assign empty string to this variable C(zabbix_url_path: '')."
    default: zabbix
    env:
      - name: ANSIBLE_ZABBIX_URL_PATH
    vars:
      - name: ansible_zabbix_url_path
  http_login_user:
    type: str
    description:
      - The http user to access zabbix url with Basic Auth
    vars:
      - name: http_login_user
  http_login_password:
    type: str
    description:
      - The http password to access zabbix url with Basic Auth
    vars:
      - name: http_login_password
  zabbix_http_headers:
    type: dict
    description:
      - A dictionary of additional HTTP headers to be sent with every request to the Zabbix API.
      - These headers are applied first, and can be overridden by plugin-specific headers like 'Authorization'.
    vars:
      - name: ansible_zabbix_http_headers
"""

import json
import base64

from uuid import uuid4

from ansible.module_utils.basic import to_text
from ansible.errors import AnsibleConnectionFailure
from ansible.plugins.httpapi import HttpApiBase
from ansible.module_utils.compat.version import StrictVersion
from ansible.module_utils.connection import ConnectionError


class HttpApi(HttpApiBase):
    auth = None
    url_path = '/zabbix'  # By default Zabbix WebUI is on http(s)://FQDN/zabbix

    def __init__(self, connection):
        super().__init__(connection)
        self.connection._auth = {'Content-Type': 'application/json-rpc'}

    def set_become(self, become_context):
        """As this is an http rpc call there is no elevation available
        """
        pass

    def update_auth(self, response, response_text):
        return None

    def login(self, username, password):
        if auth_key := self.get_option('zabbix_auth_key'):
            self.auth = auth_key
            return

        payload = self.payload_builder("user.login", username=username, password=password)

        code, response = self.send_request(data=payload)

        if code == 200 and response != '':
            self.auth = response

    def logout(self):
        if self.auth and not self.get_option('zabbix_auth_key'):
            payload = self.payload_builder("user.logout")
            self.send_request(data=payload)

    def api_version(self):
        url_path = self.get_option('zabbix_url_path')
        if isinstance(url_path, str):
            # zabbix_url_path provided (even if it is an empty string)
            if url_path == '':
                self.url_path = ''
            else:
                self.url_path = '/' + url_path
        if not hasattr(self.connection, 'zbx_api_version'):
            code, version = self.send_request(data=self.payload_builder('apiinfo.version'))
            if code == 200 and len(version) != 0:
                self.connection.zbx_api_version = version
            else:
                raise ConnectionError("Could not get API version from Zabbix. Got HTTP code %s. Got version %s" % (code, version))
        return self.connection.zbx_api_version

    def send_request(self, data, request_method="POST", path="/api_jsonrpc.php"):
        headers = {}
        # Apply custom headers first. Plugin-specific headers set later will take precedence.
        custom_headers = self.get_option('zabbix_http_headers')
        if isinstance(custom_headers, dict):
            headers.update(custom_headers)

        path = self.url_path + path

        if self.auth and data['method'] not in ['user.login', 'apiinfo.version']:
            if StrictVersion(self.api_version()) >= StrictVersion('6.4'):
                headers['Authorization'] = 'Bearer ' + self.auth
            else:
                data['auth'] = self.auth

        http_login_user = self.get_option('http_login_user')
        http_login_password = self.get_option('http_login_password')
        if http_login_user and http_login_user != '-42':
            # Need to add Basic auth header
            credentials = (http_login_user + ':' + http_login_password).encode('ascii')
            headers['Authorization'] = 'Basic ' + base64.b64encode(credentials).decode("ascii")

        try:
            self._display_request(request_method, path, data['method'])
            response, response_data = self.connection.send(
                path,
                json.dumps(data),
                method=request_method,
                headers=headers
            )
            value = to_text(response_data.getvalue())

            try:
                json_data = json.loads(value) if value else {}
            # JSONDecodeError only available on Python 3.5+
            except ValueError:
                raise ConnectionError("Invalid JSON response: %s" % value)

            if "error" in json_data:
                # Get this response from Zabbix when we switch username to execute REST API
                if "re-login" in json_data["error"]["data"]:
                    # Need to login with new username/password
                    self.login(self.connection.get_option('remote_user'), self.connection.get_option('password'))
                    # Replace 'auth' field in payload with new one (we got from login process)
                    data = json.loads(data)
                    data['auth'] = self.connection._auth['auth']
                    data = json.dumps(data)
                    # Re-send the request we initially were trying to execute
                    response, response_data = self.connection.send(
                        path,
                        data,
                        method=request_method,
                        headers=headers
                    )
                    value = to_text(response_data.getvalue())

                    try:
                        json_data = json.loads(value) if value else {}
                    # JSONDecodeError only available on Python 3.5+
                    except ValueError:
                        raise ConnectionError("Invalid JSON response: %s" % value)

                    if "error" in json_data:
                        raise ConnectionError("REST API returned %s when sending %s" % (json_data["error"], data))

                    if "result" in json_data:
                        json_data = json_data["result"]

                    try:
                        # Some methods return bool not a dict in "result"
                        iter(json_data)
                    except TypeError:
                        # Do not try to find "error" if it is not a dict
                        return response.getcode(), json_data

                    return response.getcode(), json_data

                raise ConnectionError("REST API returned %s when sending %s" % (json_data["error"], data))

            if "result" in json_data:
                json_data = json_data["result"]

            try:
                # Some methods return bool not a dict in "result"
                iter(json_data)
            except TypeError:
                # Do not try to find "error" if it is not a dict
                return response.getcode(), json_data

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

    def _display_request(self, request_method, path, jsonrpc_method):
        self.connection.queue_message(
            "vvvv",
            "Zabbix httpapi request: %s %s%s (%s)" % (
                request_method, self.connection._url, path, jsonrpc_method),
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

    def handle_httperror(self, exc):
        # The method defined in ansible.plugins.httpapi
        # We need to override it to avoid endless re-tries if HTTP authentication fails

        if exc.code == 401:
            return False

        return exc
