# (c) 2021, Markus Fischbacher (fischbacher.markus@gmail.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# Quick Link to Zabbix API docs: https://www.zabbix.com/documentation/current/manual/api

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
name: jsonrpc
author: Markus Fischbacher (@rockaut)
short_description: HttpApi Plugin for Zabbix
description:
  - This HttpApi plugin provides methods to connect to Zabbix over their HTTP(S)-based api.
version_added: 1.6.0
"""

import json

from uuid import uuid4

from ansible.module_utils.basic import to_text
from ansible.errors import AnsibleConnectionFailure
from ansible.plugins.httpapi import HttpApiBase
from ansible.module_utils.connection import ConnectionError


BASE_HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
}


class HttpApi(HttpApiBase):
    zbx_api_version = None

    def set_become(self, become_context):
        """As this is an http rpc call there is no elevation available
        """
        pass

    def update_auth(self, response, response_text):
        return None

    def login(self, username, password):
        payload = self.payload_builder("user.login", username=username, password=password)
        code, response = self.send_request(data=payload)

        if code == 200 and response != '':
            self.connection._auth = response

    def logout(self):
        payload = self.payload_builder("user.logout", self.connection._auth)
        self.send_request(data=payload)

    def handle_httperror(self, exc):
        """Overridable method for dealing with HTTP codes.
        This method will attempt to handle known cases of HTTP status codes.
        If your API uses status codes to convey information in a regular way,
        you can override this method to handle it appropriately.
        :returns:
            * True if the code has been handled in a way that the request
            may be resent without changes.
            * False if the error cannot be handled or recovered from by the
            plugin. This will result in the HTTPError being raised as an
            exception for the caller to deal with as appropriate (most likely
            by failing).
            * Any other value returned is taken as a valid response from the
            server without making another request. In many cases, this can just
            be the original exception.
            """
        if exc.code == 401:
            if self.connection._auth:
                # Stored auth appears to be invalid, clear and retry
                self.connection._auth = None
                self.login(self.connection.get_option('remote_user'), self.connection.get_option('password'))
                return True

            # Unauthorized and there's no token. Return an error
            return False

        return exc

    def api_version(self):
        if not self.zbx_api_version:
            if not hasattr(self.connection, 'zbx_api_version'):
                code, version = self.send_request(data=self.payload_builder('apiinfo.version'))
                if code == 200 and version != '':
                    self.connection.zbx_api_version = version
            self.zbx_api_version = self.connection.zbx_api_version
        return self.zbx_api_version

    def send_request(self, data=None, request_method="POST", path="/api_jsonrpc.php"):
        if not data:
            data = {}

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
        if auth_:
            req['auth'] = auth_
        req['params'] = (kwargs)

        return req
