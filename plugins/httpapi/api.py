# (c) 2021, Markus Fischbacher (fischbacher.markus@gmail.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# Quick Link to Zabbix API docs: https://www.zabbix.com/documentation/current/manual/api

from __future__ import absolute_import, division, print_function

from ansible.plugins import AnsiblePlugin

__metaclass__ = type

DOCUMENTATION = """
---
author: fischbacher.markus@gmail.com
httpapi : zabbix
short_description: HttpApi Plugin for Zabbix
description:
  - This HttpApi plugin provides methods to connect to Zabbix over their HTTP(S)-based api.
version_added: "1.0"
options:
  zabbix_token:
    type: str
    description:
      - Specifies the api token path of the FTD device
    vars:
      - name: ansible_httpapi_zabbix_token
"""

import json

from ansible.module_utils.basic import to_text
from ansible.errors import AnsibleAction, AnsibleConnectionFailure
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.plugins.httpapi import HttpApiBase
from ansible.module_utils.connection import ConnectionError


BASE_HEADERS = {"Content-Type": "application/json"}


import debugpy

class HttpApi(HttpApiBase):

    def set_become(self, become_context):
      """As this is an http rpc call there is no elevation available
      """
      pass

    def update_auth(self, response, response_text):
      return None

    def login(self, username, password):
      self.connection._auth = {}

    # def logout(self):
    #   logout_path = '/my/logout/path'
    #   self.send_request(None, path=logout_path)

    #   # Clean up tokens
    #   self.connection._auth = None

    def send_request(self, request_method="POST", path="/api_jsonrpc.php", payload=None):
        payload = json.dumps(payload) if payload else '{}'

        import debugpy
        debugpy.listen(5678)
        print("Waiting for debugger attach")
        debugpy.wait_for_client()
        debugpy.breakpoint()
        print('break on this line')


        try:
            self._display_request(request_method, path)
            response, response_data = self.connection.send(
                path,
                payload,
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
