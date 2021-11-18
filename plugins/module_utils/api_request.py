# -*- coding: utf-8 -*-

# (c) 2021, Markus Fischbacher (fischbacher.markus@gmail.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# Quick Link to Zabbix API docs: https://www.zabbix.com/documentation/current/manual/api


from __future__ import absolute_import, division, print_function

__metaclass__ = type

from uuid import uuid4

from ansible.module_utils.urls import CertificateError
from ansible.module_utils.six.moves.urllib.parse import urlencode
from ansible.module_utils.connection import ConnectionError, request_builder
from ansible.module_utils.connection import Connection
from ansible.module_utils._text import to_text


class ZabbixApiRequest(object):
    def __init__(self, module, headers=None, keymap=None):
        self.module = module
        self.connection = Connection(self.module._socket_path)

    def _httpapi_error_handle(self, method, payload=None):

        try:
            code, response = self.connection.send_request(payload=payload)
        except ConnectionError as e:
            self.module.fail_json(msg="connection error occurred: {0}".format(e))
        except CertificateError as e:
            self.module.fail_json(msg="certificate error occurred: {0}".format(e))
        except ValueError as e:
            self.module.fail_json(msg="certificate not found: {0}".format(e))

        if code == 404:
            if to_text(u"Object not found") in to_text(response) or to_text(
                u"Could not find object"
            ) in to_text(response):
                return {}

        if not (code >= 200 and code < 300):
            self.module.fail_json(
                msg="Zabbix httpapi returned error {0} with message {1}".format(
                    code, response
                )
            )

        return response

    def post(self, **kwargs):
        return self._httpapi_error_handle("POST", **kwargs)

    def get_api_version(self):
      payload = self.payload_builder("apiinfo.version")
      response = self.post(payload=payload)
      return response

    @staticmethod
    def payload_builder(method_, **kwargs):
      reqid = str(uuid4())
      req = {'jsonrpc': '2.0', 'method': method_, 'id': reqid}
      req['params'] = (kwargs)

      return req
