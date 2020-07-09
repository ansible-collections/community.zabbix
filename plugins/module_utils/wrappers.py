#!/usr/bin/env python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import atexit
import traceback

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from distutils.version import LooseVersion

try:
    from zabbix_api import ZabbixAPI
    HAS_ZABBIX_API = True
except ImportError:
    ZBX_IMP_ERR = traceback.format_exc()
    HAS_ZABBIX_API = False


class ZapiWrapper(object):
    """
    A simple wrapper over the Zabbix API
    """
    def __init__(self, module, zbx=None):
        self._module = module

        if not HAS_ZABBIX_API:
            module.fail_json(msg=missing_required_lib('zabbix-api', url='https://pypi.org/project/zabbix-api/'), exception=ZBX_IMP_ERR)

        # check if zbx is already instantiated or not
        if zbx is not None and isinstance(zbx, ZabbixAPI):
            self._zapi = zbx
        else:
            credentials = module.params.get['zabbix_credentials']
            if not credentials:
                credentials = {}
            credentials['server_url'] = module.params['server_url']
            credentials['http_login_user'] = module.params['http_login_user']
            credentials['http_login_password'] = module.params['http_login_password']
            credentials['validate_certs'] = module.params['validate_certs']
            credentials['timeout'] = module.params['timeout']
            self._zapi = ZabbixAPI(server_url, timeout=credentials['timeout'],
                                   user=credentials['http_login_user'], passwd=credentials['http_login_password'],
                                   validate_certs=credentials['validate_certs'])

        self.login(credentials)

        self._zbx_api_version = self._zapi.api_version()[:5]

    def login(self, credentials = {}):
        # check if api already logged in
        if not self._zapi.auth != '':
            try:
                credentials['login_user'] = self._module.params['login_user']
                credentials['login_password'] = self._module.params['login_password']
                self._zapi.login(credentials['login_user'], credentials['login_password'])
                atexit.register(self._zapi.logout)
            except Exception as e:
                self._module.fail_json(msg="Failed to connect to Zabbix server: %s" % e)
