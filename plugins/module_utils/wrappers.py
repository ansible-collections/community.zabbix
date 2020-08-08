#!/usr/bin/env python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import atexit
import traceback

from ansible.module_utils.basic import missing_required_lib

try:
    from zabbix_api import ZabbixAPI, Already_Exists, ZabbixAPIException

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
            server_url = module.params['server_url']
            http_login_user = module.params['http_login_user']
            http_login_password = module.params['http_login_password']
            validate_certs = module.params['validate_certs']
            timeout = module.params['timeout']
            self._zapi = ZabbixAPI(server_url, timeout=timeout, user=http_login_user, passwd=http_login_password,
                                   validate_certs=validate_certs)

        self.login()

        self._zbx_api_version = self._zapi.api_version()[:5]

    def login(self):
        # check if api already logged in
        if not self._zapi.auth != '':
            try:
                login_user = self._module.params['login_user']
                login_password = self._module.params['login_password']
                self._zapi.login(login_user, login_password)
                atexit.register(self._zapi.logout)
            except Exception as e:
                self._module.fail_json(msg="Failed to connect to Zabbix server: %s" % e)


class ScreenItem(object):
    @staticmethod
    def create(zapi_wrapper, data, ignoreExists=False):
        try:
            zapi_wrapper._zapi.screenitem.create(data)
        except Already_Exists as ex:
            if not ignoreExists:
                raise ex

    @staticmethod
    def delete(zapi_wrapper, id_list=None):
        try:
            if id_list is None:
                id_list = []
            zapi_wrapper._zapi.screenitem.delete(id_list)
        except ZabbixAPIException as ex:
            raise ex
