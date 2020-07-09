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


class ZabbixCredentials(object):
    """
    Wraps around the needed connection parameters for api
    """

    server_url = None
    http_login_user = None
    http_login_password = None
    login_user = None
    login_password = None
    timeout = 10
    validate_certs = True

    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

    def update_from_ansible_module(self, m):
        """
        :param m: ansible module
        :return:
        """
        if m.params.get('zabbix_credentials'):
            for k, v in m.params['zabbix_credentials'].items():
                if hasattr(self, k):
                    setattr(self, k, v)
        if m.params['server_url']:
            self.server_url = m.params['server_url']
        if m.params['http_login_user']:
            self.http_login_user = m.params['http_login_user']
        if m.params['http_login_password']:
            self.http_login_password = m.params['http_login_password']
        if m.params['login_user']:
            self.login_user = m.params['login_user']
        if m.params['login_password']:
            self.login_password = m.params['login_password']
        if m.params['timeout']:
            self.timeout = m.params['timeout']
        if m.params['validate_certs']:
            self.validate_certs = m.params['validate_certs']

    def __str__(self):
        return 'connection %s user %s (%s)' % (self.server_url, self.login_user, self.http_login_user)


class ZapiWrapper(object):
    """
    A simple wrapper over the Zabbix API
    """

    _credentials = ZabbixCredentials()

    def __init__(self, module, zbx=None):
        self._module = module

        if not HAS_ZABBIX_API:
            module.fail_json(msg=missing_required_lib('zabbix-api', url='https://pypi.org/project/zabbix-api/'), exception=ZBX_IMP_ERR)

        # check if zbx is already instantiated or not
        if zbx is not None and isinstance(zbx, ZabbixAPI):
            self._zapi = zbx
        else:
            self._credentials.update_from_ansible_module(self._module)
            self._zapi = ZabbixAPI(self._credentials.server_url, timeout=self._credentials.timeout,
                                   user=self._credentials.http_login_user, passwd=self._credentials.http_login_password,
                                   validate_certs=self._credentials.validate_certs)

        self.login()

        self._zbx_api_version = self._zapi.api_version()[:5]

    def login(self):
        # check if api already logged in
        if not self._zapi.auth != '':
            try:
                self._credentials.update_from_ansible_module(self._module)
                self._zapi.login(self._credentials.login_user, self._credentials.login_password)
                atexit.register(self._zapi.logout)
            except Exception as e:
                self._module.fail_json(msg="Failed to connect to Zabbix server: %s" % e)
