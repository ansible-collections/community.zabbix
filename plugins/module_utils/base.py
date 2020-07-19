#!/usr/bin/env python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible_collections.community.zabbix.plugins.module_utils.wrappers import ZapiWrapper


class ZabbixBase(object):
    """
    The base class for deriving off module classes
    """
    def __init__(self, module, zbx=None, zapi_wrapper=None):
        self._module = module

        if zapi_wrapper is None:
            self._zapi_wrapper = ZapiWrapper(module, zbx)
        else:
            self._zapi_wrapper = zapi_wrapper

        # include some backward compat properties for now
        self._zapi = self._zapi_wrapper._zapi
        self._zbx_api_version = self._zapi_wrapper._zbx_api_version
