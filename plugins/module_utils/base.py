#!/usr/bin/env python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible_collections.community.zabbix.plugins.module_utils.api_request import ZabbixApiRequest


class ZabbixBase(object):
    """
    The base class for deriving off module classes
    """
    def __init__(self, module, zbx=None, zapi_wrapper=None):
        self._module = module
        self._zapi = ZabbixApiRequest(module)
        self._zbx_api_version = self._zapi.api_version()
