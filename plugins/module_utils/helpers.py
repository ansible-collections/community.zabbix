#!/usr/bin/env python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from distutils.version import LooseVersion


def zabbix_common_argument_spec():
    """
    Return a dictionary with connection options.
    The options are commonly used by most of Zabbix modules.
    """
    return dict(
        server_url=dict(type='str', required=True, aliases=['url']),
        login_user=dict(type='str', required=True),
        login_password=dict(type='str', required=True, no_log=True),
        http_login_user=dict(type='str', required=False, default=None),
        http_login_password=dict(type='str', required=False, default=None, no_log=True),
        timeout=dict(type='int', default=10),
        validate_certs=dict(type='bool', required=False, default=True),
    )


def helper_cleanup_data(obj):
    """
    Removes the None values from the object and returns the object
    Args:
        obj: object to cleanup

    Returns:
       object: cleaned object
    """
    if isinstance(obj, (list, tuple, set)):
        return type(obj)(helper_cleanup_data(x) for x in obj if x is not None)
    elif isinstance(obj, dict):
        return type(obj)((helper_cleanup_data(k), helper_cleanup_data(v))
                         for k, v in obj.items() if k is not None and v is not None)
    else:
        return obj


def helper_to_numeric_value(strs, value):
    """Converts string values to integers

    Parameters:
        value: string value

    Returns:
        int: converted integer
    """
    strs = [s.lower() if isinstance(s, str) else s for s in strs]
    value = value.lower()
    tmp_dict = dict(zip(strs, list(range(len(strs)))))
    return tmp_dict[value]


def helper_convert_unicode_to_str(data):
    """Converts unicode objects to strings in dictionary

    Parameters:
        data: unicode object

    Returns:
        dict: strings in dictionary
    """
    if isinstance(data, dict):
        return dict(map(helper_convert_unicode_to_str, data.items()))
    elif isinstance(data, (list, tuple, set)):
        return type(data)(map(helper_convert_unicode_to_str, data))
    elif data is None:
        return data
    else:
        return str(data)
