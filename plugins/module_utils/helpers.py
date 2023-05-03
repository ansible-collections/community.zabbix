#!/usr/bin/env python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function
__metaclass__ = type


def zabbix_common_argument_spec():
    """
    Return a dictionary with connection options.
    The options are commonly used by most of Zabbix modules.
    """
    return dict(
        http_login_user=dict(
            type='str',
            required=False,
            default=None
        ),
        http_login_password=dict(
            type='str',
            required=False,
            default=None,
            no_log=True
        )
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


def helper_to_numeric_value(elements, value):
    """Converts string values to integers

    Parameters:
        elements: list of elements to enumerate
        value: string value

    Returns:
        int: converted integer
    """
    if value is None:
        return None
    for index, element in enumerate(elements):
        if isinstance(element, str) and element.lower() == value.lower():
            return index
        if isinstance(element, list):
            for deep_element in element:
                if isinstance(deep_element, str) and deep_element.lower() == value.lower():
                    return index


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


def helper_compare_lists(l1, l2, diff_dict):
    """
    Compares l1 and l2 lists and adds the items that are different
    to the diff_dict dictionary.
    Used in recursion with helper_compare_dictionaries() function.

    Parameters:
        l1: first list to compare
        l2: second list to compare
        diff_dict: dictionary to store the difference

    Returns:
        dict: items that are different
    """
    if len(l1) != len(l2):
        diff_dict.append(l1)
        return diff_dict
    for i, item in enumerate(l1):
        if isinstance(item, dict):
            for item2 in l2:
                diff_dict2 = {}
                diff_dict2 = helper_compare_dictionaries(item, item2, diff_dict2)
                if len(diff_dict2) == 0:
                    break
            if len(diff_dict2) != 0:
                diff_dict.insert(i, item)
        else:
            if item != l2[i]:
                diff_dict.append(item)
    while {} in diff_dict:
        diff_dict.remove({})
    return diff_dict


def helper_compare_dictionaries(d1, d2, diff_dict):
    """
    Compares d1 and d2 dictionaries and adds the items that are different
    to the diff_dict dictionary.
    Used in recursion with helper_compare_lists() function.

    Parameters:
        d1: first dictionary to compare
        d2: second dictionary to compare
        diff_dict: dictionary to store the difference

    Returns:
        dict: items that are different
    """
    for k, v in d1.items():
        if k not in d2:
            diff_dict[k] = v
            continue
        if isinstance(v, dict):
            diff_dict[k] = {}
            helper_compare_dictionaries(v, d2[k], diff_dict[k])
            if diff_dict[k] == {}:
                del diff_dict[k]
            else:
                diff_dict[k] = v
        elif isinstance(v, list):
            diff_dict[k] = []
            helper_compare_lists(v, d2[k], diff_dict[k])
            if diff_dict[k] == []:
                del diff_dict[k]
            else:
                diff_dict[k] = v
        else:
            if v != d2[k]:
                diff_dict[k] = v
    return diff_dict


def helper_normalize_data(data, del_keys=None):
    """
    Delete None parameter or specified keys from data.

    Parameters:
        data: dictionary

    Returns:
        data: falsene parameter removed data
        del_keys: deleted keys
    """
    if del_keys is None:
        del_keys = []

    for key, value in data.items():
        if value is None:
            del_keys.append(key)

    for key in del_keys:
        if key in data.keys():
            del data[key]

    return data, del_keys
