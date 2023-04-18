# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Ansible, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


class ModuleDocFragment(object):

    # Standard documentation fragment
    DOCUMENTATION = r"""
options:
    http_login_user:
        description:
            - Basic Auth login
        type: str
        required: false
    http_login_password:
        description:
            - Basic Auth password
        type: str
        required: false
    """
