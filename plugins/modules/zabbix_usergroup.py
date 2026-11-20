#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Tobias Birkefeld (@tcraxs) <t@craxs.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: zabbix_usergroup
short_description: Create/delete/update Zabbix user groups
description:
   - Create user groups if they do not exist.
   - Delete existing user groups if they exist and are empty.
   - Update existing user groups.
author:
    - "Tobias Birkefeld (@tcraxs)"
requirements:
    - "python >= 3.9"
options:
    name:
        description:
            - Name of the user group to create, update or delete.
        required: true
        type: str
        aliases: [ "user_group" ]
    gui_access:
        description:
            - Frontend authentication method of the users in the group.
            - "Possible values:"
            - default -  use the system default authentication method;
            - internal - use internal authentication;
            - LDAP - use LDAP authentication;
            - disable - disable access to the frontend.
        required: false
        type: str
        default: "default"
        choices: [ "default", "internal", "LDAP", "disable"]
    debug_mode:
        description:
            - Whether debug mode is enabled or disabled.
        required: false
        type: str
        default: "disabled"
        choices: [ "disabled", "enabled" ]
    status:
        description:
            - Whether the user group is enabled or disabled.
        required: false
        type: str
        default: "enabled"
        choices: [ "enabled", "disabled" ]
    rights:
        description:
            - Permissions to assign to the group
            - For <= Zabbix 6.0
        required: false
        type: list
        elements: dict
        suboptions:
            host_group:
                description:
                    - Name of the host group to add permission to.
                required: true
                type: str
            permission:
                description:
                    - Access level to the host group.
                required: true
                type: str
                choices: [ "denied", "read-only", "read-write" ]
    hostgroup_rights:
        description:
            - Host group permissions to assign to the user group
            - For => Zabbix 7.0
        required: false
        type: list
        elements: dict
        suboptions:
            host_group:
                description:
                    - Name of the host group to add permission to.
                required: true
                type: str
            permission:
                description:
                    - Access level to the host group.
                required: true
                type: str
                choices: [ "denied", "read-only", "read-write" ]
    templategroup_rights:
        description:
            - Template group permissions to assign to the user group
            - For => Zabbix 7.0
        required: false
        type: list
        elements: dict
        suboptions:
            template_group:
                description:
                    - Name of the template group to add permission to.
                required: true
                type: str
            permission:
                description:
                    - Access level to the templategroup.
                required: true
                type: str
                choices: [ "denied", "read-only", "read-write" ]
    mfa_status:
        description:
            - Whether MFA is enabled or disabled for users in the group.
            - Supported by this module on Zabbix 8.0 and later. If omitted, the existing setting is preserved.
            - Global MFA must be configured and enabled in Zabbix for MFA to take effect.
            - Disabling MFA also resets the group's selected MFA method to the system default.
        type: str
        choices: [ "disabled", "enabled" ]
    mfa_method:
        description:
            - Name of an existing MFA method to use for the group.
            - Supported by this module on Zabbix 8.0 and later.
            - Requires O(mfa_status=enabled).
            - Set to an empty string to select the system default MFA method.
            - If omitted, the existing method is preserved.
        type: str
    proxy_mode:
        description:
            - Mode for access to proxies that are not included in proxy groups.
            - Use V(allow_list) to allow only O(proxies), or V(deny_list) to deny only O(proxies).
            - Supported from Zabbix 8.0. If omitted, the existing mode is preserved.
            - New user groups use V(allow_list) by default in Zabbix.
        type: str
        choices: [ "deny_list", "allow_list" ]
    proxies:
        description:
            - Names of proxies in the allow or deny list selected by O(proxy_mode).
            - Applies to proxies that are not included in proxy groups.
            - Supported from Zabbix 8.0. If omitted, the existing list is preserved.
            - Set to an empty list to remove all proxies from the list.
            - New user groups have an empty list by default in Zabbix.
        type: list
        elements: str
    proxy_group_mode:
        description:
            - Mode for access to proxy groups and their proxies.
            - Use V(allow_list) to allow only O(proxy_groups), or V(deny_list) to deny only O(proxy_groups).
            - Supported from Zabbix 8.0. If omitted, the existing mode is preserved.
            - New user groups use V(allow_list) by default in Zabbix.
        type: str
        choices: [ "deny_list", "allow_list" ]
    proxy_groups:
        description:
            - Names of proxy groups in the allow or deny list selected by O(proxy_group_mode).
            - Supported from Zabbix 8.0. If omitted, the existing list is preserved.
            - Set to an empty list to remove all proxy groups from the list.
            - New user groups have an empty list by default in Zabbix.
        type: list
        elements: str
    apm_filters:
        description:
            - APM-based permissions to assign to the user group using resource attributes.
            - Supported from Zabbix 8.0. If omitted, the existing filters are preserved.
            - Set to an empty list to remove all APM filters.
        type: list
        elements: dict
        suboptions:
            key:
                description:
                    - Non-empty APM resource attribute key.
                type: str
                required: true
            value:
                description:
                    - APM resource attribute value.
                type: str
                default: ""
            signal_type:
                description:
                    - APM signal category to which the permission applies.
                type: str
                choices: [ "all", "traces", "metrics", "logs" ]
                default: all
    tag_filters:
        description:
            - Tag based permissions to assign to the group
        required: false
        type: list
        elements: dict
        suboptions:
            host_group:
                description:
                    - Name of the host group to add permission to.
                required: true
                type: str
            tag:
                description:
                    - Tag name.
                required: false
                type: str
                default: ""
            value:
                description:
                    - Tag value.
                required: false
                type: str
                default: ""
    userdirectory:
        description:
            - Authentication user directory when gui_access set to LDAP or System default.
            - For => Zabbix 7.0
        required: false
        type: str
    state:
        description:
            - State of the user group.
            - On C(present), it will create if user group does not exist or update the user group if the associated data is different.
            - On C(absent) will remove a user group if it exists.
        required: false
        type: str
        default: "present"
        choices: [ "present", "absent" ]

extends_documentation_fragment:
- community.zabbix.zabbix
"""

EXAMPLES = r"""
# If you want to use Username and Password to be authenticated by Zabbix Server
- name: Set credentials to access Zabbix Server API
  ansible.builtin.set_fact:
    ansible_user: Admin
    ansible_httpapi_pass: zabbix

# If you want to use API token to be authenticated by Zabbix Server
# https://www.zabbix.com/documentation/current/en/manual/web_interface/frontend_sections/administration/general#api-tokens
- name: Set API token
  ansible.builtin.set_fact:
    ansible_zabbix_auth_key: 8ec0d52432c15c91fcafe9888500cf9a607f44091ab554dbee860f6b44fac895

# Base create user group example
- name: Create user group
    # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_usergroup:
    name: ACME
    userdirectory: LDAP infra 1
    state: present

# Base create user group with selected user directory for LDAP authentication
- name: Create user group
    # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_usergroup:
    name: ACME
    userdirectory: LDAP infra 1
    state: present

# Base create user group with disabled gui access
- name: Create user group with disabled gui access
    # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_usergroup:
    name: ACME
    gui_access: disable

# Base create user group with permissions for Zabbix <= 6.0
- name: Create user group with permissions
    # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_usergroup:
    name: ACME
    rights:
        - host_group: Webserver
          permission: read-write
        - host_group: Databaseserver
          permission: read-only
    state: present

# Base create user group with permissions for Zabbix => 7.0
- name: Create user group with permissions
    # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_usergroup:
    name: ACME
    hostgroup_rights:
        - host_group: Webserver
          permission: read-write
        - host_group: Databaseserver
          permission: read-only
    templategroup_rights:
        - template_group: Linux Templates
          permission: read-write
        - template_group: Templates
          permission: read-only
    state: present

# Base create user group with tag permissions
- name: Create user group with tag permissions
    # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_usergroup:
    name: ACME
    tag_filters:
        - host_group: Webserver
          tag: Application
          value: Java
        - host_group: Discovered hosts
          tag: Service
          value: JIRA
    state: present

# Group MFA settings for Zabbix >= 8.0
- name: Enable MFA with an existing method
  community.zabbix.zabbix_usergroup:
    name: ACME
    mfa_status: enabled
    mfa_method: Corporate TOTP

- name: Use the system default MFA method
  community.zabbix.zabbix_usergroup:
    name: ACME
    mfa_status: enabled
    mfa_method: ""

- name: Disable MFA for the group
  community.zabbix.zabbix_usergroup:
    name: ACME
    mfa_status: disabled

# Proxy permissions for Zabbix >= 8.0
- name: Allow access to selected proxies and proxy groups
  community.zabbix.zabbix_usergroup:
    name: ACME
    proxy_mode: allow_list
    proxies:
      - Branch proxy
    proxy_group_mode: allow_list
    proxy_groups:
      - Production proxies

- name: Deny access to selected proxies
  community.zabbix.zabbix_usergroup:
    name: ACME
    proxy_mode: deny_list
    proxies:
      - Restricted proxy

- name: Clear the proxy and proxy group lists
  community.zabbix.zabbix_usergroup:
    name: ACME
    proxies: []
    proxy_groups: []

# APM-based permissions for Zabbix >= 8.0
- name: Set APM resource attribute permissions
  community.zabbix.zabbix_usergroup:
    name: ACME
    apm_filters:
      - key: service.namespace
        value: production
        signal_type: all
      - key: service.name
        value: checkout
        signal_type: traces

- name: Clear APM permissions
  community.zabbix.zabbix_usergroup:
    name: ACME
    apm_filters: []

# Base delete user groups example
- name: Delete user groups
    # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: "zabbixeu"  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_usergroup:
    name: ACME
    state: absent
"""

RETURN = r"""
state:
  description: User group state at the end of execution.
  returned: on success
  type: str
  sample: "present"
usergroup:
  description: User group name.
  returned: on success
  type: str
  sample: "ACME"
usrgrpid:
    description: User group id, if created, changed or deleted.
    returned: on success
    type: str
    sample: "42"
msg:
    description: The result of the operation
    returned: always
    type: str
    sample: "User group created: ACME, ID: 42"
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
from ansible.module_utils.compat.version import LooseVersion
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class Rights(ZabbixBase):
    """
    Restructure the user defined rights to fit the Zabbix API requirements
    """

    def get_hostgroup_by_hostgroup_name(self, name):
        """Get host group by host group name.

        Parameters:
            name: Name of the host group.

        Returns:
            host group matching host group name.
        """
        try:
            _hostgroup = self._zapi.hostgroup.get(
                {"output": "extend", "filter": {"name": [name]}}
            )
            if len(_hostgroup) < 1:
                self._module.fail_json(msg="Host group not found: %s" % name)
            else:
                return _hostgroup[0]
        except Exception as e:
            self._module.fail_json(msg="Failed to get host group '%s': %s" % (name, e))

    def construct_the_data(self, _rights):
        """Construct the user defined rights to fit the Zabbix API requirements

        Parameters:
            _rights: rights to construct

        Returns:
            dict: user defined rights
        """
        if _rights is None:
            return []
        constructed_data = []
        for right in _rights:
            constructed_right = {
                "id": self.get_hostgroup_by_hostgroup_name(right.get("host_group"))[
                    "groupid"
                ],
                "permission": zabbix_utils.helper_to_numeric_value(
                    ["denied", None, "read-only", "read-write"], right.get("permission")
                ),
            }
            constructed_data.append(constructed_right)
        return zabbix_utils.helper_cleanup_data(constructed_data)


class HostgroupRights(ZabbixBase):
    """
    Restructure the user defined host group rights to fit the Zabbix API requirements
    """

    def get_hostgroup_by_hostgroup_name(self, name):
        """Get host group by host group name.

        Parameters:
            name: Name of the host group.

        Returns:
            host group matching host group name.
        """
        try:
            _hostgroup = self._zapi.hostgroup.get({
                "output": "extend",
                "filter": {"name": [name]}
            })
            if len(_hostgroup) < 1:
                self._module.fail_json(msg="Host group not found: %s" % name)
            else:
                return _hostgroup[0]
        except Exception as e:
            self._module.fail_json(msg="Failed to get host group '%s': %s" % (name, e))

    def construct_the_data(self, _rights):
        """Construct the user defined host group rights to fit the Zabbix API requirements

        Parameters:
            _rights: rights to construct

        Returns:
            dict: user defined rights
        """
        if _rights is None:
            return []
        constructed_data = []
        for right in _rights:
            constructed_right = {
                "id": self.get_hostgroup_by_hostgroup_name(right.get("host_group"))["groupid"],
                "permission": zabbix_utils.helper_to_numeric_value([
                    "denied",
                    None,
                    "read-only",
                    "read-write"], right.get("permission")
                )
            }
            constructed_data.append(constructed_right)
        return zabbix_utils.helper_cleanup_data(constructed_data)


class TemplategroupRights(ZabbixBase):
    """
    Restructure the user defined template group rights to fit the Zabbix API requirements
    """

    def get_templategroup_by_templategroup_name(self, name):
        """Get template group by template group name.

        Parameters:
            name: Name of the template group.

        Returns:
            template group matching template group name.
        """
        try:
            _templategroup = self._zapi.templategroup.get({
                "output": "extend",
                "filter": {"name": [name]}
            })
            if len(_templategroup) < 1:
                self._module.fail_json(msg="Template group not found: %s" % name)
            else:
                return _templategroup[0]
        except Exception as e:
            self._module.fail_json(msg="Failed to get template group '%s': %s" % (name, e))

    def construct_the_data(self, _rights):
        """Construct the user defined template rights to fit the Zabbix API requirements

        Parameters:
            _rights: rights to construct

        Returns:
            dict: user defined rights
        """
        if _rights is None:
            return []
        constructed_data = []
        for right in _rights:
            constructed_right = {
                "id": self.get_templategroup_by_templategroup_name(right.get("template_group"))["groupid"],
                "permission": zabbix_utils.helper_to_numeric_value([
                    "denied",
                    None,
                    "read-only",
                    "read-write"], right.get("permission")
                )
            }
            constructed_data.append(constructed_right)
        return zabbix_utils.helper_cleanup_data(constructed_data)


class TagFilters(Rights):
    """
    Restructure the user defined tag_filters to fit the Zabbix API requirements
    """

    def construct_the_data(self, _tag_filters):
        """Construct the user defined tag filters to fit the Zabbix API requirements

        Parameters:
            _tag_filters: tag filters to construct

        Returns:
            dict: user defined tag filters
        """
        if _tag_filters is None:
            return []
        constructed_data = []
        for tag_filter in _tag_filters:
            constructed_tag_filter = {
                "groupid": self.get_hostgroup_by_hostgroup_name(
                    tag_filter.get("host_group")
                )["groupid"],
                "tag": tag_filter.get("tag"),
                "value": tag_filter.get("value"),
            }
            constructed_data.append(constructed_tag_filter)
        return zabbix_utils.helper_cleanup_data(constructed_data)


class UserGroup(ZabbixBase):
    def _get_mfa_id(self, name):
        try:
            methods = self._zapi.mfa.get({"output": ["mfaid", "name"], "search": {"name": name}})
        except Exception as e:
            self._module.fail_json(msg="Failed to get MFA method '%s': %s" % (name, e))
        for method in methods:
            if method["name"] == name:
                return method["mfaid"]
        self._module.fail_json(msg="MFA method not found: %s" % name)

    def _construct_apm_filters(self, filters):
        signal_types = {"all": -1, "traces": 0, "metrics": 1, "logs": 2}
        constructed_filters = []
        seen = set()
        for apm_filter in filters:
            if not apm_filter["key"]:
                self._module.fail_json(msg="apm_filters key must not be empty")
            identity = (apm_filter["key"], apm_filter["value"], apm_filter["signal_type"])
            if identity in seen:
                self._module.fail_json(msg="apm_filters must not contain duplicate key, value and signal_type combinations")
            seen.add(identity)
            constructed_filters.append({
                "key": apm_filter["key"],
                "value": apm_filter["value"],
                "signal_type": signal_types[apm_filter["signal_type"]],
            })
        return constructed_filters

    def _construct_proxy_permissions(self, names, proxy_groups=False):
        if proxy_groups:
            api = self._zapi.proxygroup
            id_field = "proxy_groupid"
            label = "Proxy group"
        else:
            api = self._zapi.proxy
            id_field = "proxyid"
            label = "Proxy"

        permissions = []
        for name in dict.fromkeys(names):
            try:
                objects = api.get({"output": [id_field], "filter": {"name": [name]}})
            except Exception as e:
                self._module.fail_json(msg="Failed to get %s '%s': %s" % (label.lower(), name, e))
            if not objects:
                self._module.fail_json(msg="%s not found: %s" % (label, name))
            permissions.append({id_field: objects[0][id_field]})
        return permissions

    def _construct_parameters(self, **kwargs):
        """Construct parameters of UserGroup object

        Parameters:
            **kwargs: Arbitrary keyword parameters.

        Returns:
            dict: dictionary of specified parameters
        """
        _params = {
            "name": kwargs["name"],
            "gui_access": zabbix_utils.helper_to_numeric_value(
                ["default", "internal", "LDAP", "disable"], kwargs["gui_access"]
            ),
            "debug_mode": zabbix_utils.helper_to_numeric_value(
                ["disabled", "enabled"], kwargs["debug_mode"]
            ),
            "users_status": zabbix_utils.helper_to_numeric_value(
                ["enabled", "disabled"], kwargs["status"]
            ),
            "tag_filters": kwargs["tag_filters"],
        }
        if LooseVersion(self._zbx_api_version) < LooseVersion("7.0"):
            _params["rights"] = kwargs["rights"]
        else:
            _params["hostgroup_rights"] = kwargs["hostgroup_rights"]
            _params["templategroup_rights"] = kwargs["templategroup_rights"]

            if kwargs["userdirectory"]:
                try:
                    _userdir = self._zapi.userdirectory.get(
                        {
                            "output": "extend",
                            "search": {"name": [kwargs["userdirectory"]]},
                        }
                    )
                except Exception as e:
                    self._module.fail_json(
                        msg="Failed to get user directory '%s': %s"
                        % (kwargs["userdirectory"], e)
                    )
                if len(_userdir) == 0:
                    self._module.fail_json(
                        msg="User directory '%s' not found" % kwargs["userdirectory"]
                    )
                _params["userdirectoryid"] = _userdir[0]["userdirectoryid"]

        if LooseVersion(self._zbx_api_version) >= LooseVersion("8.0"):
            if kwargs.get("mfa_status") is not None:
                _params["mfa_status"] = zabbix_utils.helper_to_numeric_value(
                    ["disabled", "enabled"], kwargs["mfa_status"]
                )
                if kwargs["mfa_status"] == "disabled":
                    _params["mfaid"] = "0"
            if kwargs.get("mfa_method") is not None:
                _params["mfaid"] = self._get_mfa_id(kwargs["mfa_method"]) if kwargs["mfa_method"] else "0"
            for mode in ("proxy_mode", "proxy_group_mode"):
                if kwargs.get(mode) is not None:
                    _params[mode] = zabbix_utils.helper_to_numeric_value(
                        ["deny_list", "allow_list"], kwargs[mode]
                    )
            if kwargs.get("proxies") is not None:
                _params["proxies"] = self._construct_proxy_permissions(kwargs["proxies"])
            if kwargs.get("proxy_groups") is not None:
                _params["proxy_groups"] = self._construct_proxy_permissions(kwargs["proxy_groups"], proxy_groups=True)
            if kwargs.get("apm_filters") is not None:
                _params["apm_filters"] = self._construct_apm_filters(kwargs["apm_filters"])

        return _params

    def check_if_usergroup_exists(self, name):
        """Check if user group exists.

        Parameters:
            name: Name of the user group.

        Returns:
            The return value. True for success, False otherwise.
        """
        try:
            _usergroup = self._zapi.usergroup.get(
                {"output": "extend", "filter": {"name": [name]}}
            )
            if len(_usergroup) > 0:
                return _usergroup
        except Exception as e:
            self._module.fail_json(
                msg="Failed to check if user group '%s' exists: %s" % (name, e)
            )

    def get_usergroup_by_usergroup_name(self, name):
        """Get user group by user group name.

        Parameters:
            name: Name of the user group.

        Returns:
            User group matching user group name.
        """
        try:
            if LooseVersion(self._zbx_api_version) < LooseVersion("7.0"):
                _usergroup = self._zapi.usergroup.get(
                    {
                        "output": "extend",
                        "selectTagFilters": "extend",
                        "selectRights": "extend",
                        "filter": {"name": [name]},
                    }
                )
            else:
                parameters = {
                    "output": "extend",
                    "selectTagFilters": "extend",
                    "selectHostGroupRights": "extend",
                    "selectTemplateGroupRights": "extend",
                    "filter": {"name": [name]},
                }
                if LooseVersion(self._zbx_api_version) >= LooseVersion("8.0"):
                    if self._module.params["proxies"] is not None:
                        parameters["selectProxies"] = ["proxyid"]
                    if self._module.params["proxy_groups"] is not None:
                        parameters["selectProxyGroups"] = ["proxy_groupid"]
                    if self._module.params["apm_filters"] is not None:
                        parameters["selectApmFilters"] = ["key", "value", "signal_type"]
                _usergroup = self._zapi.usergroup.get(parameters)

            if len(_usergroup) < 1:
                self._module.fail_json(msg="User group not found: %s" % name)
            else:
                return _usergroup[0]
        except Exception as e:
            self._module.fail_json(msg="Failed to get user group '%s': %s" % (name, e))

    def check_difference(self, **kwargs):
        """Check difference between user group and user specified parameters.

        Parameters:
            **kwargs: Arbitrary keyword parameters.

        Returns:
            dict: dictionary of differences
        """
        existing_usergroup = zabbix_utils.helper_convert_unicode_to_str(
            self.get_usergroup_by_usergroup_name(kwargs["name"])
        )
        parameters = zabbix_utils.helper_convert_unicode_to_str(
            self._construct_parameters(**kwargs)
        )
        change_parameters = {}
        _diff = zabbix_utils.helper_compare_dictionaries(
            parameters, existing_usergroup, change_parameters
        )
        return _diff

    def update(self, **kwargs):
        """Update user group.

        Parameters:
            **kwargs: Arbitrary keyword parameters.

        Returns:
            usergroup: updated user group
        """
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            return self._zapi.usergroup.update(kwargs)
        except Exception as e:
            self._module.fail_json(
                msg="Failed to update user group '%s': %s" % (kwargs["usrgrpid"], e)
            )

    def add(self, **kwargs):
        """Add user group.

        Parameters:
            **kwargs: Arbitrary keyword parameters.

        Returns:
            usergroup: added user group
        """
        try:
            parameters = self._construct_parameters(**kwargs)
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            usergroup = self._zapi.usergroup.create(parameters)
            return usergroup["usrgrpids"][0]
        except Exception as e:
            self._module.fail_json(
                msg="Failed to create user group '%s': %s" % (kwargs["name"], e)
            )

    def delete(self, usrgrpid):
        """Delete user group.

        Parameters:
            usrgrpid: User group id.

        Returns:
            usergroup: deleted user group
        """
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            else:
                return self._zapi.usergroup.delete([usrgrpid])
        except Exception as e:
            self._module.fail_json(
                msg="Failed to delete user group '%s': %s" % (usrgrpid, e)
            )


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(
        name=dict(type="str", required=True, aliases=["user_group"]),
        gui_access=dict(
            type="str",
            required=False,
            default="default",
            choices=["default", "internal", "LDAP", "disable"],
        ),
        debug_mode=dict(
            type="str",
            required=False,
            default="disabled",
            choices=["disabled", "enabled"],
        ),
        status=dict(
            type="str",
            required=False,
            default="enabled",
            choices=["enabled", "disabled"],
        ),
        rights=dict(
            type="list",
            elements="dict",
            required=False,
            options=dict(
                host_group=dict(type="str", required=True),
                permission=dict(
                    type="str",
                    required=True,
                    choices=["denied", "read-only", "read-write"],
                ),
            ),
        ),
        hostgroup_rights=dict(
            type="list",
            elements="dict",
            required=False,
            options=dict(
                host_group=dict(type="str", required=True),
                permission=dict(
                    type="str",
                    required=True,
                    choices=["denied", "read-only", "read-write"],
                ),
            ),
        ),
        templategroup_rights=dict(
            type="list",
            elements="dict",
            required=False,
            options=dict(
                template_group=dict(type="str", required=True),
                permission=dict(
                    type="str",
                    required=True,
                    choices=["denied", "read-only", "read-write"],
                ),
            ),
        ),
        mfa_status=dict(type="str", choices=["disabled", "enabled"]),
        mfa_method=dict(type="str"),
        proxy_mode=dict(type="str", choices=["deny_list", "allow_list"]),
        proxies=dict(type="list", elements="str"),
        proxy_group_mode=dict(type="str", choices=["deny_list", "allow_list"]),
        proxy_groups=dict(type="list", elements="str"),
        apm_filters=dict(
            type="list",
            elements="dict",
            options=dict(
                key=dict(type="str", required=True, no_log=False),
                value=dict(type="str", default=""),
                signal_type=dict(type="str", default="all", choices=["all", "traces", "metrics", "logs"]),
            ),
        ),
        tag_filters=dict(
            type="list",
            elements="dict",
            required=False,
            options=dict(
                host_group=dict(type="str", required=True),
                tag=dict(type="str", default=""),
                value=dict(type="str", default=""),
            ),
        ),
        userdirectory=dict(type="str", required=False),
        state=dict(type="str", default="present", choices=["present", "absent"]),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    name = module.params["name"]
    gui_access = module.params["gui_access"]
    debug_mode = module.params["debug_mode"]
    status = module.params["status"]
    rights = module.params["rights"]
    hostgroup_rights = module.params["hostgroup_rights"]
    templategroup_rights = module.params["templategroup_rights"]
    mfa_status = module.params["mfa_status"]
    mfa_method = module.params["mfa_method"]
    proxy_mode = module.params["proxy_mode"]
    proxies = module.params["proxies"]
    proxy_group_mode = module.params["proxy_group_mode"]
    proxy_groups = module.params["proxy_groups"]
    apm_filters = module.params["apm_filters"]
    tag_filters = module.params["tag_filters"]
    userdirectory = module.params["userdirectory"]
    state = module.params["state"]

    userGroup = UserGroup(module)
    if LooseVersion(userGroup._zbx_api_version) < LooseVersion("8.0"):
        for option in ("proxy_mode", "proxies", "proxy_group_mode", "proxy_groups", "apm_filters", "mfa_status", "mfa_method"):
            if module.params[option] is not None:
                module.fail_json(msg="%s is supported from Zabbix 8.0" % option)
    if mfa_method is not None and mfa_status != "enabled":
        module.fail_json(msg="mfa_method requires mfa_status=enabled")
    zbx = userGroup._zapi
    if LooseVersion(userGroup._zbx_api_version) < LooseVersion("7.0"):
        rgts = Rights(module, zbx)
    else:
        hostgroup_rgts = HostgroupRights(module, zbx)
        templategroup_rgts = TemplategroupRights(module, zbx)
    tgflts = TagFilters(module, zbx)

    usergroup_exists = userGroup.check_if_usergroup_exists(name)

    if usergroup_exists:
        usrgrpid = userGroup.get_usergroup_by_usergroup_name(name)["usrgrpid"]
        if state == "absent":
            userGroup.delete(usrgrpid)
            module.exit_json(
                changed=True,
                state=state,
                usergroup=name,
                usrgrpid=usrgrpid,
                msg="User group deleted: %s, ID: %s" % (name, usrgrpid),
            )
        else:
            if LooseVersion(userGroup._zbx_api_version) < LooseVersion("7.0"):
                difference = userGroup.check_difference(
                    usrgrpid=usrgrpid,
                    name=name,
                    gui_access=gui_access,
                    debug_mode=debug_mode,
                    status=status,
                    rights=rgts.construct_the_data(rights),
                    tag_filters=tgflts.construct_the_data(tag_filters),
                )
            else:
                difference = userGroup.check_difference(
                    usrgrpid=usrgrpid,
                    name=name,
                    gui_access=gui_access,
                    debug_mode=debug_mode,
                    status=status,
                    hostgroup_rights=hostgroup_rgts.construct_the_data(
                        hostgroup_rights
                    ),
                    templategroup_rights=templategroup_rgts.construct_the_data(
                        templategroup_rights
                    ),
                    tag_filters=tgflts.construct_the_data(tag_filters),
                    userdirectory=userdirectory,
                    proxy_mode=proxy_mode,
                    proxies=proxies,
                    proxy_group_mode=proxy_group_mode,
                    proxy_groups=proxy_groups,
                    apm_filters=apm_filters,
                    mfa_status=mfa_status,
                    mfa_method=mfa_method,
                )
            if difference == {}:
                module.exit_json(
                    changed=False,
                    state=state,
                    usergroup=name,
                    usrgrpid=usrgrpid,
                    msg="User group is up to date: %s" % name,
                )
            else:
                userGroup.update(usrgrpid=usrgrpid, **difference)
                module.exit_json(
                    changed=True,
                    state=state,
                    usergroup=name,
                    usrgrpid=usrgrpid,
                    msg="User group updated: %s, ID: %s" % (name, usrgrpid),
                )
    else:
        if state == "absent":
            module.exit_json(
                changed=False,
                state=state,
                usergroup=name,
                msg="User group %s does not exists, nothing to delete" % name,
            )
        else:
            if LooseVersion(userGroup._zbx_api_version) < LooseVersion("7.0"):
                usrgrpid = userGroup.add(
                    name=name,
                    gui_access=gui_access,
                    debug_mode=debug_mode,
                    status=status,
                    rights=rgts.construct_the_data(rights),
                    tag_filters=tgflts.construct_the_data(tag_filters),
                )
            else:
                usrgrpid = userGroup.add(
                    name=name,
                    gui_access=gui_access,
                    debug_mode=debug_mode,
                    status=status,
                    hostgroup_rights=hostgroup_rgts.construct_the_data(
                        hostgroup_rights
                    ),
                    templategroup_rights=templategroup_rgts.construct_the_data(
                        templategroup_rights
                    ),
                    tag_filters=tgflts.construct_the_data(tag_filters),
                    userdirectory=userdirectory,
                    proxy_mode=proxy_mode,
                    proxies=proxies,
                    proxy_group_mode=proxy_group_mode,
                    proxy_groups=proxy_groups,
                    apm_filters=apm_filters,
                    mfa_status=mfa_status,
                    mfa_method=mfa_method,
                )
            module.exit_json(
                changed=True,
                state=state,
                usergroup=name,
                usrgrpid=usrgrpid,
                msg="User group created: %s, ID: %s" % (name, usrgrpid),
            )


if __name__ == "__main__":
    main()
