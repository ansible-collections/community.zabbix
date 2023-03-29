#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Tobias Birkefeld (@tcraxs) <t@craxs.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
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
    - "python >= 2.6"
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
            - For => Zabbix 6.2
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
            - For => Zabbix 6.2
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
                default: ''
            value:
                description:
                    - Tag value.
                required: false
                type: str
                default: ''
    userdirectory:
        description:
            - Authentication user directory when gui_access set to LDAP or System default.
            - For => Zabbix 6.2
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
notes:
    - Only Zabbix >= 4.0 is supported.
extends_documentation_fragment:
- community.zabbix.zabbix
'''

EXAMPLES = r'''
# If you want to use Username and Password to be authenticated by Zabbix Server
- name: Set credentials to access Zabbix Server API
  set_fact:
    ansible_user: Admin
    ansible_httpapi_pass: zabbix

# If you want to use API token to be authenticated by Zabbix Server
# https://www.zabbix.com/documentation/current/en/manual/web_interface/frontend_sections/administration/general#api-tokens
- name: Set API token
  set_fact:
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
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_usergroup:
    name: ACME
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
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
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
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
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
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_usergroup:
    name: ACME
    rights:
        - host_group: Webserver
          permission: read-write
        - host_group: Databaseserver
          permission: read-only
    state: present

# Base create user group with permissions for Zabbix => 6.2
- name: Create user group with permissions
    # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
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
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
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

# Base delete user groups example
- name: Delete user groups
    # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_usergroup:
    name: ACME
    state: absent
'''

RETURN = r'''
state:
  description: User group state at the end of execution.
  returned: on success
  type: str
  sample: 'present'
usergroup:
  description: User group name.
  returned: on success
  type: str
  sample: 'ACME'
usrgrpid:
    description: User group id, if created, changed or deleted.
    returned: on success
    type: str
    sample: '42'
msg:
    description: The result of the operation
    returned: always
    type: str
    sample: 'User group created: ACME, ID: 42'
'''

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
            _hostgroup = self._zapi.hostgroup.get({
                'output': 'extend',
                'filter': {'name': [name]}
            })
            if len(_hostgroup) < 1:
                self._module.fail_json(msg='Host group not found: %s' % name)
            else:
                return _hostgroup[0]
        except Exception as e:
            self._module.fail_json(msg='Failed to get host group "%s": %s' % (name, e))

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
                'id': self.get_hostgroup_by_hostgroup_name(right.get('host_group'))['groupid'],
                'permission': zabbix_utils.helper_to_numeric_value([
                    'denied',
                    None,
                    'read-only',
                    'read-write'], right.get('permission')
                )
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
                'output': 'extend',
                'filter': {'name': [name]}
            })
            if len(_hostgroup) < 1:
                self._module.fail_json(msg='Host group not found: %s' % name)
            else:
                return _hostgroup[0]
        except Exception as e:
            self._module.fail_json(msg='Failed to get host group "%s": %s' % (name, e))

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
                'id': self.get_hostgroup_by_hostgroup_name(right.get('host_group'))['groupid'],
                'permission': zabbix_utils.helper_to_numeric_value([
                    'denied',
                    None,
                    'read-only',
                    'read-write'], right.get('permission')
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
                'output': 'extend',
                'filter': {'name': [name]}
            })
            if len(_templategroup) < 1:
                self._module.fail_json(msg='Template group not found: %s' % name)
            else:
                return _templategroup[0]
        except Exception as e:
            self._module.fail_json(msg='Failed to get template group "%s": %s' % (name, e))

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
                'id': self.get_templategroup_by_templategroup_name(right.get('template_group'))['groupid'],
                'permission': zabbix_utils.helper_to_numeric_value([
                    'denied',
                    None,
                    'read-only',
                    'read-write'], right.get('permission')
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
                'groupid': self.get_hostgroup_by_hostgroup_name(tag_filter.get('host_group'))['groupid'],
                'tag': tag_filter.get('tag'),
                'value': tag_filter.get('value')
            }
            constructed_data.append(constructed_tag_filter)
        return zabbix_utils.helper_cleanup_data(constructed_data)


class UserGroup(ZabbixBase):
    def _construct_parameters(self, **kwargs):
        """Construct parameters of UserGroup object

        Parameters:
            **kwargs: Arbitrary keyword parameters.

        Returns:
            dict: dictionary of specified parameters
        """
        _params = {
            'name': kwargs['name'],
            'gui_access': zabbix_utils.helper_to_numeric_value([
                'default',
                'internal',
                'LDAP',
                'disable'], kwargs['gui_access']
            ),
            'debug_mode': zabbix_utils.helper_to_numeric_value([
                'disabled',
                'enabled'], kwargs['debug_mode']
            ),
            'users_status': zabbix_utils.helper_to_numeric_value([
                'enabled',
                'disabled'], kwargs['status']
            ),
            'tag_filters': kwargs['tag_filters']
        }
        if LooseVersion(self._zbx_api_version) < LooseVersion('6.2'):
            _params['rights'] = kwargs['rights']
        else:
            _params['hostgroup_rights'] = kwargs['hostgroup_rights']
            _params['templategroup_rights'] = kwargs['templategroup_rights']

            if kwargs['userdirectory']:
                try:
                    if LooseVersion(self._zbx_api_version) <= LooseVersion('6.2'):
                        _userdir = self._zapi.userdirectory.get({
                            'output': 'extend',
                            'filter': {'name': [kwargs['userdirectory']]}
                        })
                    else:
                        _userdir = self._zapi.userdirectory.get({
                            'output': 'extend',
                            'search': {'name': [kwargs['userdirectory']]}
                        })
                except Exception as e:
                    self._module.fail_json(msg='Failed to get user directory "%s": %s' % (kwargs['userdirectory'], e))
                if len(_userdir) == 0:
                    self._module.fail_json(msg='User directory "%s" not found' % kwargs['userdirectory'])
                _params['userdirectoryid'] = _userdir[0]['userdirectoryid']

        return _params

    def check_if_usergroup_exists(self, name):
        """Check if user group exists.

        Parameters:
            name: Name of the user group.

        Returns:
            The return value. True for success, False otherwise.
        """
        try:
            _usergroup = self._zapi.usergroup.get({
                'output': 'extend',
                'filter': {'name': [name]}
            })
            if len(_usergroup) > 0:
                return _usergroup
        except Exception as e:
            self._module.fail_json(msg='Failed to check if user group "%s" exists: %s' % (name, e))

    def get_usergroup_by_usergroup_name(self, name):
        """Get user group by user group name.

        Parameters:
            name: Name of the user group.

        Returns:
            User group matching user group name.
        """
        try:
            if LooseVersion(self._zbx_api_version) < LooseVersion('6.2'):
                _usergroup = self._zapi.usergroup.get({
                    'output': 'extend',
                    'selectTagFilters': 'extend',
                    'selectRights': 'extend',
                    'filter': {'name': [name]}
                })
            else:
                _usergroup = self._zapi.usergroup.get({
                    'output': 'extend',
                    'selectTagFilters': 'extend',
                    'selectHostGroupRights': 'extend',
                    'selectTemplateGroupRights': 'extend',
                    'filter': {'name': [name]}
                })

            if len(_usergroup) < 1:
                self._module.fail_json(msg='User group not found: %s' % name)
            else:
                return _usergroup[0]
        except Exception as e:
            self._module.fail_json(msg='Failed to get user group "%s": %s' % (name, e))

    def check_difference(self, **kwargs):
        """Check difference between user group and user specified parameters.

        Parameters:
            **kwargs: Arbitrary keyword parameters.

        Returns:
            dict: dictionary of differences
        """
        existing_usergroup = zabbix_utils.helper_convert_unicode_to_str(self.get_usergroup_by_usergroup_name(kwargs['name']))
        parameters = zabbix_utils.helper_convert_unicode_to_str(self._construct_parameters(**kwargs))
        change_parameters = {}
        _diff = zabbix_utils.helper_compare_dictionaries(parameters, existing_usergroup, change_parameters)
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
            self._module.fail_json(msg='Failed to update user group "%s": %s' % (kwargs['usrgrpid'], e))

    def add(self, **kwargs):
        """Add user group.

        Parameters:
            **kwargs: Arbitrary keyword parameters.

        Returns:
            usergroup: added user group
        """
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            parameters = self._construct_parameters(**kwargs)
            usergroup = self._zapi.usergroup.create(parameters)
            return usergroup['usrgrpids'][0]
        except Exception as e:
            self._module.fail_json(msg='Failed to create user group "%s": %s' % (kwargs['name'], e))

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
            self._module.fail_json(msg='Failed to delete user group "%s": %s' % (usrgrpid, e))


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(
        name=dict(type='str', required=True, aliases=['user_group']),
        gui_access=dict(type='str', required=False, default='default', choices=['default', 'internal', 'LDAP', 'disable']),
        debug_mode=dict(type='str', required=False, default='disabled', choices=['disabled', 'enabled']),
        status=dict(type='str', required=False, default='enabled', choices=['enabled', 'disabled']),
        rights=dict(type='list', elements='dict', required=False, options=dict(
            host_group=dict(type='str', required=True),
            permission=dict(type='str', required=True, choices=['denied', 'read-only', 'read-write'])
        )),
        hostgroup_rights=dict(type='list', elements='dict', required=False, options=dict(
            host_group=dict(type='str', required=True),
            permission=dict(type='str', required=True, choices=['denied', 'read-only', 'read-write'])
        )),
        templategroup_rights=dict(type='list', elements='dict', required=False, options=dict(
            template_group=dict(type='str', required=True),
            permission=dict(type='str', required=True, choices=['denied', 'read-only', 'read-write'])
        )),
        tag_filters=dict(type='list', elements='dict', required=False, options=dict(
            host_group=dict(type='str', required=True),
            tag=dict(type='str', default=''),
            value=dict(type='str', default='')
        )),
        userdirectory=dict(type='str', required=False),
        state=dict(type='str', default='present', choices=['present', 'absent'])
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    zabbix_utils.require_creds_params(module)

    for p in ['server_url', 'login_user', 'login_password', 'timeout', 'validate_certs']:
        if p in module.params and not module.params[p] is None:
            module.warn('Option "%s" is deprecated with the move to httpapi connection and will be removed in the next release' % p)

    name = module.params['name']
    gui_access = module.params['gui_access']
    debug_mode = module.params['debug_mode']
    status = module.params['status']
    rights = module.params['rights']
    hostgroup_rights = module.params['hostgroup_rights']
    templategroup_rights = module.params['templategroup_rights']
    tag_filters = module.params['tag_filters']
    userdirectory = module.params['userdirectory']
    state = module.params['state']

    userGroup = UserGroup(module)
    zbx = userGroup._zapi
    if LooseVersion(userGroup._zbx_api_version) < LooseVersion('6.2'):
        rgts = Rights(module, zbx)
    else:
        hostgroup_rgts = HostgroupRights(module, zbx)
        templategroup_rgts = TemplategroupRights(module, zbx)
    tgflts = TagFilters(module, zbx)

    usergroup_exists = userGroup.check_if_usergroup_exists(name)

    if usergroup_exists:
        usrgrpid = userGroup.get_usergroup_by_usergroup_name(name)['usrgrpid']
        if state == 'absent':
            userGroup.delete(usrgrpid)
            module.exit_json(changed=True, state=state, usergroup=name, usrgrpid=usrgrpid, msg='User group deleted: %s, ID: %s' % (name, usrgrpid))
        else:
            if LooseVersion(userGroup._zbx_api_version) < LooseVersion('6.2'):
                difference = userGroup.check_difference(
                    usrgrpid=usrgrpid,
                    name=name,
                    gui_access=gui_access,
                    debug_mode=debug_mode,
                    status=status,
                    rights=rgts.construct_the_data(rights),
                    tag_filters=tgflts.construct_the_data(tag_filters)
                )
            else:
                difference = userGroup.check_difference(
                    usrgrpid=usrgrpid,
                    name=name,
                    gui_access=gui_access,
                    debug_mode=debug_mode,
                    status=status,
                    hostgroup_rights=hostgroup_rgts.construct_the_data(hostgroup_rights),
                    templategroup_rights=templategroup_rgts.construct_the_data(templategroup_rights),
                    tag_filters=tgflts.construct_the_data(tag_filters),
                    userdirectory=userdirectory
                )
            if difference == {}:
                module.exit_json(changed=False, state=state, usergroup=name, usrgrpid=usrgrpid, msg='User group is up to date: %s' % name)
            else:
                userGroup.update(
                    usrgrpid=usrgrpid,
                    **difference
                )
                module.exit_json(changed=True, state=state, usergroup=name, usrgrpid=usrgrpid, msg='User group updated: %s, ID: %s' % (name, usrgrpid))
    else:
        if state == 'absent':
            module.exit_json(changed=False, state=state, usergroup=name, msg='User group %s does not exists, nothing to delete' % name)
        else:
            if LooseVersion(userGroup._zbx_api_version) < LooseVersion('6.2'):
                usrgrpid = userGroup.add(
                    name=name,
                    gui_access=gui_access,
                    debug_mode=debug_mode,
                    status=status,
                    rights=rgts.construct_the_data(rights),
                    tag_filters=tgflts.construct_the_data(tag_filters)
                )
            else:
                usrgrpid = userGroup.add(
                    name=name,
                    gui_access=gui_access,
                    debug_mode=debug_mode,
                    status=status,
                    hostgroup_rights=hostgroup_rgts.construct_the_data(hostgroup_rights),
                    templategroup_rights=templategroup_rgts.construct_the_data(templategroup_rights),
                    tag_filters=tgflts.construct_the_data(tag_filters),
                    userdirectory=userdirectory
                )
            module.exit_json(changed=True, state=state, usergroup=name, usrgrpid=usrgrpid, msg='User group created: %s, ID: %s' % (name, usrgrpid))


if __name__ == '__main__':
    main()
