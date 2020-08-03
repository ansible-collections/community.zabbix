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
    - "zabbix-api >= 0.5.4"
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
# Base create user group example
- name: Create user group
  community.zabbix.zabbix_usergroup:
    server_url: "http://zabbix.example.com/zabbix/"
    login_user: admin
    login_password: secret
    name: ACME
    state: present

# Base create user group with disabled gui access
- name: Create user group with disabled gui access
  community.zabbix.zabbix_usergroup:
    server_url: "http://zabbix.example.com/zabbix/"
    login_user: admin
    login_password: secret
    name: ACME
    gui_access: disable

# Base create user group with permissions
- name: Create user group with permissions
  community.zabbix.zabbix_usergroup:
    server_url: "http://zabbix.example.com/zabbix/"
    login_user: admin
    login_password: secret
    name: ACME
    rights:
        - host_group: Webserver
          permission: read-write
        - host_group: Databaseserver
          permission: read-only
    state: present

# Base create user group with tag permissions
- name: Create user group with tag permissions
  community.zabbix.zabbix_usergroup:
    server_url: "http://zabbix.example.com/zabbix/"
    login_user: admin
    login_password: secret
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
  community.zabbix.zabbix_usergroup:
    server_url: "http://zabbix.example.com/zabbix/"
    login_user: admin
    login_password: secret
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
            'rights': kwargs['rights'],
            'tag_filters': kwargs['tag_filters']
        }
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
            _usergroup = self._zapi.usergroup.get({
                'output': 'extend',
                'selectTagFilters': 'extend',
                'selectRights': 'extend',
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
        tag_filters=dict(type='list', elements='dict', required=False, options=dict(
            host_group=dict(type='str', required=True),
            tag=dict(type='str', default=''),
            value=dict(type='str', default='')
        )),
        state=dict(type='str', default='present', choices=['present', 'absent'])
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    name = module.params['name']
    gui_access = module.params['gui_access']
    debug_mode = module.params['debug_mode']
    status = module.params['status']
    rights = module.params['rights']
    tag_filters = module.params['tag_filters']
    state = module.params['state']

    userGroup = UserGroup(module)
    # reuse zabbix-api login
    zbx = userGroup._zapi
    rgts = Rights(module, zbx)
    tgflts = TagFilters(module, zbx)

    usergroup_exists = userGroup.check_if_usergroup_exists(name)

    if usergroup_exists:
        usrgrpid = userGroup.get_usergroup_by_usergroup_name(name)['usrgrpid']
        if state == 'absent':
            userGroup.delete(usrgrpid)
            module.exit_json(changed=True, state=state, usergroup=name, usrgrpid=usrgrpid, msg='User group deleted: %s, ID: %s' % (name, usrgrpid))
        else:
            difference = userGroup.check_difference(
                usrgrpid=usrgrpid,
                name=name,
                gui_access=gui_access,
                debug_mode=debug_mode,
                status=status,
                rights=rgts.construct_the_data(rights),
                tag_filters=tgflts.construct_the_data(tag_filters)
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
            usrgrpid = userGroup.add(
                name=name,
                gui_access=gui_access,
                debug_mode=debug_mode,
                status=status,
                rights=rgts.construct_the_data(rights),
                tag_filters=tgflts.construct_the_data(tag_filters)
            )
            module.exit_json(changed=True, state=state, usergroup=name, usrgrpid=usrgrpid, msg='User group created: %s, ID: %s' % (name, usrgrpid))


if __name__ == '__main__':
    main()
