#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, sky-joker
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
module: zabbix_user
short_description: Create/update/delete Zabbix users
author:
    - sky-joker (@sky-joker)
description:
    - This module allows you to create, modify and delete Zabbix users.
requirements:
    - "python >= 2.6"
    - "zabbix-api >= 0.5.4"
options:
    alias:
        description:
            - Name of the user alias in Zabbix.
            - alias is the unique identifier used and cannot be updated using this module.
        aliases: [ username ]
        required: true
        type: str
    name:
        description:
            - Name of the user.
        type: str
    surname:
        description:
            - Surname of the user.
        type: str
    usrgrps:
        description:
            - User groups to add the user to.
            - Required when I(state=present).
        required: false
        type: list
        elements: str
    passwd:
        description:
            - User's password.
            - Required unless all of the I(usrgrps) are set to use LDAP as frontend access.
            - Always required for Zabbix versions lower than 4.0.
        required: false
        type: str
    override_passwd:
        description:
            - Override password for the user.
            - Password will not be updated on subsequent runs without setting this value to yes.
        default: no
        type: bool
    lang:
        description:
            - Language code of the user's language.
            - C(default) can be used with Zabbix version 5.2 or higher.
        choices:
            - 'en_GB'
            - 'en_US'
            - 'zh_CN'
            - 'cs_CZ'
            - 'fr_FR'
            - 'he_IL'
            - 'it_IT'
            - 'ko_KR'
            - 'ja_JP'
            - 'nb_NO'
            - 'pl_PL'
            - 'pt_BR'
            - 'pt_PT'
            - 'ru_RU'
            - 'sk_SK'
            - 'tr_TR'
            - 'uk_UA'
            - 'default'
        type: str
    theme:
        description:
            - User's theme.
        choices:
            - 'default'
            - 'blue-theme'
            - 'dark-theme'
        type: str
    autologin:
        description:
            - Whether to enable auto-login.
            - If enable autologin, cannot enable autologout.
        type: bool
    autologout:
        description:
            - User session life time in seconds. If set to 0, the session will never expire.
            - If enable autologout, cannot enable autologin.
        type: str
    refresh:
        description:
            - Automatic refresh period in seconds.
        type: str
    rows_per_page:
        description:
            - Amount of object rows to show per page.
        type: str
    after_login_url:
        description:
            - URL of the page to redirect the user to after logging in.
        type: str
    user_medias:
        description:
            - Set the user's media.
            - If not set, makes no changes to media.
        suboptions:
            mediatype:
                description:
                    - Media type name to set.
                default: 'Email'
                type: str
            sendto:
                description:
                    - Address, user name or other identifier of the recipient.
                required: true
                type: str
            period:
                description:
                    - Time when the notifications can be sent as a time period or user macros separated by a semicolon.
                    - Please review the documentation for more information on the supported time period.
                    - https://www.zabbix.com/documentation/4.0/manual/appendix/time_period
                default: '1-7,00:00-24:00'
                type: str
            severity:
                description:
                    - Trigger severities to send notifications about.
                suboptions:
                   not_classified:
                       description:
                           - severity not_classified enable/disable.
                       default: True
                       type: bool
                   information:
                       description:
                           - severity information enable/disable.
                       default: True
                       type: bool
                   warning:
                       description:
                           - severity warning enable/disable.
                       default: True
                       type: bool
                   average:
                       description:
                           - severity average enable/disable.
                       default: True
                       type: bool
                   high:
                       description:
                           - severity high enable/disable.
                       default: True
                       type: bool
                   disaster:
                       description:
                           - severity disaster enable/disable.
                       default: True
                       type: bool
                default:
                  not_classified: True
                  information: True
                  warning: True
                  average: True
                  high: True
                  disaster: True
                type: dict
            active:
                description:
                    - Whether the media is enabled.
                default: true
                type: bool
        type: list
        elements: dict
    type:
        description:
            - Type of the user.
            - I(type) can be used when Zabbix version is 5.0 or lower.
        choices:
            - 'Zabbix user'
            - 'Zabbix admin'
            - 'Zabbix super admin'
        type: str
    timezone:
        description:
            - User's time zone.
            - I(timezone) can be used with Zabbix version 5.2 or higher.
            - For the full list of supported time zones please refer to U(https://www.php.net/manual/en/timezones.php)
        type: str
        version_added: 1.2.0
    role_name:
        description:
            - User's role.
            - I(role_name) can be used when Zabbix version is 5.2 or higher.
            - Default is C(User role) when creating a new user.
            - The default value will be removed at the version 2.0.0.
        type: str
        version_added: 1.2.0
    state:
        description:
            - State of the user.
            - On C(present), it will create if user does not exist or update the user if the associated data is different.
            - On C(absent) will remove a user if it exists.
        default: 'present'
        choices: ['present', 'absent']
        type: str
extends_documentation_fragment:
- community.zabbix.zabbix

'''

EXAMPLES = r'''
- name: create a new zabbix user.
  community.zabbix.zabbix_user:
    server_url: "http://zabbix.example.com/zabbix/"
    login_user: Admin
    login_password: secret
    alias: example
    name: user name
    surname: user surname
    usrgrps:
      - Guests
      - Disabled
    passwd: password
    lang: en_GB
    theme: blue-theme
    autologin: no
    autologout: '0'
    refresh: '30'
    rows_per_page: '200'
    after_login_url: ''
    user_medias:
      - mediatype: Email
        sendto: example@example.com
        period: 1-7,00:00-24:00
        severity:
          not_classified: no
          information: yes
          warning: yes
          average: yes
          high: yes
          disaster: yes
        active: no
    type: Zabbix super admin
    state: present

- name: delete existing zabbix user.
  community.zabbix.zabbix_user:
    server_url: "http://zabbix.example.com/zabbix/"
    login_user: admin
    login_password: secret
    alias: example
    usrgrps:
      - Guests
    passwd: password
    user_medias:
      - sendto: example@example.com
    state: absent
'''

RETURN = r'''
user_ids:
    description: User id created or changed
    returned: success
    type: dict
    sample: { "userids": [ "5" ] }
'''


import copy

from distutils.version import LooseVersion
from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
from ansible_collections.community.zabbix.plugins.module_utils.helpers import helper_normalize_data
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


class User(ZabbixBase):

    def alias_key(self):
        """ Returns the key name for 'alias', which has been renamed to
        'username' in Zabbix 5.4.

        """
        if LooseVersion(self._zbx_api_version) >= LooseVersion('5.4'):
            return 'username'

        return 'alias'

    def get_usergroups_by_name(self, usrgrps):
        params = {
            'output': ['usrgrpid', 'name', 'gui_access'],
            'filter': {
                'name': usrgrps
            }
        }
        res = self._zapi.usergroup.get(params)
        if res:
            ids = [{'usrgrpid': g['usrgrpid']} for g in res]
            # User can be created password-less only when all groups are LDAP
            # Verify there are no groups with different access methods
            not_ldap = bool([g for g in res if g['gui_access'] != '2'])
            not_found_groups = set(usrgrps) - set([g['name'] for g in res])
            if not_found_groups:
                self._module.fail_json(msg='User groups not found: %s' % not_found_groups)
            return ids, not_ldap
        else:
            self._module.fail_json(msg='No user groups found')

    def check_user_exist(self, alias):
        zbx_user = self._zapi.user.get({'output': 'extend', 'filter': {self.alias_key(): alias},
                                        'getAccess': True, 'selectMedias': 'extend',
                                        'selectUsrgrps': 'extend'})

        return zbx_user

    def convert_user_medias_parameter_types(self, user_medias):
        copy_user_medias = copy.deepcopy(user_medias)
        for user_media in copy_user_medias:
            media_types = self._zapi.mediatype.get({'output': 'extend'})
            for media_type in media_types:
                if LooseVersion(self._zbx_api_version) < LooseVersion('4.4'):
                    if media_type['description'] == user_media['mediatype']:
                        user_media['mediatypeid'] = media_type['mediatypeid']
                        break
                else:
                    if media_type['name'] == user_media['mediatype']:
                        user_media['mediatypeid'] = media_type['mediatypeid']
                        break

            if 'mediatypeid' not in user_media:
                self._module.fail_json(msg="Media type not found: %s" % user_media['mediatype'])
            else:
                del user_media['mediatype']

            severity_binary_number = ''
            for severity_key in 'disaster', 'high', 'average', 'warning', 'information', 'not_classified':
                if user_media['severity'][severity_key]:
                    severity_binary_number = severity_binary_number + '1'
                else:
                    severity_binary_number = severity_binary_number + '0'
            user_media['severity'] = str(int(severity_binary_number, 2))

            if user_media['active']:
                user_media['active'] = '0'
            else:
                user_media['active'] = '1'

        return copy_user_medias

    def get_roleid_by_name(self, role_name):
        roles = self._zapi.role.get({'output': 'extend'})
        for role in roles:
            if role['name'] == role_name:
                return role['roleid']

        self._module.fail_json(msg="Role not found: %s" % role_name)

    def user_parameter_difference_check(self, zbx_user, alias, name, surname, user_group_ids, passwd, lang, theme,
                                        autologin, autologout, refresh, rows_per_page, url, user_medias, user_type,
                                        timezone, role_name, override_passwd):

        if user_medias:
            user_medias = self.convert_user_medias_parameter_types(user_medias)

        # existing data
        existing_data = copy.deepcopy(zbx_user[0])
        usrgrpids = []
        for usrgrp in existing_data['usrgrps']:
            usrgrpids.append({'usrgrpid': usrgrp['usrgrpid']})

        existing_data['usrgrps'] = sorted(usrgrpids, key=lambda x: x['usrgrpid'])

        # Processing for zabbix 4.0 and above.
        # In zabbix 4.0 and above, Email sendto is of type list.
        # This module, one media supports only one Email sendto.
        # Therefore following processing extract one Email from list.
        if LooseVersion(self._zbx_api_version) >= LooseVersion('4.0'):
            for media in existing_data['medias']:
                if isinstance(media['sendto'], list):
                    media['sendto'] = media['sendto'][0]

        existing_data['user_medias'] = sorted(existing_data['medias'], key=lambda x: x['sendto'])
        for del_key in ['medias', 'attempt_clock', 'attempt_failed', 'attempt_ip', 'debug_mode', 'users_status',
                        'gui_access']:
            del existing_data[del_key]

        for user_media in existing_data['user_medias']:
            for del_key in ['mediaid', 'userid']:
                del user_media[del_key]

        # request data
        request_data = {
            'userid': zbx_user[0]['userid'],
            self.alias_key(): alias,
            'name': name,
            'surname': surname,
            'usrgrps': sorted(user_group_ids, key=lambda x: x['usrgrpid']),
            'lang': lang,
            'theme': theme,
            'autologin': autologin,
            'autologout': autologout,
            'refresh': refresh,
            'rows_per_page': rows_per_page,
            'url': url,
        }

        if user_medias:
            request_data['user_medias'] = sorted(user_medias, key=lambda x: x['sendto'])
        else:
            del existing_data['user_medias']

        if override_passwd:
            request_data['passwd'] = passwd

        # The type key has changed to roleid key since Zabbix 5.2
        if LooseVersion(self._zbx_api_version) < LooseVersion('5.2'):
            request_data['type'] = user_type
        else:
            request_data['roleid'] = self.get_roleid_by_name(role_name) if role_name else None
            request_data['timezone'] = timezone

        request_data, del_keys = helper_normalize_data(request_data)
        existing_data, _del_keys = helper_normalize_data(existing_data, del_keys)

        user_parameter_difference_check_result = True
        if existing_data == request_data:
            user_parameter_difference_check_result = False

        diff_params = {
            "before": existing_data,
            "after": request_data
        }

        return user_parameter_difference_check_result, diff_params

    def add_user(self, alias, name, surname, user_group_ids, passwd, lang, theme, autologin, autologout, refresh,
                 rows_per_page, url, user_medias, user_type, not_ldap, timezone, role_name):

        if role_name is None and LooseVersion(self._zbx_api_version) >= LooseVersion('5.2'):
            # This variable is to set the default value because the module must have a backward-compatible.
            # The default value will be removed at the version 2.0.0.
            # https://github.com/ansible-collections/community.zabbix/pull/382
            role_name = "User role"

        if user_medias:
            user_medias = self.convert_user_medias_parameter_types(user_medias)

        user_ids = {}

        request_data = {
            self.alias_key(): alias,
            'name': name,
            'surname': surname,
            'usrgrps': user_group_ids,
            'lang': lang,
            'theme': theme,
            'autologin': autologin,
            'autologout': autologout,
            'refresh': refresh,
            'rows_per_page': rows_per_page,
            'url': url,
        }
        if user_medias:
            request_data['user_medias'] = user_medias

        if LooseVersion(self._zbx_api_version) < LooseVersion('4.0') or not_ldap:
            request_data['passwd'] = passwd

        # The type key has changed to roleid key since Zabbix 5.2
        if LooseVersion(self._zbx_api_version) < LooseVersion('5.2'):
            request_data['type'] = user_type
        else:
            request_data['roleid'] = self.get_roleid_by_name(role_name)
            request_data['timezone'] = timezone

        request_data, _del_keys = helper_normalize_data(request_data)

        diff_params = {}
        if not self._module.check_mode:
            try:
                user_ids = self._zapi.user.create(request_data)
            except Exception as e:
                self._module.fail_json(msg="Failed to create user %s: %s" % (alias, e))
        else:
            diff_params = {
                "before": "",
                "after": request_data
            }

        return user_ids, diff_params

    def update_user(self, zbx_user, alias, name, surname, user_group_ids, passwd, lang, theme, autologin, autologout,
                    refresh, rows_per_page, url, user_medias, user_type, timezone, role_name, override_passwd):

        if user_medias:
            user_medias = self.convert_user_medias_parameter_types(user_medias)

        user_ids = {}

        request_data = {
            'userid': zbx_user[0]['userid'],
            self.alias_key(): alias,
            'name': name,
            'surname': surname,
            'usrgrps': user_group_ids,
            'lang': lang,
            'theme': theme,
            'autologin': autologin,
            'autologout': autologout,
            'refresh': refresh,
            'rows_per_page': rows_per_page,
            'url': url,
        }

        if override_passwd:
            request_data['passwd'] = passwd

        # The type key has changed to roleid key since Zabbix 5.2
        if LooseVersion(self._zbx_api_version) < LooseVersion('5.2'):
            request_data['type'] = user_type
        else:
            request_data['roleid'] = self.get_roleid_by_name(role_name) if role_name else None
            request_data['timezone'] = timezone

        request_data, _del_keys = helper_normalize_data(request_data)

        # In the case of zabbix 3.2 or less, it is necessary to use updatemedia method to update media.
        if LooseVersion(self._zbx_api_version) <= LooseVersion('3.2'):
            try:
                user_ids = self._zapi.user.update(request_data)
            except Exception as e:
                self._module.fail_json(msg="Failed to update user %s: %s" % (alias, e))

            try:
                if user_medias:
                    user_ids = self._zapi.user.updatemedia({
                        'users': [{'userid': zbx_user[0]['userid']}],
                        'medias': user_medias
                    })
            except Exception as e:
                self._module.fail_json(msg="Failed to update user medias %s: %s" % (alias, e))

        if LooseVersion(self._zbx_api_version) >= LooseVersion('3.4'):
            try:
                if user_medias:
                    request_data['user_medias'] = user_medias
                user_ids = self._zapi.user.update(request_data)
            except Exception as e:
                self._module.fail_json(msg="Failed to update user %s: %s" % (alias, e))

        return user_ids

    def delete_user(self, zbx_user, alias):
        user_ids = {}
        diff_params = {}

        if not self._module.check_mode:
            try:
                user_ids = self._zapi.user.delete([zbx_user[0]['userid']])
            except Exception as e:
                self._module.fail_json(msg="Failed to delete user %s: %s" % (alias, e))
        else:
            diff_params = {
                "before": zbx_user[0],
                "after": ""
            }

        return user_ids, diff_params


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        alias=dict(type='str', required=True, aliases=['username']),
        name=dict(type='str'),
        surname=dict(type='str'),
        usrgrps=dict(type='list'),
        passwd=dict(type='str', required=False, no_log=True),
        override_passwd=dict(type='bool', required=False, default=False, no_log=False),
        lang=dict(type='str', choices=['en_GB', 'en_US', 'zh_CN', 'cs_CZ', 'fr_FR',
                                       'he_IL', 'it_IT', 'ko_KR', 'ja_JP', 'nb_NO',
                                       'pl_PL', 'pt_BR', 'pt_PT', 'ru_RU', 'sk_SK',
                                       'tr_TR', 'uk_UA', 'default']),
        theme=dict(type='str', choices=['default', 'blue-theme', 'dark-theme']),
        autologin=dict(type='bool'),
        autologout=dict(type='str'),
        refresh=dict(type='str'),
        rows_per_page=dict(type='str'),
        after_login_url=dict(type='str'),
        user_medias=dict(type='list', elements='dict',
                         options=dict(mediatype=dict(type='str', default='Email'),
                                      sendto=dict(type='str', required=True),
                                      period=dict(type='str', default='1-7,00:00-24:00'),
                                      severity=dict(type='dict',
                                                    options=dict(
                                                        not_classified=dict(type='bool', default=True),
                                                        information=dict(type='bool', default=True),
                                                        warning=dict(type='bool', default=True),
                                                        average=dict(type='bool', default=True),
                                                        high=dict(type='bool', default=True),
                                                        disaster=dict(type='bool', default=True)),
                                                    default=dict(
                                                        not_classified=True,
                                                        information=True,
                                                        warning=True,
                                                        average=True,
                                                        high=True,
                                                        disaster=True)),
                                      active=dict(type='bool', default=True))),
        timezone=dict(type='str'),
        role_name=dict(type='str'),
        type=dict(type='str', choices=['Zabbix user', 'Zabbix admin', 'Zabbix super admin']),
        state=dict(type='str', default="present", choices=['present', 'absent'])
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=[
            ['state', 'present', ['usrgrps']]
        ],
        supports_check_mode=True
    )

    alias = module.params['alias']
    name = module.params['name']
    surname = module.params['surname']
    usrgrps = module.params['usrgrps']
    passwd = module.params['passwd']
    override_passwd = module.params['override_passwd']
    lang = module.params['lang']
    theme = module.params['theme']
    autologin = module.params['autologin']
    autologout = module.params['autologout']
    refresh = module.params['refresh']
    rows_per_page = module.params['rows_per_page']
    after_login_url = module.params['after_login_url']
    user_medias = module.params['user_medias']
    user_type = module.params['type']
    timezone = module.params['timezone']
    role_name = module.params['role_name']
    state = module.params['state']

    if autologin is not None:
        if autologin:
            autologin = '1'
        else:
            autologin = '0'

    user_type_dict = {
        'Zabbix user': '1',
        'Zabbix admin': '2',
        'Zabbix super admin': '3'
    }
    user_type = user_type_dict[user_type] if user_type else None

    user = User(module)

    user_ids = {}
    zbx_user = user.check_user_exist(alias)
    if state == 'present':
        user_group_ids, not_ldap = user.get_usergroups_by_name(usrgrps)
        if LooseVersion(user._zbx_api_version) < LooseVersion('4.0') or not_ldap:
            if passwd is None:
                module.fail_json(msg='User password is required. One or more groups are not LDAP based.')

        if zbx_user:
            diff_check_result, diff_params = user.user_parameter_difference_check(zbx_user, alias, name, surname,
                                                                                  user_group_ids, passwd, lang, theme,
                                                                                  autologin, autologout, refresh,
                                                                                  rows_per_page, after_login_url,
                                                                                  user_medias, user_type, timezone,
                                                                                  role_name, override_passwd)

            if not module.check_mode and diff_check_result:
                user_ids = user.update_user(zbx_user, alias, name, surname, user_group_ids, passwd, lang,
                                            theme, autologin, autologout, refresh, rows_per_page, after_login_url,
                                            user_medias, user_type, timezone, role_name, override_passwd)
        else:
            diff_check_result = True
            user_ids, diff_params = user.add_user(alias, name, surname, user_group_ids, passwd, lang, theme, autologin,
                                                  autologout, refresh, rows_per_page, after_login_url, user_medias,
                                                  user_type, not_ldap, timezone, role_name)

    if state == 'absent':
        if zbx_user:
            diff_check_result = True
            user_ids, diff_params = user.delete_user(zbx_user, alias)
        else:
            diff_check_result = False
            diff_params = {}

    if not module.check_mode:
        if user_ids:
            module.exit_json(changed=True, user_ids=user_ids)
        else:
            module.exit_json(changed=False)
    else:
        if diff_check_result:
            module.exit_json(changed=True, diff=diff_params)
        else:
            module.exit_json(changed=False, diff=diff_params)


if __name__ == "__main__":
    main()
