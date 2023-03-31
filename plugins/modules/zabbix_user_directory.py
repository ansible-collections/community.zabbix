#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: zabbix_user_directory
short_description: Create/update/delete Zabbix user directories
description:
   - This module allows you to create, modify and delete Zabbix user directories.
author:
    - Evgeny Yurchenko (@BGmot)
requirements:
    - python >= 3.9
options:
    name:
        description:
            - Unique name of the user directory.
        required: true
        type: str
    idp_type:
        description:
            - Type of IdP. Only one user directory of type SAML can exist.
            - This parameter is available since Zabbix 6.4.
        required: false
        type: str
        choices: ['ldap', 'saml']
    provision_status:
        description:
            - User directory provisioning status.
            - if I(false) Provisioning of users created by this user directory is disabled
            - if I(true) Provisioning of users created by this user directory is enabled.
              Additionally, the authentication status of C(ldap_jit_status) or C(saml_jit_status) should be enabled.
            - This parameter is available since Zabbix 6.4.
        required: false
        type: bool
        default: false
    user_username:
        description:
            - LDAP/SAML attribute name to use for users.name field when user is provisioned
            - This parameter is available since Zabbix 6.4.
        required: false
        type: str
    user_lastname:
        description:
            - LDAP/SAML attribute name to use for users.surname field when user is provisioned
            - This parameter is available since Zabbix 6.4.
        required: false
        type: str
    user_ref_attr:
        description:
            - LDAP user object attribute name. Will be set instead of the placeholder I(%{ref}) in c(group_filter) string.
            - This parameter is available since Zabbix 6.4.
        required: false
        type: str
    description:
        description:
            - User directory description.
        required: false
        type: str
        default: ''
    group_membership:
        description:
            - LDAP property containing groups of user. E.g. I(memberOf)
            - This parameter is available since Zabbix 6.4.
        required: false
        type: str
    group_basedn:
        description:
            - LDAP groups path in LDAP tree to search for groups data.
            - Used to configure user membership check in I(openLDAP).
            - Required if group_membership is not set.
            - This parameter is available since Zabbix 6.4.
        type: str
    group_name:
        description:
            - LDAP/SAML attribute name to get group name for group mapping between Zabbix and IdP.
            - Used to configure user membership check in LDAP.
            - Ignored when provisioning a user if group_membership is set.
            - This parameter is available since Zabbix 6.4.
        required: false
        type: str
    group_member:
        description:
            - LDAP tree attribute name containing group name received with C(group_filter) query.
            - Used to configure user membership check in openLDAP.
            - Ignored when provisioning a user if group_membership is set.
            - This parameter is available since Zabbix 6.4.
        type: str
    group_filter:
        description:
            - LDAP search filter to select groups when searching for specific user groups.
            - Used to configure user membership check in openLDAP.
            - Ignored when provisioning a user if group_membership is set.
            - This parameter is available since Zabbix 6.4.
        type: str
        required: false
    bind_password:
        description:
            - LDAP bind password. Can be empty for anonymous binding.
        required: false
        type: str
    search_filter:
        description:
            - LDAP custom filter string when authenticating user in LDAP.
            - Supported search_filter placeholders
            -   I(%{attr}) search attribute name (uid, sAMAccountName);
            -   I(%{user}) username value.
        default: (%{attr}=%{user})
        required: false
        type: str
    start_tls:
        description:
            - LDAP startTLS option. It cannot be used with ldaps:// protocol hosts.
        required: false
        type: int
        default: 0
        choices: [0, 1]
    host:
        description:
            - LDAP server host name, IP or URI. URI should contain schema, host and port (optional).
            - required if C(idp_type) is set to I(ldap).
        required: false
        type: str
    port:
        description:
            - LDAP server port.
            - required if C(idp_type) is set to I(ldap).
        required: false
        type: int
    base_dn:
        description:
            - LDAP base distinguished name string.
            - required if C(idp_type) is set to I(ldap).
        required: false
        type: str
    search_attribute:
        description:
            - LDAP attribute name to identify user by username in Zabbix database.
            - required if C(idp_type) is set to I(ldap).
        required: false
        type: str
    bind_dn:
        description:
            - LDAP bind distinguished name string. Can be empty for anonymous binding.
        required: false
        type: str
        default: ''
    idp_entityid:
        description:
            - SAML URI that identifies the IdP in SAML messages.
            - required if C(idp_type) is set to I(saml).
            - This parameter is available since Zabbix 6.4.
        required: false
        type: str
    sp_entityid:
        description:
            - SAML SP entity ID.
            - required if C(idp_type) is set to I(saml).
            - This parameter is available since Zabbix 6.4.
        required: false
        type: str
    sso_url:
        description:
            - SAML URL of the IdP's SAML SSO service, to which Zabbix will send SAML authentication requests.
            - required if C(idp_type) is set to I(saml).
            - This parameter is available since Zabbix 6.4.
        required: false
        type: str
    slo_url:
        description:
            - SAML IdP service endpoint URL to which Zabbix will send SAML logout requests.
            - This parameter is available since Zabbix 6.4.
        required: false
        type: str
    username_attribute:
        description:
            - SAML username attribute to be used in comparison with Zabbix user.username value when authenticating.
            - required if C(idp_type) is set to I(saml).
            - This parameter is available since Zabbix 6.4.
        required: false
        type: str
    nameid_format:
        description:
            - SAML SP name ID format.
            - This parameter is available since Zabbix 6.4.
        required: false
        type: str
    scim_status:
        description:
            - Whether the SCIM provisioning for SAML is enabled or disabled.
            - This parameter is available since Zabbix 6.4.
        required: false
        type: bool
        default: false
    encrypt_nameid:
        description:
            - SAML encrypt name ID. Encrypts if I(true).
            - This parameter is available since Zabbix 6.4.
        required: false
        type: bool
        default: false
    encrypt_assertions:
        description:
            - SAML encrypt assertions. Encrypts if I(true).
            - This parameter is available since Zabbix 6.4.
        required: false
        type: bool
        default: false
    sign_messages:
        description:
            - SAML sign messages. Signs if I(true).
            - This parameter is available since Zabbix 6.4.
        required: false
        type: bool
        default: false
    sign_assertions:
        description:
            - SAML sign assertions. Signs if I(true).
            - This parameter is available since Zabbix 6.4.
        required: false
        type: bool
        default: false
    sign_authn_requests:
        description:
            - SAML sign AuthN requests. Signs if I(true).
            - This parameter is available since Zabbix 6.4.
        required: false
        type: bool
        default: false
    sign_logout_requests:
        description:
            - SAML sign logout requests. Signs if I(true).
            - This parameter is available since Zabbix 6.4.
        required: false
        type: bool
        default: false
    sign_logout_responses:
        description:
            - SAML sign logout responses. Signs if I(true).
            - This parameter is available since Zabbix 6.4.
        required: false
        type: bool
        default: false
    provision_media:
        type: list
        elements: dict
        description:
            - Array of the IdP media type mappings objects.
            - This parameter is available since Zabbix 6.4.
        suboptions:
            name:
                description:
                    - Visible name in the list of media type mappings.
                type: str
                required: true
            mediatype:
                description:
                    - Name of media type to be created.
                type: str
                required: true
            attribute:
                description:
                    - Attribute name. Used as the value for the I(sendto) field.
                    - If present in data received from IdP and the value is not empty, will trigger media creation for the provisioned user.
                type: str
                required: true
    provision_groups:
        type: list
        elements: dict
        description:
            - Array of the IdP media type mappings objects.
            - This parameter is available since Zabbix 6.4.
        suboptions:
            name:
                description:
                    - IdP group full name.
                    - Supports the wildcard character "*". Unique across all provisioning groups mappings.
                type: str
                required: true
            role:
                description:
                    - User role name to assign to the user.
                    - Note that if multiple provisioning groups mappings are matched, the role of the highest user type will be assigned to the user.
                      If there are multiple roles with the same user type, the first role (sorted in alphabetical order) will be assigned to the user.
                type: str
                required: true
            user_groups:
                type: list
                elements: str
                description:
                    - Array of Zabbix user group names.
                    - Note that if multiple provisioning groups mappings are matched, Zabbix user groups of all matched mappings will be assigned to the user.
                required: true
    state:
        description:
            - State of the user directory.
            - On C(present), it will create if user directory does not exist or update it if the associated data is different.
            - On C(absent) will remove the user directory if it exists.
        choices: ['present', 'absent']
        default: 'present'
        type: str

extends_documentation_fragment:
- community.zabbix.zabbix

'''

EXAMPLES = r'''
---
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

- name: Create new user directory or update existing info (Zabbix <= 6.2)
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_user_directory:
    state: present
    name: TestUserDirectory
    host: 'test.com'
    port: 389
    base_dn: 'ou=Users,dc=example,dc=org'
    search_attribute: 'uid'
    bind_dn: 'cn=ldap_search,dc=example,dc=org'
    description: 'Test user directory'
    search_filter: '(%{attr}=test_user)'
    start_tls: 0

- name: Create new user directory with LDAP IDP or update existing info (Zabbix >= 6.4)
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_user_directory:
    state: present
    name: TestUserDirectory
    idp_type: ldap
    host: 'test.ca'
    port: 389
    base_dn: 'ou=Users,dc=example,dc=org'
    search_attribute: 'uid'
    provision_status: true
    group_name: cn
    group_basedn: ou=Group,dc=example,dc=org
    group_member: member
    user_ref_attr: uid
    group_filter: '(member=uid=%{ref},ou=Users,dc=example,dc=com)'
    user_username: first_name
    user_lastname: last_name
    provision_media:
      - name: Media1
        mediatype: Email
        attribute: email1
    provision_groups:
      - name: idpname1
        role: Guest role
        user_groups:
          - Guests

- name: Create new user directory with SAML IDP or update existing info (Zabbix >= 6.4)
  # set task level variables as we change ansible_connection plugin here
  vars:
    ansible_network_os: community.zabbix.zabbix
    ansible_connection: httpapi
    ansible_httpapi_port: 443
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_zabbix_url_path: 'zabbixeu'  # If Zabbix WebUI runs on non-default (zabbix) path ,e.g. http://<FQDN>/zabbixeu
    ansible_host: zabbix-example-fqdn.org
  community.zabbix.zabbix_user_directory:
    state: present
    name: TestUserDirectory
    idp_type: saml
    idp_entityid: http://okta.com/xxxxx
    sp_entityid: zabbix
    sso_url: http://xxxx.okta.com/app/xxxxxx_123dhu8o3
    username_attribute: usrEmail
    provision_status: true
    group_name: cn
    user_username: first_name
    user_lastname: last_name
    provision_media:
      - name: Media1
        mediatype: Email
        attribute: email1
    provision_groups:
      - name: idpname1
        role: Guest role
        user_groups:
          - Guests
'''


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.zabbix.plugins.module_utils.base import ZabbixBase
from ansible.module_utils.compat.version import LooseVersion
import ansible_collections.community.zabbix.plugins.module_utils.helpers as zabbix_utils


def main():
    argument_spec = zabbix_utils.zabbix_common_argument_spec()
    argument_spec.update(dict(
        name=dict(type='str', required=True),
        idp_type=dict(type='str', required=False, choices=['ldap', 'saml']),
        host=dict(type='str', required=False),
        port=dict(type='int', required=False),
        base_dn=dict(type='str', required=False),
        search_attribute=dict(type='str', required=False),
        bind_dn=dict(type='str', required=False, default=''),
        bind_password=dict(type='str', required=False, no_log=True),
        description=dict(type='str', required=False, default=''),
        search_filter=dict(type='str', default='(%{attr}=%{user})', required=False),
        start_tls=dict(type='int', required=False, choices=[0, 1], default=0),
        idp_entityid=dict(type='str', required=False),
        sp_entityid=dict(type='str', required=False),
        sso_url=dict(type='str', required=False),
        slo_url=dict(type='str', required=False),
        username_attribute=dict(type='str', required=False),
        nameid_format=dict(type='str', required=False),
        scim_status=dict(type='bool', required=False, default=False),
        encrypt_nameid=dict(type='bool', required=False, default=False),
        encrypt_assertions=dict(type='bool', required=False, default=False),
        sign_messages=dict(type='bool', required=False, default=False),
        sign_assertions=dict(type='bool', required=False, default=False),
        sign_authn_requests=dict(type='bool', required=False, default=False),
        sign_logout_requests=dict(type='bool', required=False, default=False),
        sign_logout_responses=dict(type='bool', required=False, default=False),
        provision_status=dict(type='bool', required=False, default=False),
        group_basedn=dict(type='str', required=False),
        group_filter=dict(type='str', required=False),
        group_member=dict(type='str', required=False),
        group_membership=dict(type='str', required=False),
        group_name=dict(type='str', required=False),
        user_lastname=dict(type='str', required=False),
        user_ref_attr=dict(type='str', required=False),
        user_username=dict(type='str', required=False),
        provision_media=dict(
            type='list',
            required=False,
            elements='dict',
            options=dict(
                name=dict(type='str', required=True),
                mediatype=dict(type='str', required=True),
                attribute=dict(type='str', required=True)
            )
        ),
        provision_groups=dict(
            type='list',
            required=False,
            elements='dict',
            options=dict(
                name=dict(type='str', required=True),
                role=dict(type='str', required=True),
                user_groups=dict(type='list', elements='str', required=True)
            )
        ),
        state=dict(type='str', default='present', choices=['present', 'absent'])
    ))

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )
    ''' For future when < 6.4 disappears we should use this, now we cannot do this as at this point Zabbix version is unknown
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ('state', 'present', ('idp_type',)),
            ('idp_type', 'ldap', ('host', 'port', 'base_dn', 'search_attribute'), False),
            ('idp_type', 'saml', ('idp_entityid', 'sp_entityid', 'sso_url', 'username_attribute'), False),
            ('provision_status', 'true', ('provision_groups'))
        ]
    )
    '''

    zabbix_utils.require_creds_params(module)

    for p in ['server_url', 'login_user', 'login_password', 'timeout', 'validate_certs']:
        if p in module.params and not module.params[p] is None:
            module.warn('Option "%s" is deprecated with the move to httpapi connection and will be removed in the next release' % p)

    parameters = {
        'name': module.params['name']
    }
    for p in ['host', 'port', 'base_dn', 'search_attribute', 'bind_dn', 'bind_password', 'description', 'start_tls']:
        if module.params[p]:
            if p in ['port', 'start_tls']:
                parameters[p] = str(module.params[p])
            else:
                parameters[p] = module.params[p]

    state = module.params['state']

    user_directory = ZabbixBase(module)

    if LooseVersion(user_directory._zbx_api_version) < LooseVersion('6.2'):
        module.fail_json(msg='Zabbix < 6.2 does not support user directories.')

    if LooseVersion(user_directory._zbx_api_version) < LooseVersion('6.4'):
        parameters['search_filter'] = module.params['search_filter']
        directory = user_directory._zapi.userdirectory.get({'filter': {'name': parameters['name']}})
    else:
        # Zabbix >= 6.4
        # Mandatory parameters check
        if state == 'present' and not module.params['idp_type']:
            module.fail_json('"idp_type" parameter must be provided when state is "present"')
        if module.params['idp_type']:
            if (module.params['idp_type'] == 'ldap'
                    and (not module.params['host'] or not module.params['port'] or not module.params['base_dn'] or not module.params['search_attribute'])):
                module.fail_json('"host", "port", "base_dn", "search_attribute" must be provided when idp_type is "ldap"')
            if (module.params['idp_type'] == 'saml'
                    and (not module.params['idp_entityid'] or not module.params['sp_entityid']
                         or not module.params['sso_url'] or not module.params['username_attribute'])):
                module.fail_json('"idp_entityid", "sp_entityid", "sso_url", "username_attribute" must be provided when idp_type is "ldap"')

        directory = user_directory._zapi.userdirectory.get(
            {
                'search': {'name': parameters['name']},
                'selectProvisionMedia': 'extend',
                'selectProvisionGroups': 'extend'
            })
        parameters['idp_type'] = str(zabbix_utils.helper_to_numeric_value(['', 'ldap', 'saml'], module.params['idp_type']))
        if parameters['idp_type'] == '1':
            # idp_type is ldap
            parameters['search_filter'] = module.params['search_filter']
        elif parameters['idp_type'] == '2':
            # idp_type is saml
            for p in ['idp_entityid', 'sso_url', 'username_attribute', 'sp_entityid', 'slo_url', 'nameid_format']:
                # str parameters
                if module.params[p]:
                    parameters[p] = module.params[p]
            for p in ['scim_status', 'encrypt_nameid', 'encrypt_assertions', 'sign_messages', 'sign_assertions',
                      'sign_authn_requests', 'sign_logout_requests', 'sign_logout_responses']:
                # boolean parameters
                if module.params[p]:
                    parameters[p] = str(int(module.params[p]))

        if module.params['provision_status']:
            parameters['provision_status'] = int(module.params['provision_status'])

        if module.params['provision_media']:
            if 'provision_status' not in parameters or not parameters['provision_status']:
                module.fail_json('"provision_status" must be True to define "provision_media"')
            parameters['provision_media'] = []
            for media in module.params['provision_media']:
                media_type_name = media['mediatype']
                media_type_ids = user_directory._zapi.mediatype.get({'filter': {'name': media_type_name}})
                if not media_type_ids:
                    module.fail_json('Mediatype "%s" cannot be found' % media_type_name)
                parameters['provision_media'].append(
                    {
                        'name': media['name'],
                        'mediatypeid': media_type_ids[0]['mediatypeid'],
                        'attribute': media['attribute']
                    }
                )

        if module.params['provision_groups']:
            if 'provision_status' not in parameters or not parameters['provision_status']:
                module.fail_json('"provision_status" must be True to define "provision_groups"')
            parameters['provision_groups'] = []
            for group in module.params['provision_groups']:
                role_name = group['role']
                role_ids = user_directory._zapi.role.get({'filter': {'name': role_name}})
                if not role_ids:
                    module.fail_json('Role "%s" cannot be found' % role_name)
                user_groups = []
                for user_group in group['user_groups']:
                    ug_ids = user_directory._zapi.usergroup.get({'filter': {'name': user_group}})
                    if not ug_ids:
                        module.fail_json('User group "%s" cannot be found' % user_group)
                    user_groups.append({'usrgrpid': ug_ids[0]['usrgrpid']})
                parameters['provision_groups'].append(
                    {
                        'name': group['name'],
                        'roleid': role_ids[0]['roleid'],
                        'user_groups': user_groups
                    }
                )
        for p in ['group_basedn', 'group_filter', 'group_member', 'group_membership', 'group_name', 'group_name',
                  'user_lastname', 'user_ref_attr', 'user_username']:
            if module.params[p]:
                parameters[p] = module.params[p]

    if not directory:
        # No User Directory found with given name
        if state == 'absent':
            module.exit_json(changed=False, msg='User directory not found. Not changed: %s' % parameters['name'])

        elif state == 'present':
            if module.check_mode:
                module.exit_json(changed=True)
            else:
                user_directory._zapi.userdirectory.create(parameters)
                module.exit_json(changed=True, result='Successfully added user directory %s' % parameters['name'])
    else:
        # User Directory with given name exists
        if state == 'absent':
            user_directory._zapi.userdirectory.delete([directory[0]['userdirectoryid']])
            module.exit_json(changed=True, result='Successfully deleted user directory %s' % parameters['name'])
        elif state == 'present':
            diff_dict = {}
            if 'provision_status' in directory[0]:
                # Zabbix API returns provision_status as str we need it as int to correctly compare
                directory[0]['provision_status'] = int(directory[0]['provision_status'])
            if zabbix_utils.helper_compare_dictionaries(parameters, directory[0], diff_dict):
                parameters['userdirectoryid'] = directory[0]['userdirectoryid']
                user_directory._zapi.userdirectory.update(parameters)
                module.exit_json(changed=True, result='Successfully updated user directory %s' % parameters['name'])
            else:
                module.exit_json(changed=False, result='User directory %s is up-to date' % parameters['name'])

            module.exit_json(changed=False, result='User directory %s is up-to date' % parameters['name'])


if __name__ == '__main__':
    main()
